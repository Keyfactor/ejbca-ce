/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.cmp;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.RevDetails;
import com.novosec.pkix.asn1.cmp.RevReqContent;
import com.novosec.pkix.asn1.crmf.CertTemplate;

/**
 * Message handler for the CMP revocation request messages
 * @author tomas
 * @version $Id$
 */
public class RevocationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(RevocationMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
	
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	
	private UserAdminSession userAdminSession;
	private CertificateStoreSession certificateStoreSession;
	
	public RevocationMessageHandler(Admin admin, CertificateStoreSession certificateStoreSession, UserAdminSession userAdminSession, CAAdminSession caAdminSession, EndEntityProfileSession endEntityProfileSession, CertificateProfileSession certificateProfileSession) {
		super(admin, caAdminSession, endEntityProfileSession, certificateProfileSession);
		raAuthenticationSecret = CmpConfiguration.getRAAuthenticationSecret();
		responseProtection = CmpConfiguration.getResponseProtection();
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		this.userAdminSession = userAdminSession;
		this.certificateStoreSession = certificateStoreSession;

	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		LOG.trace(">handleMessage");
		IResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		// Try to find a HMAC/SHA1 protection key
		String owfAlg = null;
		String macAlg = null;
		int iterationCount = 1024;
		String cmpRaAuthSecret = null;
		String keyId = getSenderKeyId(msg.getHeader());
		if (keyId != null) {
			try {
				ResponseStatus status = ResponseStatus.FAILURE;
				FailInfo failInfo = FailInfo.BAD_MESSAGE_CHECK;
				String failText = null;
				CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());				
				owfAlg = verifyer.getOwfOid();
				macAlg = verifyer.getMacOid();
				iterationCount = verifyer.getIterationCount();
				boolean ret = true;
				if (raAuthenticationSecret != null) {
					if (!verifyer.verify(raAuthenticationSecret)) {
						ret = false;
					}
					cmpRaAuthSecret = raAuthenticationSecret;
				} else {
					// Get the correct profiles' and CA ids based on current configuration. 
					CAInfo caInfo;
					try {
						int eeProfileId = getUsedEndEntityProfileId(keyId);
						int caId = getUsedCaId(keyId, eeProfileId);
						caInfo = caAdminSession.getCAInfo(admin, caId);
					} catch (NotFoundException e) {
						LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
						return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
					} catch (EJBException e) {
						final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
						LOG.error(errMsg, e);                   
						return null;    // Fatal error
					}
					if (caInfo instanceof X509CAInfo) {
						cmpRaAuthSecret = ((X509CAInfo) caInfo).getCmpRaAuthSecret();
					}
					// Now we know which CA the request is for, if we didn't use a global shared secret we can check it now!
					if (cmpRaAuthSecret == null || !verifyer.verify(cmpRaAuthSecret)) {
						ret = false;
					}
				}
				if (ret) {
					// If authentication was correct, we will now try to find the certificate to revoke
					PKIMessage pkimsg = msg.getMessage();
					PKIBody body = pkimsg.getBody();
					RevReqContent rr = body.getRr();
					RevDetails rd = rr.getRevDetails(0);
					CertTemplate ct = rd.getCertDetails();
					DERInteger serno = ct.getSerialNumber();
					X509Name issuer = ct.getIssuer();
					// Get the revocation reason. 
					// For CMPv1 this can be a simple DERBitString or it can be a requested CRL Entry Extension
					// If there exists CRL Entry Extensions we will use that, because it's the only thing allowed in CMPv2
					int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
					DERBitString reasonbits = rd.getRevocationReason();
					if (reasonbits != null) {
						reason = CertTools.bitStringToRevokedCertInfo(reasonbits);						
						LOG.debug("CMPv1 revocation reason: "+reason);
					} else {
						LOG.debug("CMPv1 revocation reason is null");
					}
					X509Extensions crlExt = rd.getCrlEntryDetails();
					if (crlExt != null) {
						X509Extension ext = crlExt.getExtension(X509Extensions.ReasonCode);
						if (ext != null) {
							try {
								ASN1InputStream ai = new ASN1InputStream(ext.getValue().getOctets());
								DERObject obj = ai.readObject();
								DEREnumerated crlreason = DEREnumerated.getInstance(obj);
								// RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE are the same integer values as the CRL reason extension code
								reason = crlreason.getValue().intValue();
								LOG.debug("CRLReason extension: "+reason);
							} catch (IOException e) {
								LOG.info("Exception parsin CRL reason extension: ", e);
							}
						} else {
							LOG.debug("No CRL reason code extension present.");
						}
					} else {
						LOG.debug("No CRL entry extensions present");
					}
					
					if ( (serno != null) && (issuer != null) ) {
						String iMsg = INTRES.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
						LOG.info(iMsg);
						try {
							String username = certificateStoreSession.findUsernameByCertSerno(admin, serno.getValue(), issuer.toString());
							userAdminSession.revokeCert(admin, serno.getValue(), issuer.toString(), username, reason);
							status = ResponseStatus.SUCCESS;
						} catch (AuthorizationDeniedException e) {
							failInfo = FailInfo.NOT_AUTHORIZED;
							String errMsg = INTRES.getLocalizedMessage("cmp.errornotauthrevoke", issuer.toString(), serno.getValue().toString(16));
							failText = errMsg; 
							LOG.error(failText);
						} catch (FinderException e) {
							failInfo = FailInfo.BAD_CERTIFICATE_ID;
							String errMsg = INTRES.getLocalizedMessage("cmp.errorcertnofound", issuer.toString(), serno.getValue().toString(16));
							failText = errMsg; 
							LOG.error(failText);
						} catch (WaitingForApprovalException e) {
							status = ResponseStatus.GRANTED_WITH_MODS;
						} catch (ApprovalException e) {
							failInfo = FailInfo.BAD_REQUEST;
							String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrequested");
							failText = errMsg; 
							LOG.error(failText);
						} catch (AlreadyRevokedException e) {
							failInfo = FailInfo.BAD_REQUEST;
							String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrevoked");
							failText = errMsg; 
							LOG.error(failText);
						}
					} else {
						failInfo = FailInfo.BAD_CERTIFICATE_ID;
						String errMsg = INTRES.getLocalizedMessage("cmp.errormissingissuerrevoke", issuer.toString(), serno.getValue().toString(16));
						failText = errMsg; 
						LOG.error(failText);
					}
				} else {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage");
					LOG.error(errMsg);
					failText = errMsg;
					if (verifyer.getErrMsg() != null) {
						failText = verifyer.getErrMsg();
					}
				}
				LOG.debug("Creating a PKI revocation message response");
				CmpRevokeResponseMessage rresp = new CmpRevokeResponseMessage();
				rresp.setRecipientNonce(msg.getSenderNonce());
				rresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
				rresp.setSender(msg.getRecipient());
				rresp.setRecipient(msg.getSender());
				rresp.setTransactionId(msg.getTransactionId());
				rresp.setFailInfo(failInfo);
				rresp.setFailText(failText);
				rresp.setStatus(status);
	    		// Set all protection parameters
				LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
	    		if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
	    			rresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
	    		}
	    		resp = rresp;
				try {
					resp.create();
				} catch (InvalidKeyException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				} catch (NoSuchAlgorithmException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				} catch (NoSuchProviderException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				} catch (SignRequestException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				} catch (NotFoundException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				} catch (IOException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				}							

			} catch (NoSuchAlgorithmException e) {
				String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.error(errMsg, e);			
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			} catch (NoSuchProviderException e) {
				String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.error(errMsg, e);			
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			} catch (InvalidKeyException e) {
				String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.error(errMsg, e);			
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			/*} catch (RemoteException e) {
				// Fatal error
				String errMsg = intres.getLocalizedMessage("cmp.errorrevoke");
				log.error(errMsg, e);			
				resp = null;*/
			}							
		} else {
			// If we don't have any protection to verify, we fail
			String errMsg = INTRES.getLocalizedMessage("cmp.errornoprot");
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		}
		
		return resp;
	}
	
}
