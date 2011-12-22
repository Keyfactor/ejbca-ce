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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;

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
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
	
	// /** Parameter used to authenticate RA messages if we are using RA mode to create users */
	//private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	private CA ca;
	
	private UserAdminSession userAdminSession;
    private CertificateStoreSession certificateStoreSession;
    private AccessControlSession authorizationSession;
    private EndEntityAccessSession endEntityAccessSession;
    private final WebAuthenticationProviderSessionLocal authenticationProviderSession;
	
	public RevocationMessageHandler(AuthenticationToken admin, CA ca, UserAdminSession userAdminSession, CaSession caSession, 
	            EndEntityProfileSession endEntityProfileSession, CertificateProfileSession certificateProfileSession, CertificateStoreSession certStoreSession,
	            AccessControlSession authSession, EndEntityAccessSession eeAccessSession,  WebAuthenticationProviderSessionLocal authProviderSession) {
		super(admin, caSession, endEntityProfileSession, certificateProfileSession);
		//raAuthenticationSecret = CmpConfiguration.getRAAuthenticationSecret();
		responseProtection = CmpConfiguration.getResponseProtection();
		this.ca = ca;
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		this.userAdminSession = userAdminSession;
        this.certificateStoreSession = certStoreSession;
        this.authorizationSession = authSession;
        this.endEntityAccessSession = eeAccessSession;
        this.authenticationProviderSession = authProviderSession;
	}
	public ResponseMessage handleMessage(BaseCmpMessage msg, boolean authenticated) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		
		if (ca == null) {
		    String errmsg = "CA '" + msg.getRecipient().getName().toString().hashCode() + "' (DN: " + msg.getRecipient().getName().toString() + ") is unknown";
            return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, errmsg);
		}
		
		ResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		// Try to find a HMAC/SHA1 protection key
		String owfAlg = null;
		String macAlg = null;
		int iterationCount = 1024;
		String cmpRaAuthSecret = null;
		String keyId = getSenderKeyId(msg.getHeader());
		if (keyId != null) {
            ResponseStatus status = ResponseStatus.FAILURE;
            FailInfo failInfo = FailInfo.BAD_MESSAGE_CHECK;
            String failText = null;

            CAInfo caInfo = null;
			try {
				int eeProfileId = getUsedEndEntityProfileId(keyId);
				int caId = getUsedCaId(keyId, eeProfileId);
				caInfo = caSession.getCAInfo(admin, caId);
			} catch (NotFoundException e) {
				LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
				return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
			} catch (EJBException e) {
                String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
				LOG.error(errMsg, e);                   
				return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
			} catch (CADoesntExistsException e) {
                LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
                return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
            } catch (AuthorizationDeniedException e) {
                LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
                return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
            }

            //Verify the authenticity of the message
            final VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(caInfo, admin, caSession, endEntityAccessSession, certificateStoreSession, authorizationSession, endEntityProfileSession, authenticationProviderSession);
            ICMPAuthenticationModule authenticationModule = null;
            if(messageVerifyer.verify(msg.getMessage(), null, authenticated)) {
                authenticationModule = messageVerifyer.getUsedAuthenticationModule();
            } else {

                String errMsg = "";
                if(messageVerifyer.getErrorMessage() != null) {
                    errMsg = messageVerifyer.getErrorMessage();
                } else {
                    errMsg = "Unrecognized authentication modules";
                }
                LOG.error(errMsg);
                return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
            }
            if(authenticationModule instanceof HMACAuthenticationModule) {
                HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
                owfAlg = hmacmodule.getCmpPbeVerifyer().getOwfOid();
                macAlg = hmacmodule.getCmpPbeVerifyer().getMacOid();
            }


            cmpRaAuthSecret = authenticationModule.getAuthenticationString();
            if (cmpRaAuthSecret != null) {
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
					if (LOG.isDebugEnabled()) {
						LOG.debug("CMPv1 revocation reason: "+reason);
					}
				} else {
					if (LOG.isDebugEnabled()) {
						LOG.debug("CMPv1 revocation reason is null");
					}
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
								if (LOG.isDebugEnabled()) {
									LOG.debug("CRLReason extension: "+reason);
								}
							} catch (IOException e) {
								LOG.info("Exception parsin CRL reason extension: ", e);
							}
						} else {
							if (LOG.isDebugEnabled()) {
								LOG.debug("No CRL reason code extension present.");
							}
						}
					} else {
						if (LOG.isDebugEnabled()) {
							LOG.debug("No CRL entry extensions present");
						}
					}
					
					if ( (serno != null) && (issuer != null) ) {
						String iMsg = INTRES.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
						LOG.info(iMsg);
						try {
							userAdminSession.revokeCert(admin, serno.getValue(), issuer.toString(), reason);
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
					if (authenticationModule.getErrorMessage() != null) {
						failText = authenticationModule.getErrorMessage();
					}
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("Creating a PKI revocation message response");
				}
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
				if (LOG.isDebugEnabled()) {
					LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
				}
	    		if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
	    			rresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
	    		} else {
	    		    try {
                        rresp.setSignKeyInfo(ca.getCACertificate(), ca.getCAToken().getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), ca.getCAToken().getCryptoToken().getSignProviderName());
                    } catch (CryptoTokenOfflineException e) {
                        LOG.error(e.getLocalizedMessage(), e);
                    } catch (IllegalCryptoTokenException e) {
                        LOG.error(e.getLocalizedMessage(), e);                    }
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
				} catch (IOException e) {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorgeneral");
					LOG.error(errMsg, e);			
				}							
							
		} else {
			// If we don't have any protection to verify, we fail
			String errMsg = INTRES.getLocalizedMessage("cmp.errornoprot");
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		}
		return resp;
	}
}
