/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;

/**
 * Message handler for the CMP revocation request messages
 * 
 * @version $Id$
 */
public class RevocationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(RevocationMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
	
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	
	private EndEntityManagementSession endEntityManagementSession;
    private CertificateStoreSession certificateStoreSession;
    private AuthorizationSession authorizationSession;
    private EndEntityAccessSession endEntityAccessSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
    private CryptoTokenSessionLocal cryptoTokenSession;
	
    public RevocationMessageHandler(final AuthenticationToken authenticationToken, final CmpConfiguration cmpConfiguration, final String configAlias,
    		final EjbBridgeSessionLocal ejbBridgeSession, final CryptoTokenSessionLocal cryptoTokenSession) {
        super(authenticationToken, cmpConfiguration, configAlias, ejbBridgeSession);
        this.responseProtection = this.cmpConfiguration.getResponseProtection(this.confAlias);
        this.endEntityManagementSession = ejbBridgeSession.getEndEntityManagementSession();
        this.certificateStoreSession = ejbBridgeSession.getCertificateStoreSession();
        this.authorizationSession = ejbBridgeSession.getAuthorizationSession();
        this.endEntityAccessSession = ejbBridgeSession.getEndEntityAccessSession();
        this.authenticationProviderSession = ejbBridgeSession.getWebAuthenticationProviderSession();
        this.cryptoTokenSession = cryptoTokenSession;
    }

	public ResponseMessage handleMessage(final BaseCmpMessage msg, boolean authenticated) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		
        CA ca = null;
        try {
            final String caDN = msg.getHeader().getRecipient().getName().toString();
            final int caId = CertTools.stringToBCDNString(caDN).hashCode();
            if (LOG.isDebugEnabled()) {
                LOG.debug("CA DN is '"+caDN+"' and resulting caId is "+caId+", after CertTools.stringToBCDNString conversion.");
            }
            ca = caSession.getCA(admin, caId);
        } catch (CADoesntExistsException e) {
            final String errMsg = "CA with DN '" + msg.getHeader().getRecipient().getName().toString() + "' is unknown";
            LOG.info(errMsg);
            return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, errMsg);
        } catch (AuthorizationDeniedException e) {
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
            return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.INCORRECT_DATA, e.getMessage());
        }
		
		// if version == 1 it is cmp1999 and we should not return a message back
		// Try to find a HMAC/SHA1 protection key
		final String keyId = CmpMessageHelper.getStringFromOctets(msg.getHeader().getSenderKID());
		ResponseStatus status = ResponseStatus.FAILURE;
		FailInfo failInfo = FailInfo.BAD_MESSAGE_CHECK;
		String failText = null;

		//Verify the authenticity of the message
		final VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(ca.getCAInfo(), this.confAlias, admin, caSession, endEntityAccessSession, certificateStoreSession, 
		        authorizationSession, endEntityProfileSession, certificateProfileSession, authenticationProviderSession, endEntityManagementSession, this.cmpConfiguration);
		ICMPAuthenticationModule authenticationModule = messageVerifyer.getUsedAuthenticationModule(msg.getMessage(), null, authenticated);
		if(authenticationModule == null) {
	          LOG.info(messageVerifyer.getErrorMessage());
	          return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, messageVerifyer.getErrorMessage());
		}

		// If authentication was correct, we will now try to find the certificate to revoke
		final PKIMessage pkiMessage = msg.getMessage();
		final PKIBody pkiBody = pkiMessage.getBody();
		final RevReqContent rr = (RevReqContent) pkiBody.getContent();
		RevDetails rd;
		try {
		    rd = rr.toRevDetailsArray()[0];
		} catch(Exception e) {
		    LOG.debug("Could not parse the revocation request. Trying to parse it as novosec generated message.");
		    rd = CmpMessageHelper.getNovosecRevDetails(rr);
		    LOG.debug("Succeeded in parsing the novosec generated request.");
		}
		final CertTemplate ct = rd.getCertDetails();
		final ASN1Integer serno = ct.getSerialNumber();
		final X500Name issuer = ct.getIssuer();
		// Get the revocation reason. 
		// For CMPv1 this can be a simple DERBitString or it can be a requested CRL Entry Extension
		// If there exists CRL Entry Extensions we will use that, because it's the only thing allowed in CMPv2
		int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
		
		DERBitString reasonbits;
		try {
		    final ASN1OctetString reasonoctets = rd.getCrlEntryDetails().getExtension(Extension.reasonCode).getExtnValue();
		    reasonbits = new DERBitString(reasonoctets.getEncoded());
		} catch (NullPointerException | IOException e) {
		    //If reason wasn't included the request, or was incorrectly encoded
		    LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
		    return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.INCORRECT_DATA, e.getMessage());
		}
		if (reasonbits != null) {
		    reason = CertTools.bitStringToRevokedCertInfo(reasonbits);
		    if (LOG.isDebugEnabled()) {
		        LOG.debug("CMPv1 revocation reason: "+reason);
		    }
		}
		final Extensions crlExt = rd.getCrlEntryDetails();
		if (crlExt != null) {
		    final Extension ext = crlExt.getExtension(Extension.reasonCode);
		    if (ext != null) {
		        try {
		            final ASN1InputStream ai = new ASN1InputStream(ext.getExtnValue().getOctets());
		            final ASN1Primitive obj = ai.readObject();
		            final ASN1Enumerated crlreason = ASN1Enumerated.getInstance(obj);
		            // RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE are the same integer values as the CRL reason extension code
		            reason = crlreason.getValue().intValue();
		            if (LOG.isDebugEnabled()) {
		                LOG.debug("CRLReason extension: "+reason);
		            }
		            ai.close();
		        } catch (IOException e) {
		            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
		            return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.INCORRECT_DATA, e.getMessage());
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
		
		if (serno != null && issuer != null) {
		    final String iMsg = INTRES.getLocalizedMessage("cmp.receivedrevreq", issuer.toString(), serno.getValue().toString(16));
		    LOG.info(iMsg);
		    try {
		        endEntityManagementSession.revokeCert(admin, serno.getValue(), issuer.toString(), reason);
		        status = ResponseStatus.SUCCESS;
		    } catch (AuthorizationDeniedException e) {
		        failInfo = FailInfo.NOT_AUTHORIZED;
		        final String errMsg = INTRES.getLocalizedMessage("cmp.errornotauthrevoke", issuer.toString(), serno.getValue().toString(16));
		        failText = errMsg; 
		        LOG.info(failText);
		    } catch (NoSuchEndEntityException e) {
		        failInfo = FailInfo.BAD_CERTIFICATE_ID;
		        final String errMsg = INTRES.getLocalizedMessage("cmp.errorcertnofound", issuer.toString(), serno.getValue().toString(16));
		        failText = errMsg; 
                // This is already info logged in endEntityManagementSession.revokeCert
                // LOG.info(failText);
		    } catch (WaitingForApprovalException e) {
		        status = ResponseStatus.GRANTED_WITH_MODS;
		    } catch (ApprovalException e) {
		        failInfo = FailInfo.BAD_REQUEST;
		        final String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrequested");
		        failText = errMsg; 
		        LOG.info(failText);
		    } catch (AlreadyRevokedException e) {
		        failInfo = FailInfo.CERT_REVOKED;
		        final String errMsg = INTRES.getLocalizedMessage("cmp.erroralreadyrevoked");
		        failText = errMsg; 
		        // This is already info logged in endEntityManagementSession.revokeCert
		        // LOG.info(failText);
		    }
		} else {
		    failInfo = FailInfo.BAD_CERTIFICATE_ID;
            final String errMsg = INTRES.getLocalizedMessage("cmp.errormissingissuerrevoke",
                    (issuer != null ? issuer.toString() : "<no issuer in request>"),
                    (serno != null ? serno.getValue().toString(16) : "<no serial number in request>"));
		    failText = errMsg; 
		    LOG.info(failText);
		}
		
		if (LOG.isDebugEnabled()) {
		    LOG.debug("Creating a PKI revocation message response");
		}
		final CmpRevokeResponseMessage rresp = new CmpRevokeResponseMessage();
		rresp.setRecipientNonce(msg.getSenderNonce());
		rresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
		rresp.setSender(msg.getRecipient());
		rresp.setRecipient(msg.getSender());
		rresp.setTransactionId(msg.getTransactionId());
		rresp.setFailInfo(failInfo);
		rresp.setFailText(failText);
		rresp.setStatus(status);

		if (StringUtils.equals(responseProtection, "pbe")) {
		    final HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
		    final String owfAlg = hmacmodule.getCmpPbeVerifyer().getOwfOid();
		    final String macAlg = hmacmodule.getCmpPbeVerifyer().getMacOid();
		    final int iterationCount = 1024;
		    final String cmpRaAuthSecret = hmacmodule.getAuthenticationString();
		    
		    if (owfAlg != null && macAlg != null && keyId != null && cmpRaAuthSecret != null) {
		        // Set all protection parameters
		        if (LOG.isDebugEnabled()) {
		            LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
		        }
		        rresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
		    }
		} else if(StringUtils.equals(responseProtection, "signature")) {
		    try {
		        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
		        final String aliasCertSign = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		        rresp.setSignKeyInfo(ca.getCertificateChain(), cryptoToken.getPrivateKey(aliasCertSign), cryptoToken.getSignProviderName());
                if(msg.getHeader().getProtectionAlg() != null) {
                    rresp.setPreferredDigestAlg(AlgorithmTools.getDigestFromSigAlg(msg.getHeader().getProtectionAlg().getAlgorithm().getId()));
                }
		    } catch (CryptoTokenOfflineException e) {
		        LOG.error(e.getLocalizedMessage(), e);
		    }
		}
		try {
		    rresp.create();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
		    LOG.error(INTRES.getLocalizedMessage("cmp.errorgeneral"), e);
        }
		return rresp;
	}  
}
