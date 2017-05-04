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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;

/**
 * Message handler for certificate request confirmation message.
 * 
 * According to RFC 4210 4.2.2.2:
 *  "Where verification of the cert confirmation message fails, the RA/CA
 *   MUST revoke the newly issued certificate if it has been published or
 *   otherwise made available."
 * 
 * However, EJBCA does not keep track of the transaction and always responds
 * with a ResponseStatus.SUCCESS Certificate Confirmation ACK.
 * 
 * @version $Id$
 */
public class ConfirmationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(ConfirmationMessageHandler.class);
	
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
    private CryptoTokenSessionLocal cryptoTokenSession;
    
    public ConfirmationMessageHandler(final AuthenticationToken authenticationToken, final CmpConfiguration cmpConfiguration, final String configAlias,
    		final EjbBridgeSessionLocal ejbBridgeSession, final CryptoTokenSessionLocal cryptoTokenSession) {
        super(authenticationToken, cmpConfiguration, configAlias, ejbBridgeSession);
        this.responseProtection = this.cmpConfiguration.getResponseProtection(this.confAlias);
        this.cryptoTokenSession = cryptoTokenSession;
    }
	
    public ResponseMessage handleMessage(BaseCmpMessage cmpRequestMessage, boolean authenticated) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		int version = cmpRequestMessage.getHeader().getPvno().getValue().intValue();
		CmpConfirmResponseMessage cresp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
        if (version == PKIHeader.CMP_1999) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cmp1999 - Not creating a PKI confirm message response");
            }
        } else if (version > PKIHeader.CMP_1999) {
			// Creating the confirm message response
			if (LOG.isDebugEnabled()) {
				LOG.debug("Creating a PKI confirm message response, responseProtection="+responseProtection);
			}
			cresp = new CmpConfirmResponseMessage();
			cresp.setRecipientNonce(cmpRequestMessage.getSenderNonce());
			cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
			cresp.setSender(cmpRequestMessage.getRecipient());
			cresp.setRecipient(cmpRequestMessage.getSender());
			cresp.setTransactionId(cmpRequestMessage.getTransactionId());
			if (StringUtils.equals(responseProtection, "pbe")) {
			    try {
                    setPbeParameters(cresp, cmpRequestMessage, authenticated);
                } catch (InvalidCmpProtectionException e) {
                    throw new IllegalArgumentException(e);
                }
			} else if (StringUtils.equals(responseProtection, "signature")) {
			    signResponse(cresp, cmpRequestMessage);
			}
            try {
                cresp.create();
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
                LOG.error("Exception during CMP processing: ", e);
            }						
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Not Cmp1999 or Cmp2000 or later - Not creating a PKI confirm message response");
			}
		}
		return cresp;
	}
	
	private void setPbeParameters(final BaseCmpMessage cmpResponseMessage, final BaseCmpMessage cmpRequestMessage, final boolean authenticated) throws InvalidCmpProtectionException {
        final String keyId = CmpMessageHelper.getStringFromOctets(cmpRequestMessage.getHeader().getSenderKID());
        String sharedSecret = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC, confAlias);
        if(StringUtils.equals(sharedSecret, "-")) {
            try {
                final X509CAInfo cainfo = getCAInfo(cmpRequestMessage.getRecipient().getName().toString());
                sharedSecret = cainfo.getCmpRaAuthSecret();
            } catch (CADoesntExistsException e) {
                LOG.error("Exception during CMP response protection: ", e);
            }
        }
        // We don't need to check the shared secret in client mode (= the EndEntiy password) because PBE protection is only supported in RA mode
        CmpPbeVerifyer verifyer = new CmpPbeVerifyer(cmpRequestMessage.getMessage());
        String owfAlg = verifyer.getOwfOid();
        String macAlg = verifyer.getMacOid();
        int iterationCount = verifyer.getIterationCount();
        cmpResponseMessage.setPbeParameters(keyId, sharedSecret, owfAlg, macAlg, iterationCount);
	}
	
	private void signResponse(CmpConfirmResponseMessage cresp, BaseCmpMessage cmpRequestMessage) {
        try {
            // Get the CA that should sign the response
            X509CAInfo caInfo = getCAInfo(cmpRequestMessage.getRecipient().getName().toString());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using CA '" + caInfo.getName() + "' to sign Certificate Confirm message");
            }
            X509Certificate cacert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
            // We use the actual asn.1 encoding from the cacert subjectDN here. This ensures that the DN is exactly as 
            // encoded in the certificate (which it should be).
            // If we use only the cainfo.getSubjectDN we will get "EJBCA encoding", and this may not be the same if the 
            // CA certificate comes from an external CA that encodes thing differently than EJBCA.
            cresp.setSender(new GeneralName(X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded())));
            final CAToken caToken = caInfo.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
            cresp.setSignKeyInfo(caInfo.getCertificateChain(), cryptoToken.getPrivateKey(
                    caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), 
                    cryptoToken.getSignProviderName());
            final AlgorithmIdentifier protectionAlgorithm = cmpRequestMessage.getHeader().getProtectionAlg();
            if (protectionAlgorithm != null) {
                cresp.setPreferredDigestAlg(AlgorithmTools.getDigestFromSigAlg(protectionAlgorithm.getAlgorithm().getId()));
            }
        } catch (CADoesntExistsException | CryptoTokenOfflineException e) {
            LOG.error("Exception during CMP response signing: " + e.getMessage(), e);            
        }
    }
    
    private X509CAInfo getCAInfo(final String caDn) throws CADoesntExistsException {
        CAInfo caInfo = null;
        if (caDn == null) {
            final String caDnDefault = CertTools.stringToBCDNString(this.cmpConfiguration.getCMPDefaultCA(this.confAlias));
            caInfo = caSession.getCAInfoInternal(caDnDefault.hashCode(), null, true);
        } else {
            final String caDnNormalized = CertTools.stringToBCDNString(caDn);
            try {
                caInfo = caSession.getCAInfoInternal(caDnNormalized.hashCode(), null, true);
            } catch (CADoesntExistsException e) {
                final String caDnDefault = CertTools.stringToBCDNString(this.cmpConfiguration.getCMPDefaultCA(this.confAlias));
                LOG.info("Could not find Recipient CA with DN '" + caDnNormalized + "'." +
                        " Trying to use CMP DefaultCA instead with DN '" + caDnDefault + "' (" + caDnDefault.hashCode() + ").");
                caInfo = caSession.getCAInfoInternal(caDnDefault.hashCode(), null, true);
            }
        }
        if (!(caInfo instanceof X509CAInfo)) {
            throw new CADoesntExistsException("Incorrect CA type.");
        }
        return (X509CAInfo) caInfo;
    }
}
