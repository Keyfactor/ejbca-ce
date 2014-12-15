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
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;

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
 * @author tomas
 * @version $Id$
 */
public class ConfirmationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(ConfirmationMessageHandler.class);
	
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	/** CA Session used to sign the response */
	private CaSessionLocal caSession;
    private CryptoTokenSessionLocal cryptoTokenSession;
    
	public ConfirmationMessageHandler(AuthenticationToken admin, String configAlias, CaSessionLocal caSession, 
	        EndEntityProfileSessionLocal endEntityProfileSession, CertificateProfileSession certificateProfileSession, 
	        AccessControlSession authSession, WebAuthenticationProviderSessionLocal authProvSession, 
	        CryptoTokenSessionLocal cryptoTokenSession, GlobalConfigurationSession globalConfigSession) {

		super(admin, configAlias, caSession, endEntityProfileSession, certificateProfileSession, (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID));
		responseProtection = this.cmpConfiguration.getResponseProtection(this.confAlias);
		this.caSession = caSession;
        this.cryptoTokenSession = cryptoTokenSession;
	}
	public ResponseMessage handleMessage(BaseCmpMessage msg, boolean authenticated) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		int version = msg.getHeader().getPvno().getValue().intValue();
		ResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		if (version > 1) {
			
			// Creating the confirm message response
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Creating a PKI confirm message response, responseProtection="+responseProtection);
			}
			CmpConfirmResponseMessage cresp = new CmpConfirmResponseMessage();
			cresp.setRecipientNonce(msg.getSenderNonce());
			cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
			cresp.setSender(msg.getRecipient());
			cresp.setRecipient(msg.getSender());
			cresp.setTransactionId(msg.getTransactionId());

			if (StringUtils.equals(responseProtection, "pbe")) {
			    setPbeParameters(cresp, msg, authenticated);
			} else if (StringUtils.equals(responseProtection, "signature")) {
			    signResponse(cresp, msg);
			}
			resp = cresp;
			try {
				resp.create();
			} catch (InvalidKeyException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchAlgorithmException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchProviderException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (CertificateEncodingException e) {
			    LOG.error("Exception during CMP processing: ", e);      
            } catch (CRLException e) {
                LOG.error("Exception during CMP processing: ", e);      
            } 						
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Cmp1999 - Not creating a PKI confirm message response");
			}
		}
		return resp;
	}
	
	private void setPbeParameters(final CmpConfirmResponseMessage cresp, final BaseCmpMessage msg, final boolean authenticated) {
        final String keyId = CmpMessageHelper.getStringFromOctets(msg.getHeader().getSenderKID());
	    
        String owfAlg = null;
        String macAlg = null;
        int iterationCount = 1024;
        String sharedSecret = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC, confAlias);
        if(StringUtils.equals(sharedSecret, "-")) {
            X509CAInfo cainfo;
            try {
                cainfo = (X509CAInfo) getCAInfo(msg.getRecipient().getName().toString());
                sharedSecret = cainfo.getCmpRaAuthSecret();
            } catch (CADoesntExistsException e) {
                LOG.error("Exception during CMP response protection: ", e);
            }
        }
        // We don't need to check the shared secret in client mode (= the EndEntiy password) because PBE protection is only supported in RA mode
        
        CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());
        owfAlg = verifyer.getOwfOid();
        macAlg = verifyer.getMacOid();
        iterationCount = verifyer.getIterationCount();
        
        cresp.setPbeParameters(keyId, sharedSecret, owfAlg, macAlg, iterationCount);
	}
	
	private void signResponse(CmpConfirmResponseMessage cresp, BaseCmpMessage msg) {

        // Get the CA that should sign the response
        CAInfo cainfo;
        try {
            cainfo = getCAInfo(msg.getRecipient().getName().toString());
            if(LOG.isDebugEnabled()) {
                LOG.debug("Using CA '" + cainfo.getName() + "' to sign Certificate Confirm message");
            }
            X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
            // We use the actual asn.1 encoding from the cacert subjectDN here. This ensures that the DN is exactly as 
            // encoded in the certificate (which it should be).
            // If we use only the cainfo.getSubjectDN we will get "EJBCA encoding", and this may not be the same if the 
            // CA certificate comes from an external CA that encodes thing differently than EJBCA.
            cresp.setSender(new GeneralName(X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded())));
            
            try {
                CAToken catoken = cainfo.getCAToken();
                final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
                cresp.setSignKeyInfo(cainfo.getCertificateChain(), cryptoToken.getPrivateKey(
                                                    catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), 
                                                    cryptoToken.getSignProviderName());
                if(msg.getHeader().getProtectionAlg() != null) {
                    cresp.setPreferredDigestAlg(AlgorithmTools.getDigestFromSigAlg(msg.getHeader().getProtectionAlg().getAlgorithm().getId()));
                }

            } catch (CryptoTokenOfflineException e) {
                LOG.error("Exception during CMP response signing: ", e);            
            }
        
        } catch (CADoesntExistsException e1) {
            LOG.error("Exception during CMP response signing: ", e1);            
        }
    }
    
    private CAInfo getCAInfo(String cadn) throws CADoesntExistsException {
        CAInfo cainfo = null;
        if(cadn == null) {
            cadn = CertTools.stringToBCDNString(this.cmpConfiguration.getCMPDefaultCA(this.confAlias));
            cainfo = caSession.getCAInfoInternal(cadn.hashCode(), null, true);
        } else {
            try {
                cadn = CertTools.stringToBCDNString(cadn);
                cainfo = caSession.getCAInfoInternal(cadn.hashCode(), null, true);
            } catch(CADoesntExistsException e) {
                LOG.info("Could not find Recipient CA '" + cadn + "'.");
                cadn = CertTools.stringToBCDNString(this.cmpConfiguration.getCMPDefaultCA(this.confAlias));
                LOG.info("Trying to use CMP DefaultCA instead. DN " + cadn + "  ID " + cadn.hashCode());
                cainfo = caSession.getCAInfoInternal(cadn.hashCode(), null, true);
            }
        }
        return cainfo;
    }

}
