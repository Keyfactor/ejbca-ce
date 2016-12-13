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

package org.ejbca.core.model.util;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

/** Class that has helper methods to generate tokens for users in ejbca. 
 * Generating tokens can often depend on the ejb services (local interfaces), for example for key recovery.
 * 
 * @version $Id$
 */
public class GenerateToken {
    private static final Logger log = Logger.getLogger(GenerateToken.class);

	private EndEntityAuthenticationSession authenticationSession;
	private EndEntityAccessSession endEntityAccessSession;
	private EndEntityManagementSession endEntityManagementSession;
	private CaSession caSession;
	private KeyRecoverySession keyRecoverySession;
	private SignSession signSession;
	
    public GenerateToken(EndEntityAuthenticationSession authenticationSession, EndEntityAccessSession endEntityAccessSession, EndEntityManagementSession endEntityManagementSession, CaSession caSession, KeyRecoverySession keyRecoverySession, SignSession signSession) {
    	this.authenticationSession = authenticationSession;
    	this.endEntityAccessSession = endEntityAccessSession;
    	this.endEntityManagementSession = endEntityManagementSession;
    	this.caSession = caSession;
    	this.keyRecoverySession = keyRecoverySession;
    	this.signSession = signSession;
    }
    
    /**
     * This method generates a new pkcs12 or jks token for a user, and key recovers the token, if the user is configured for that in EJBCA.
     * 
     * @param administrator administrator performing the action
     * @param username username in ejbca
     * @param password password for user
     * @param caid caid of the CA the user is registered for
     * @param keyspec name of ECDSA key or length of RSA and DSA keys (endEntityInformation.extendedInformation.keyStoreAlgorithmSubType has priority over this value) 
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA (endEntityInformation.extendedInformation.keyStoreAlgorithmType has priority over this value)
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @param loadkeys true if keys should be recovered
     * @param savekeys true if generated keys should be stored for keyrecovery
     * @param reusecertificate true if the old certificate should be reused for a recovered key
     * @param endEntityProfileId the end entity profile the user is registered for
     * 
     * @return a keystore
     * 
     * @throws AuthorizationDeniedException if the authentication token was not allowed access to the EEP or CA of the end entity, to recover keys,
     * to issue certificates
     * @throws KeyStoreException if keys were set to be recovered, but no key recovery data was found
     * @throws InvalidAlgorithmParameterException  if the given parameters (keyspec, keyalg) are inappropriate for this key pair generator.
     * @throws CADoesntExistsException if the CA defined by caid does not exist
     * @throws AuthLoginException If the password was incorrect.
     * @throws AuthStatusException If the end entity's status is incorrect.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found 
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA. 
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not. 
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created. 
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile. 
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws UserDoesntFullfillEndEntityProfile if the password doesn't fulfill the demands set by the EE profile
     * @throws CertificateSignatureException if verification of the CA certificate failed
     * @throws InvalidKeySpecException if the key specification defined in keys couldn't be found
     * @throws NoSuchAlgorithmException if the algorithm defined in the keys couldn't be found
     * @throws CertificateException if there was a problem with the certificate
     * @throws CertificateEncodingException if there was a problem with the certificate
     */
    public KeyStore generateOrKeyRecoverToken(AuthenticationToken administrator, String username, String password, int caid, String keyspec,
            String keyalg, boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, UserDoesntFullfillEndEntityProfile, NoSuchEndEntityException,
            CertificateSignatureException, CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (log.isTraceEnabled()) {
            log.trace(">generateOrKeyRecoverToken");
        }
    	KeyRecoveryInformation keyData = null;
    	KeyPair rsaKeys = null;
    	EndEntityInformation userdata = endEntityAccessSession.findUser(administrator, username);
    	if (loadkeys) {
    	    if (log.isDebugEnabled()) {
    	        log.debug("Recovering keys for user: "+ username);
    	    }
            // used saved keys.
			keyData = keyRecoverySession.recoverKeys(administrator, username, endEntityProfileId);
    		if (keyData == null) {
    			throw new KeyStoreException("No key recovery data exists for user");
    		}
    		rsaKeys = keyData.getKeyPair();
    		if (reusecertificate) {
    			// TODO: Why is this only done is reusecertificate == true ??
                if (log.isDebugEnabled()) {
                    log.debug("Re-using old certificate for user: "+ username);
                }
    			keyRecoverySession.unmarkUser(administrator,username);
    		}
    		caid = keyData.getIssuerDN().hashCode(); // always use the CA of the certificate 
    	} else {
            if (log.isDebugEnabled()) {
                log.debug("Generating new keys for user: "+ username);
            }
            
            //KeyStore algorithm specification inside endEntityInformation has priority since its algorithm is approved
            if (userdata.getExtendedinformation() != null) {
                if (userdata.getExtendedinformation().getKeyStoreAlgorithmType() != null
                        && userdata.getExtendedinformation().getKeyStoreAlgorithmSubType() != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using the key-store algorithm specification found inside the endEntityInformation ("
                                + userdata.getExtendedinformation().getKeyStoreAlgorithmType() + "_"
                                + userdata.getExtendedinformation().getKeyStoreAlgorithmSubType() + ") instead of one provided separately (" + keyalg
                                + "_" + keyspec + ")");
                    }
                    keyalg = userdata.getExtendedinformation().getKeyStoreAlgorithmType();
                    keyspec = userdata.getExtendedinformation().getKeyStoreAlgorithmSubType();
                }
            }
            // generate new keys.
            rsaKeys = KeyTools.genKeys(keyspec, keyalg);
    	}
    	X509Certificate cert = null;
    	if ((reusecertificate) && (keyData != null)) {
    		cert = (X509Certificate) keyData.getCertificate();
    		boolean finishUser = true;
			finishUser = caSession.getCAInfo(administrator,caid).getFinishUser();
    		if (finishUser) {
				authenticationSession.finishUser(userdata);
    		}
    	} else {
            if (log.isDebugEnabled()) {
                log.debug("Generating new certificate for user: "+ username);
            }
			cert = (X509Certificate) signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(rsaKeys.getPublic()));
    	}
    	// Clear password from database
    	userdata = endEntityAccessSession.findUser(administrator, username); //Get GENERATED end entity information
        if (userdata.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            // If we have a successful key recovery via EJBCA WS we implicitly want to allow resetting of the password without edit_end_entity rights (ECA-4947)
            // FIXME: This instanceof can't make any sense...
            if (loadkeys && endEntityManagementSession instanceof EndEntityManagementSessionLocal) {
                endEntityManagementSession.setClearTextPassword(new AlwaysAllowLocalAuthenticationToken(
                        new UsernamePrincipal("Implicit authorization from key recovery operation to reset password.")), username, null);
            } else {
                endEntityManagementSession.setClearTextPassword(administrator, username, null);
            }
    	}
        // Make a certificate chain from the certificate and the CA-certificate
        Certificate[] cachain = (Certificate[]) signSession.getCertificateChain(caid).toArray(new Certificate[0]);
        // Verify CA-certificate
    	Certificate rootcert = cachain[cachain.length - 1];
    	if (CertTools.isSelfSigned(rootcert)) {
    		try {
    			rootcert.verify(rootcert.getPublicKey());
    		} catch (GeneralSecurityException se) {
                throw new CertificateSignatureException("RootCA certificate does not verify, issuerDN: " + CertTools.getIssuerDN(rootcert)
                        + ", subjectDN: " + CertTools.getSubjectDN(rootcert), se);
    		}
    	} else {
    		throw new CertificateSignatureException("RootCA certificate not self-signed, issuerDN: "+CertTools.getIssuerDN(rootcert)+", subjectDN: "+CertTools.getSubjectDN(rootcert));
    	}
        // Verify that the user-certificate is signed by our CA
    	Certificate cacert = cachain[0];
    	try {
    		cert.verify(cacert.getPublicKey());
    	} catch (GeneralSecurityException se) {
    		throw new CertificateSignatureException("Generated certificate does not verify using CA-certificate, issuerDN: "+CertTools.getIssuerDN(cert)+", subjectDN: "+CertTools.getSubjectDN(cert)+
    				", caIssuerDN: "+CertTools.getIssuerDN(cacert)+", caSubjectDN: "+CertTools.getSubjectDN(cacert), se);
    	}
    	if (savekeys) {
            // Save generated keys to database.
            if (log.isDebugEnabled()) {
                log.debug("Saving generated keys for recovery for user: "+ username);
            }
			keyRecoverySession.addKeyRecoveryData(administrator, cert, username, new KeyPairWrapper(rsaKeys));
    	}
        //  Use CN if as alias in the keystore, if CN is not present use username
    	String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
    	if (alias == null) {
    		alias = username;
    	}
        // Store keys and certificates in keystore.
    	KeyStore ks = null;
    	if (createJKS) {
            if (log.isDebugEnabled()) {
                log.debug("Generating JKS for user: "+ username);
            }
    		ks = KeyTools.createJKS(alias, rsaKeys.getPrivate(), password, cert, cachain);
    	} else {
            if (log.isDebugEnabled()) {
                log.debug("Generating PKCS12 for user: "+ username);
            }
    		ks = KeyTools.createP12(alias, rsaKeys.getPrivate(), cert, cachain);
    	}
        if (log.isTraceEnabled()) {
            log.trace("<generateOrKeyRecoverToken");
        }
    	return ks;
    }
}
