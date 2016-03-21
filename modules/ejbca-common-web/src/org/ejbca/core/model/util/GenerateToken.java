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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
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
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;

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
     * @param keyspec name of ECDSA key or length of RSA and DSA keys  
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @param loadkeys true if keys should be recovered
     * @param savekeys true if generated keys should be stored for keyrecovery
     * @param reusecertificate true if the old certificate should be reused for a recovered key
     * @param endEntityProfileId the end entity profile the user is registered for
     * @return KeyStore
     * @throws Exception if something goes wrong...
     */
    public KeyStore generateOrKeyRecoverToken(AuthenticationToken administrator, String username, String password, int caid, String keyspec, 
    		String keyalg, boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
    throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">generateOrKeyRecoverToken");
        }
    	KeyRecoveryInformation keyData = null;
    	KeyPair rsaKeys = null;
    	if (loadkeys) {
    	    if (log.isDebugEnabled()) {
    	        log.debug("Recovering keys for user: "+ username);
    	    }
            // used saved keys.
			keyData = keyRecoverySession.recoverKeys(administrator, username, endEntityProfileId);
    		if (keyData == null) {
    			throw new Exception("No key recovery data exists for user");
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
            // generate new keys.
    		rsaKeys = KeyTools.genKeys(keyspec, keyalg);
    	}
    	X509Certificate cert = null;
    	if ((reusecertificate) && (keyData != null)) {
    		cert = (X509Certificate) keyData.getCertificate();
    		boolean finishUser = true;
			finishUser = caSession.getCAInfo(administrator,caid).getFinishUser();
    		if (finishUser) {
    			EndEntityInformation userdata = endEntityAccessSession.findUser(administrator, username);
				authenticationSession.finishUser(userdata);
    		}
    	} else {
            if (log.isDebugEnabled()) {
                log.debug("Generating new certificate for user: "+ username);
            }
			cert = (X509Certificate)signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(rsaKeys.getPublic()));
    	}
    	// Clear password from database
    	EndEntityInformation userdata = endEntityAccessSession.findUser(administrator, username);
        if (userdata.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            if (loadkeys && endEntityManagementSession instanceof EndEntityManagementSessionLocal) {
                endEntityManagementSession.setClearTextPassword(new AlwaysAllowLocalAuthenticationToken(
                        new UsernamePrincipal("Implicit authorization from key recovery operation to reset password.")), username, null);
            } else {
                endEntityManagementSession.setClearTextPassword(administrator, username, null);
            }
    	}
        // Make a certificate chain from the certificate and the CA-certificate
    	Certificate[] cachain = (Certificate[])signSession.getCertificateChain(caid).toArray(new Certificate[0]);
        // Verify CA-certificate
    	Certificate rootcert = cachain[cachain.length - 1];
    	if (CertTools.isSelfSigned(rootcert)) {
    		try {
    			rootcert.verify(rootcert.getPublicKey());
    		} catch (GeneralSecurityException se) {
    			throw new Exception("RootCA certificate does not verify, issuerDN: "+CertTools.getIssuerDN(rootcert)+", subjectDN: "+CertTools.getSubjectDN(rootcert));
    		}
    	} else {
    		throw new Exception("RootCA certificate not self-signed, issuerDN: "+CertTools.getIssuerDN(rootcert)+", subjectDN: "+CertTools.getSubjectDN(rootcert));
    	}
        // Verify that the user-certificate is signed by our CA
    	Certificate cacert = cachain[0];
    	try {
    		cert.verify(cacert.getPublicKey());
    	} catch (GeneralSecurityException se) {
    		throw new Exception("Generated certificate does not verify using CA-certificate, issuerDN: "+CertTools.getIssuerDN(cert)+", subjectDN: "+CertTools.getSubjectDN(cert)+
    				", caIssuerDN: "+CertTools.getIssuerDN(cacert)+", caSubjectDN: "+CertTools.getSubjectDN(cacert));
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
