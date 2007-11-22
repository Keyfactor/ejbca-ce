package org.ejbca.core.model.util;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

/** Class that has helper methods to generate tokens for users in ejbca. 
 * Generating tokens can often depend on the ejb services (local interfaces), for example for key recovery.
 * 
 * @author Tomas Gustavsson
 * @version $Id: GenerateToken.java,v 1.1 2007-11-22 17:17:20 anatom Exp $
 */
public class GenerateToken {
    private static final Logger log = Logger.getLogger(GenerateToken.class);

    private static IKeyRecoverySessionLocal keyrecoverysession = null;
	private static IAuthenticationSessionLocal authsession = null;

    private static ISignSessionLocal signsession = null;
    private static ICAAdminSessionLocal casession = null;

    private static synchronized ISignSessionLocal getSignSession() throws CreateException {
    	if(signsession == null){	
    			ISignSessionLocalHome signhome = (ISignSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
    			signsession = signhome.create();
    	}
    	return signsession;
    }
    
    private static synchronized ICAAdminSessionLocal getCASession() throws CreateException {
    	if(casession == null){	
    			ICAAdminSessionLocalHome cahome = (ICAAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
    			casession = cahome.create();
    	}
    	return casession;
    }

    private static synchronized IAuthenticationSessionLocal getAuthSession() throws CreateException {
    	if(authsession == null){	
    			IAuthenticationSessionLocalHome cahome = (IAuthenticationSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IAuthenticationSessionLocalHome.COMP_NAME);
    			authsession = cahome.create();
    	}
    	return authsession;
    }

    private static synchronized IKeyRecoverySessionLocal getKeyRecoverySession() throws CreateException {
    	if(keyrecoverysession == null){	
    			IKeyRecoverySessionLocalHome home = (IKeyRecoverySessionLocalHome)ServiceLocator.getInstance().getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
    			keyrecoverysession = home.create();
    	}
    	return keyrecoverysession;
    }

    private GenerateToken() {}
    
    /**
     * This method generates a new pkcs12 or jks token for a user, and key recovers the token, if the user is configured for that in EJBCA.
     * 
     * @param administrator administrator performing the action
     * @param username username in ejbca
     * @param password password for user
     * @param caid caid of the CA the user is registered for
     * @param keyspec length of RSA keys or name of ECDSA 
     * @param keyalg CATokenConstants.KEYALGORITHM_RSA or CATokenConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @param loadkeys true if keys should be recovered
     * @param savekeys true if generated keys should be stored for keyrecovery
     * @param reusecertificate true if the old certificate should be reused for a recovered key
     * @param endEntityProfileId the end entity profile the user is registered for
     * @return KeyStore
     * @throws Exception if something goes wrong...
     */
    public static KeyStore generateOrKeyRecoverToken(Admin administrator, String username, String password, int caid, String keyspec, 
    		String keyalg, boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
    throws Exception {
    	log.debug(">generateOrKeyRecoverToken");
    	KeyRecoveryData keyData = null;
    	KeyPair rsaKeys = null;
    	if (loadkeys) {
    		log.debug("Recovering keys for user: "+ username);
            // used saved keys.
    		keyData = getKeyRecoverySession().keyRecovery(administrator, username, endEntityProfileId);
    		if (keyData == null) {
    			throw new Exception("No key recovery data exists for user");
    		}
    		rsaKeys = keyData.getKeyPair();
    		if (reusecertificate) {
    			// TODO: Why is this only done is reusecertificate == true ??
        		log.debug("Re-using old certificate for user: "+ username);
    			getKeyRecoverySession().unmarkUser(administrator,username);
    		}
    	} else {
    		log.debug("Generating new keys for user: "+ username);
            // generate new keys.
    		rsaKeys = KeyTools.genKeys(keyspec, keyalg);
    	}

    	X509Certificate cert = null;
    	if ((reusecertificate) && (keyData != null)) {
    		cert = (X509Certificate) keyData.getCertificate();
    		ICAAdminSessionLocal caadminsession = getCASession();
    		boolean finishUser = caadminsession.getCAInfo(administrator,caid).getFinishUser();
    		if (finishUser) {
    			getAuthSession().finishUser(administrator, username, password);
    		}
    	} else {
    		log.debug("Generating new certificate for user: "+ username);
    		cert = (X509Certificate)getSignSession().createCertificate(administrator, username, password, rsaKeys.getPublic());	 
    	}

        // Make a certificate chain from the certificate and the CA-certificate
    	Certificate[] cachain = (Certificate[])getSignSession().getCertificateChain(administrator, caid).toArray(new Certificate[0]);

        // Verify CA-certificate
    	if (CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
    		try {
    			cachain[cachain.length - 1].verify(cachain[cachain.length - 1].getPublicKey());
    		} catch (GeneralSecurityException se) {
    			throw new Exception("RootCA certificate does not verify");
    		}
    	} else {
    		throw new Exception("RootCA certificate not self-signed");
    	}

        // Verify that the user-certificate is signed by our CA
    	try {
    		cert.verify(cachain[0].getPublicKey());
    	} catch (GeneralSecurityException se) {
    		throw new Exception("Generated certificate does not verify using CA-certificate.");
    	}

    	if (savekeys) {
            // Save generated keys to database.
    		log.debug("Saving generated keys for recovery for user: "+ username);
    		getKeyRecoverySession().addKeyRecoveryData(administrator, cert, username, rsaKeys);
    	}

        //  Use CN if as alias in the keystore, if CN is not present use username
    	String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
    	if (alias == null) alias = username;

        // Store keys and certificates in keystore.
    	KeyStore ks = null;
    	if (createJKS) {
    		log.debug("Generating JKS for user: "+ username);
    		ks = KeyTools.createJKS(alias, rsaKeys.getPrivate(), password, cert, cachain);
    	} else {
    		log.debug("Generating PKCS12 for user: "+ username);
    		ks = KeyTools.createP12(alias, rsaKeys.getPrivate(), cert, cachain);
    	}
    	
    	log.debug("<generateOrKeyRecoverToken");
    	return ks;
    }

}
