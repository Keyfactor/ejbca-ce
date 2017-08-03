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

package org.ejbca.core.ejb.ra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
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
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/** 
 * Implementation of KeyStoreCreateSession
 * Class that has helper methods to generate tokens for users in ejbca. 
 * 
 * @version $Id$
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyStoreCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyStoreCreateSessionBean implements KeyStoreCreateSessionLocal, KeyStoreCreateSessionRemote {
    private static final Logger log = Logger.getLogger(KeyStoreCreateSessionBean.class);

    @EJB
	private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private SignSessionLocal signSession;
    
    @Override
    public byte[] generateOrKeyRecoverTokenAsByteArray(AuthenticationToken administrator, String username, String password, int caid, String keyspec,
            String keyalg, boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, EndEntityProfileValidationException, NoSuchEndEntityException,
            CertificateSignatureException, CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException { 
        
        KeyStore keyStore = generateOrKeyRecoverToken(administrator,  username,  password,  caid,  keyspec, keyalg,  createJKS,  loadkeys,  savekeys,  reusecertificate,  endEntityProfileId);
        try(ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            keyStore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e); //should never happen if keyStore is valid object
        }
        return null;
    }
    
    @Override
    public KeyStore generateOrKeyRecoverToken(AuthenticationToken administrator, String username, String password, int caid, String keyspec,
            String keyalg, boolean createJKS, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, EndEntityProfileValidationException, NoSuchEndEntityException,
            CertificateSignatureException, CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (log.isTraceEnabled()) {
            log.trace(">generateOrKeyRecoverToken");
        }
        boolean isNewToken = false;
    	KeyRecoveryInformation keyData = null;
    	KeyPair rsaKeys = null;
    	EndEntityInformation userdata = endEntityAccessSession.findUser(administrator, username);
    	if (userdata.getStatus() == EndEntityConstants.STATUS_NEW) {
    	    isNewToken = true;
    	}
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
    		    // In this case, signSession.createCertificate is never called, hence the password isn't authentication elsewhere.
    		    endEntityAuthenticationSession.authenticateUser(administrator, username, password);
    			// This is only done if reusecertificate == true because if you don't re-use certificate
    		    // signSession.createCertificate is called, which set status to generated, unless finishUser == false in CA config
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
            if (loadkeys) {
                endEntityManagementSession.setClearTextPassword(new AlwaysAllowLocalAuthenticationToken(
                        new UsernamePrincipal("Implicit authorization from key recovery operation to reset password.")), username, null);
            } else if (isNewToken) {
                // If we generate a new token through an enrollment, we don't want to demand access to edit_end_entity
                endEntityManagementSession.setClearTextPassword(new AlwaysAllowLocalAuthenticationToken(
                        new UsernamePrincipal("Implicit authorization from new enrollments")), username, null);
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
			keyRecoverySession.addKeyRecoveryData(administrator, EJBTools.wrap(cert), username, EJBTools.wrap(rsaKeys));
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
