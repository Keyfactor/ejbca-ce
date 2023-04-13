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

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
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
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.keys.KeyStoreTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
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
import java.util.Date;

/**
 * Implementation of KeyStoreCreateSession
 * Class that has helper methods to generate tokens for users in ejbca.
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyStoreCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyStoreCreateSessionBean implements KeyStoreCreateSessionLocal, KeyStoreCreateSessionRemote {
    
    private static final Logger log = Logger.getLogger(KeyStoreCreateSessionBean.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
	private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private SignSessionLocal signSession;

    @Override
    public byte[] generateOrKeyRecoverTokenAsByteArray(final AuthenticationToken authenticationToken, final String username, final String password, final String keySpecification, final String keyAlgorithm)
            throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        // Check if user exists.
        final EndEntityInformation endEntity = endEntityAccessSession.findUser(authenticationToken, username);
        if(endEntity == null) {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            throw new NotFoundException(intres.getLocalizedMessage("ra.wrongusernameorpassword"));
        }
        // Check CA ID and authorization.
        final int caId = endEntity.getCAId();
        caSession.verifyExistenceOfCA(caId);
        if(!authorizationSession.isAuthorized(authenticationToken, StandardRules.CAACCESS.resource() + caId, StandardRules.CREATECERT.resource())) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() +caId +
                    "," + StandardRules.CREATECERT.resource(), null);
            throw new AuthorizationDeniedException(msg);
        }
        // Check token type.
        if (endEntity.getTokenType() != SecConst.TOKEN_SOFT_P12) { // logger
            throw new EjbcaException(ErrorCode.BAD_USER_TOKEN_TYPE, "Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests");
        }
        final boolean useKeyRecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
        if (log.isDebugEnabled()) {
            log.debug("usekeyrecovery: " + useKeyRecovery);
        }
        final boolean saveKeys = endEntity.getKeyRecoverable() && useKeyRecovery && (endEntity.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
        if (log.isDebugEnabled()) {
            log.debug("userdata.getKeyRecoverable(): " + endEntity.getKeyRecoverable());
            log.debug("userdata.getStatus(): " + endEntity.getStatus());
            log.debug("savekeys: " + saveKeys);
        }
        final boolean loadKeys = (endEntity.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && useKeyRecovery;
        if (log.isDebugEnabled()) {
            log.debug("loadkeys: " + loadKeys);
        }
        final int endEntityProfileId = endEntity.getEndEntityProfileId();
        final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
        final boolean reuseCertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
        if (log.isDebugEnabled()) {
            log.debug("reusecertificate: " + reuseCertificate);
        }
        try {
            final KeyStore keyStore = generateOrKeyRecoverToken(authenticationToken, username, password, caId,
                    keySpecification, keyAlgorithm, null, null, SecConst.TOKEN_SOFT_P12, loadKeys, saveKeys, reuseCertificate, endEntityProfileId);
            return KeyStoreTools.getAsByteArray(keyStore, password);
        } catch (AuthLoginException e) { // Is handled as EjbcaException at caller (EjbcaWS).
            throw e;
        } catch (AuthStatusException e) { // Is handled as EjbcaException at caller (EjbcaWS).
            throw e;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Re-throw exception in RA master API: " + e.getMessage(), e);
            }
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }

    @Override
    public byte[] generateOrKeyRecoverTokenAsByteArray(AuthenticationToken administrator, String username, String password, int caid, String keyspec,
            String keyalg, int keystoreType, boolean loadkeys, boolean savekeys, boolean reusecertificate, int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, EndEntityProfileValidationException, NoSuchEndEntityException,
            CertificateSignatureException, CertificateEncodingException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyStore keyStore = generateOrKeyRecoverToken(administrator, username, password, caid, keyspec, keyalg, null, null, keystoreType, loadkeys,
                savekeys,
                reusecertificate, endEntityProfileId);
        return KeyStoreTools.getAsByteArray(keyStore, password);
    }

    @Override
    public KeyStore generateOrKeyRecoverToken(AuthenticationToken administrator, String username, String password, int caid,
            String keyspec, String keyalg, Date notBefore, Date notAfter, int keystoreType, boolean loadkeys, boolean savekeys,
            boolean reusecertificate,
            int endEntityProfileId)
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
        if (userdata == null) {
            throw new NoSuchEndEntityException("User '" + username + "' does not exist");
        }
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
                throw new KeyStoreException("No key recovery data exists for the user '" + username + "', or access to key recovery for the "
                        + "end entity profile with ID '" + endEntityProfileId + "' has not been granted to the role member '" + administrator + "'.");
    		}
    		rsaKeys = keyData.getKeyPair();
    		if (reusecertificate) {
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
            if (userdata.getExtendedInformation() != null) {
                if (userdata.getExtendedInformation().getKeyStoreAlgorithmType() != null
                        && userdata.getExtendedInformation().getKeyStoreAlgorithmSubType() != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using the key-store algorithm specification found inside the endEntityInformation ("
                                + userdata.getExtendedInformation().getKeyStoreAlgorithmType() + "_"
                                + userdata.getExtendedInformation().getKeyStoreAlgorithmSubType() + ") instead of one provided separately (" + keyalg
                                + "_" + keyspec + ")");
                    }
                    keyalg = userdata.getExtendedInformation().getKeyStoreAlgorithmType();
                    keyspec = userdata.getExtendedInformation().getKeyStoreAlgorithmSubType();
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
				endEntityManagementSession.finishUser(userdata);
    		}
    	} else {
            if (log.isDebugEnabled()) {
                log.debug("Generating new certificate for user: "+ username);
            }
            cert = (X509Certificate) signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(rsaKeys.getPublic()), -1,
                    notBefore, notAfter);
    	}
    	// Clear password from database
    	userdata = endEntityAccessSession.findUser(administrator, username); //Get GENERATED end entity information
        KeyStore ks = finishProcessingAndStoreKeys(administrator, username, password, caid, keystoreType, loadkeys, savekeys, isNewToken, rsaKeys,
                userdata, cert);
    	return ks;
    }
    
    @Override
    public KeyStore generateOrKeyRecoverTokenWithoutViewEndEntityAccessRule(AuthenticationToken administrator, String username, String password, int caid,
            String keyspec, String keyalg, Date notBefore, Date notAfter, int keystoreType, boolean loadkeys, boolean savekeys,
            boolean reusecertificate,
            int endEntityProfileId)
            throws AuthorizationDeniedException, KeyStoreException, InvalidAlgorithmParameterException, CADoesntExistsException, IllegalKeyException,
            CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, EndEntityProfileValidationException, NoSuchEndEntityException,
            CertificateSignatureException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (log.isTraceEnabled()) {
            log.trace(">generateOrKeyRecoverToken");
        }
        boolean isNewToken = false;
        KeyRecoveryInformation keyData = null;
        KeyPair rsaKeys = null;
        EndEntityInformation userdata = endEntityAccessSession.findUserWithoutViewEndEntityAccessRule(administrator, username);
        if (userdata == null) {
            throw new NoSuchEndEntityException("User '" + username + "' does not exist");
        }
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
                throw new KeyStoreException("No key recovery data exists for the user '" + username + "', or access to key recovery for the "
                        + "end entity profile with ID '" + endEntityProfileId + "' has not been granted to the role member '" + administrator + "'.");
            }
            rsaKeys = keyData.getKeyPair();
            if (reusecertificate) {
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
            if (userdata.getExtendedInformation() != null) {
                if (userdata.getExtendedInformation().getKeyStoreAlgorithmType() != null
                        && userdata.getExtendedInformation().getKeyStoreAlgorithmSubType() != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using the key-store algorithm specification found inside the endEntityInformation ("
                                + userdata.getExtendedInformation().getKeyStoreAlgorithmType() + "_"
                                + userdata.getExtendedInformation().getKeyStoreAlgorithmSubType() + ") instead of one provided separately (" + keyalg
                                + "_" + keyspec + ")");
                    }
                    keyalg = userdata.getExtendedInformation().getKeyStoreAlgorithmType();
                    keyspec = userdata.getExtendedInformation().getKeyStoreAlgorithmSubType();
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
                endEntityManagementSession.finishUser(userdata);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Generating new certificate for user: "+ username);
            }
            cert = (X509Certificate) signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(rsaKeys.getPublic()), -1,
                    notBefore, notAfter);
        }
        // Clear password from database
        userdata = endEntityAccessSession.findUserWithoutViewEndEntityAccessRule(administrator, username); //Get GENERATED end entity information
        KeyStore ks = finishProcessingAndStoreKeys(administrator, username, password, caid, keystoreType, loadkeys, savekeys, isNewToken, rsaKeys,
                userdata, cert);
        return ks;
    }

    private KeyStore finishProcessingAndStoreKeys(AuthenticationToken administrator, String username, String password, int caid, int keystoreType,
            boolean loadkeys, boolean savekeys, boolean isNewToken, KeyPair rsaKeys, EndEntityInformation userdata, X509Certificate cert)
            throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException, CertificateSignatureException,
            KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (userdata.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            // Don't clear the password if "Allow renewal before expiration" is enabled
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(userdata.getEndEntityProfileId());
            if (eep == null || !eep.isRenewDaysBeforeExpirationUsed()) {
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
        }
        // Make a certificate chain from the certificate and the CA-certificate
        Certificate[] cachain = signSession.getCertificateChain(caid).toArray(new Certificate[0]);
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
        if (keystoreType == SecConst.TOKEN_SOFT_JKS) {
            if (log.isDebugEnabled()) {
                log.debug("Generating JKS for user: "+ username);
            }
            ks = KeyTools.createJKS(alias, rsaKeys.getPrivate(), password, cert, cachain);
        } else if (keystoreType == SecConst.TOKEN_SOFT_BCFKS) {
            if (log.isDebugEnabled()) {
                log.debug("Generating FIPS compliant PKCS12 for user: " + username);
            }
            ks = KeyTools.createBcfks(alias, rsaKeys.getPrivate(), cert, cachain);
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
