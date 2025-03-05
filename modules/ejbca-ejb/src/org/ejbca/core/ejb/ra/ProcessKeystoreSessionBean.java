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

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.keyimport.KeyImportException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

/**
 * Implementation of ProcessKeystoreSession
 */

@Stateless
public class ProcessKeystoreSessionBean implements ProcessKeystoreSessionLocal, ProcessKeystoreSessionRemote {
    
    private static final Logger log = Logger.getLogger(ProcessKeystoreSessionBean.class);

    private static final String CERTIFICATE_TAG = "IMPORTED";

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void processKeyStore(final AuthenticationToken authenticationToken, final KeyImportKeystoreData keystoreData, final CAInfo caInfo,
                                            final CAData caData, final int certificateProfileId, final int endEntityProfileId) throws KeyImportException {
        try {
            // Check whether username and password exist
            String username = keystoreData.getUsername();
            String password = keystoreData.getPassword();
            if (StringUtils.isEmpty(username)) {
                log.info("Username is null or empty, can't process keystore");
                throw new KeyImportException("Username is null or empty, can't process keystore");
            } else if (StringUtils.isEmpty(password)) {
                log.info("Password for username " + username + " is null or empty, can't process keystore");
                throw new KeyImportException("Password for username " + username + " is null or empty, can't process keystore");
            }

            // Load keystore
            String keystoreString = keystoreData.getKeystore();
            byte[] keystoreBytes = Base64.decodeURLSafe(keystoreString);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new java.io.ByteArrayInputStream(keystoreBytes), keystoreData.getPassword().toCharArray());
            final Enumeration<String> en = keystore.aliases();
            String privateKeyAlias;
            EndEntityInformation userInfo = null;
            while (en.hasMoreElements()) {
                privateKeyAlias = null;
                final String alias = en.nextElement();
                if (keystore.isKeyEntry(alias)) {
                    privateKeyAlias = alias;
                    if (log.isDebugEnabled()) {
                        log.debug("Found a private key alias in keystore: " + privateKeyAlias);
                    }
                }
                if (privateKeyAlias == null) {
                    log.info("Keystore contains an alias which is not a key entry alias.");
                    throw new KeyImportException("Keystore contains an alias which is not a key entry alias.");
                }
                final Certificate[] certChain = KeyTools.getCertChain(keystore, privateKeyAlias);
                if (certChain == null || certChain.length == 0) {
                    log.info("Cannot load any certificate chain with alias: " + privateKeyAlias);
                    throw new KeyImportException("Cannot load certificate chain with alias: " + privateKeyAlias);
                }
                final Certificate userCertificate = certChain[0];
                final String fingerprint = CertTools.getFingerprintAsString(userCertificate);
                final String userCertIssuerDN = CertTools.getIssuerDN(userCertificate);
                if (log.isDebugEnabled()) {
                    log.debug("Found certificate with fingerprint '" + fingerprint + "' and issuerDN '" + userCertIssuerDN + "'.");
                }

                final PrivateKey p12PrivateKey = (PrivateKey) keystore.getKey(privateKeyAlias, keystoreData.getPassword().toCharArray());
                if (p12PrivateKey == null) {
                    log.error("Cannot load any private key with alias: " + privateKeyAlias);
                    throw new KeyImportException("Cannot load private key with alias: " + privateKeyAlias);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Found private key with algorithm: " + p12PrivateKey.getAlgorithm());
                }

                if (userInfo == null) {
                    userInfo = createUserIfNecessary(authenticationToken, keystoreData, caData, certificateProfileId,
                            endEntityProfileId, userCertificate);
                }
                final Certificate caCert = caInfo.getCertificateChain().iterator().next();
                persistCertificate(authenticationToken, userInfo, caInfo, certificateProfileId, endEntityProfileId,
                        fingerprint, userCertificate, caCert);

                persistKeyRecoveryData(authenticationToken, userInfo, caInfo, userCertificate, p12PrivateKey, caCert);
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()){
                log.error(e);
            }
            throw new KeyImportException("Invalid keystore file.");
        } catch (Exception e) {
            final String message = StringUtils.isBlank(e.getMessage()) ? "Unexpected key import error." : e.getMessage();
            if (log.isDebugEnabled()){
                log.error(e);
            }
            throw new KeyImportException(message);
        }
    }

    private void persistCertificate(AuthenticationToken authenticationToken, EndEntityInformation userInfo, CAInfo caInfo,
                                           int certificateProfileId, int endEntityProfileId, String fingerprint, Certificate userCertificate, Certificate caCert)
            throws AuthorizationDeniedException, KeyImportException {
        // Try to fetch old certificate from the database
        CertificateInfo certInfo = certificateStoreSession.getCertificateInfo(fingerprint);
        // Import the old certificate into EJBCA
        final int crlPartitionIndex = caInfo.determineCrlPartitionIndex(userCertificate);
        final String issuerDn = caInfo.getSubjectDN();
        if (certInfo == null) {
            log.info("Adding end entity certificate with fingerprint '" + fingerprint +
                    "' to the database, with status active (not revoked), for end entity: " + userInfo.getUsername());
            certificateStoreSession.storeCertificate(authenticationToken, userCertificate,
                    userInfo.getUsername(), CertTools.getFingerprintAsString(caCert), CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, certificateProfileId, endEntityProfileId, crlPartitionIndex, CERTIFICATE_TAG,
                    new Date().getTime(), null, issuerDn);
        } else {
            throw new KeyImportException("Key import failed because the certificate already exists in the database.");
        }
    }

    private void persistKeyRecoveryData(AuthenticationToken authenticationToken, EndEntityInformation userInfo, CAInfo caInfo,
                                        Certificate userCertificate, PrivateKey p12PrivateKey, Certificate cacert) throws CryptoTokenOfflineException,
            EjbcaException {
        final PublicKey p12PublicKey = userCertificate.getPublicKey();
        final KeyPair keypair = new KeyPair(p12PublicKey, p12PrivateKey);
        CAToken caToken = caInfo.getCAToken();
        String encryptKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
        final int cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
        if (encryptKeyAlias != null && authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY)) {
            keyRecoverySession.addKeyRecoveryDataInternal(authenticationToken, EJBTools.wrap(cacert),
                    EJBTools.wrap(userCertificate), userInfo.getUsername(), EJBTools.wrap(keypair), cryptoTokenId, encryptKeyAlias, caInfo.getSubjectDN());
        } else {
            log.info("Not authorized to add key recovery data to CA or unable to get CA encrypt key.");
            throw new KeyImportException("Not authorized to add key recovery data to CA or unable to get CA encrypt key.");
        }
    }

    private EndEntityInformation createUserIfNecessary(final AuthenticationToken authenticationToken, final KeyImportKeystoreData keystore, final CAData ca,
                                       final int certificateProfileId, final int endEntityProfileId, final Certificate userCertificate)
            throws AuthorizationDeniedException, KeyImportException {
        // Check whether EE exists already
        String username = keystore.getUsername();
        String password = keystore.getPassword();
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, username);
        if (endEntityInformation == null) {
            log.info("No user found for username " + username + ", creating a new user");
            try {
                endEntityInformation = new EndEntityInformation(keystore.getUsername(), CertTools.getSubjectDN(userCertificate), ca.getCaId(),
                        DnComponents.getSubjectAlternativeName(userCertificate), DnComponents.getEMailAddress(userCertificate), EndEntityConstants.STATUS_GENERATED,
                        new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certificateProfileId, null, null,
                        SecConst.TOKEN_SOFT_P12, null);
                endEntityInformation.setPassword(password);
                endEntityManagementSession.addUserForKeyImport(authenticationToken, endEntityInformation, false);
            } catch (Exception e) {
                log.info("Exception: " + e.getMessage());
                throw new KeyImportException(e.getMessage());
            }
        }

        return endEntityInformation;
    }

}
