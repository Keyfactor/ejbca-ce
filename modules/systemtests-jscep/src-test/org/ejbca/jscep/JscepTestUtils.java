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
package org.ejbca.jscep;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Basic utility methods to enable testing of jscep.
 */

public abstract class JscepTestUtils {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("JscepTestUtils"));
    private static final Logger log = Logger.getLogger(JscepTestUtils.class);

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    /** Creates and adds a Sub CA to EJBCA. */
    public static X509CAInfo createTestX509RootCA(final String caName, String cadn, char[] tokenpin, final String keySpec, final int certificateProfileId)
            throws CryptoTokenOfflineException, CAExistsException, InvalidAlgorithmException, AuthorizationDeniedException {
        return createTestX509CA(caName, cadn, tokenpin, CAInfo.SELFSIGNED, keySpec, certificateProfileId);
    }

    /** Creates and adds a CA to EJBCA. */
    public static X509CAInfo createTestX509CA(final String caName, String cadn, char[] tokenpin, int signedBy, final String keySpec,
            final int certificateProfileId)
            throws CryptoTokenOfflineException, CAExistsException, InvalidAlgorithmException, AuthorizationDeniedException {
        // Create catoken
        final String signingKeyName = caName + "_sign";
        final String encryptionKeyName = caName + "_enc";
        int cryptoTokenId = createCryptoTokenForCA(tokenpin, caName, keySpec, signingKeyName, encryptionKeyName);
        final CAToken catoken = createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                signingKeyName, encryptionKeyName);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, caName, CAConstants.CA_ACTIVE, certificateProfileId, "3650d", signedBy, null,
                catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedCaServices);
        boolean ldapOrder = !DnComponents.isDNReversed(cadn);
        cainfo.setUseLdapDnOrder(ldapOrder);
        cainfo.setCmpRaAuthSecret("foo123");
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // Create the SubCA, signed by Root designated by "signedby"

        caAdminSession.createCA(admin, cainfo);
        // Now our CA should be operational
        return (X509CAInfo) caSession.getCAInfo(admin, caName);
    }

    /** @return a CAToken for referencing the specified CryptoToken. */
    private static CAToken createCaToken(final int cryptoTokenId, String sigAlg, String encAlg, final String signingKeyAlias,
            final String encryptionKeyAlias) {
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();

        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, signingKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, encryptionKeyAlias);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, signingKeyAlias);

        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        catoken.setSignatureAlgorithm(sigAlg);
        catoken.setEncryptionAlgorithm(encAlg);
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        return catoken;
    }

    private static int createCryptoTokenForCA(final char[] pin, final String tokenName, final String keySpec, final String signingKeyName,
            final String encryptionKeyName) {
        int cryptoTokenId = createCryptoToken(pin, tokenName);
        try {

            cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, signingKeyName, KeyGenParams.builder(keySpec).build());
            cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, encryptionKeyName, KeyGenParams.builder(keySpec).build());

        } catch (Exception e) { // Make sure to catch all, can be wrapped in EJBException
            // Cleanup token if we failed during the key creation stage
            try {
                removeCryptoToken(cryptoTokenId);
            } catch (Exception e1) {
                log.error("", e1);
            }
            throw new IllegalStateException(e);
        }
        return cryptoTokenId;
    }

    /**
     * Creates a simple crypto token, no frills.
     *
     * @param pin the pin of the slot
     * @param tokenName the name of the crypto token
     * @return the crypto token ID
     */
    public static int createCryptoToken(char[] pin, String tokenName) {
        // Generate full name of cryptotoken including class/method name etc.
        final String callingClassName = Thread.currentThread().getStackTrace()[4].getClassName();
        final String callingClassSimpleName = callingClassName.substring(callingClassName.lastIndexOf('.') + 1);
        final String callingMethodName = Thread.currentThread().getStackTrace()[4].getMethodName();
        final String fullTokenName = callingClassSimpleName + "." + callingMethodName + "." + tokenName;

        // Delete cryptotokens with the same name
        while (true) {
            final Integer oldCryptoTokenId = cryptoTokenManagementSession.getIdFromName(fullTokenName);
            if (oldCryptoTokenId == null)
                break;
            removeCryptoToken(oldCryptoTokenId);
        }

        // Set up properties
        final Properties cryptoTokenProperties = new Properties();
        // For CA export tests
        cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());

        if (pin == null) {
            cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        } else {
            cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, String.valueOf(pin));
        }

        // Create the cryptotoken
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(admin, fullTokenName, SoftCryptoToken.class.getName(),
                    cryptoTokenProperties, null, pin);
        } catch (CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException | CryptoTokenNameInUseException | AuthorizationDeniedException
                | NoSuchSlotException e) {
            throw new IllegalStateException(e);
        }

        return cryptoTokenId;
    }

    /** Remove the cryptoToken, if the crypto token with the given ID does not exist, nothing happens */
    public static void removeCryptoToken(final int cryptoTokenId) {

        try {
            cryptoTokenManagementSession.deleteCryptoToken(admin, cryptoTokenId);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Expect that calling method knows what it's doing
        }
    }

    /** Removes a CA, and it's associated certificate and Crypto Token. */
    public static void removeCa(final String caName) throws AuthorizationDeniedException {
        CAInfo caInfo = caSession.getCAInfo(admin, caName);
        Integer cryptoTokenId = null;
        if (caInfo != null) {
            if (caInfo.getCAToken() != null) {
                // We want to delete this CAs crypto token
                cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
            }
            caSession.removeCA(admin, caInfo.getCAId());
            internalCertificateStoreSession.removeCertificatesBySubject(caInfo.getSubjectDN());
        }
        if (cryptoTokenId == null) {
            // If we didn't find on in CAToken, make sure we don't have one with the same name as the CA
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(caName);
        }
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(admin, cryptoTokenId);
        }
    }
}
