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
package org.cesecore.keys.token;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;

/**
 * Utility methods for creating CAs and CryptoTokens for tests. Both soft and PKCS#11 tokens.
 * <p>
 * PKCS#11 tokens will be created with the properties defined in systemtests.properties, if present.
 * Otherwise defaults will be used (see systemtest.properties.sample or {@link SystemTestsConfiguration}) 
 */
public class CryptoTokenTestUtils {

    private static final Logger log = Logger.getLogger(CryptoTokenTestUtils.class);

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CryptoTokenTestUtils.class.getSimpleName()));

    public static final char[] SOFT_TOKEN_PIN = "foo123".toCharArray();

    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    public static X509CA createTestCAWithSoftCryptoToken(AuthenticationToken authenticationToken, String dN) throws Exception {
      return createTestCAWithSoftCryptoToken(authenticationToken, dN, CAInfo.SELFSIGNED);
    }
    
    public static X509CA createTestCAWithSoftCryptoToken(AuthenticationToken authenticationToken, String dN, int signedBy) throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        X509CA x509ca = CaTestUtils.createTestX509CA(dN, SOFT_TOKEN_PIN, SoftCryptoToken.class.getName(), signedBy, X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign
                + X509KeyUsage.cRLSign);
        // Remove any lingering test CA before starting the tests
        CAInfo oldCaInfo = caSession.getCAInfo(authenticationToken, x509ca.getCAId());
        if (oldCaInfo != null) {
            CaTestUtils.removeCa(authenticationToken, oldCaInfo);
        }
        // Now add the test CA so it is available in the tests
        caSession.addCA(authenticationToken, x509ca);
        return x509ca;
    }

    /** Create CryptoToken and generate CA's keys */
    public static int createCryptoTokenForCA(AuthenticationToken authenticationToken, String tokenName, String signKeySpec) {
        return createCryptoTokenForCA(authenticationToken, null, true, false, tokenName, signKeySpec);
    }

    public static int createCryptoTokenForCA(AuthenticationToken authenticationToken, char[] pin, String tokenName, String signKeySpec) {
        return createCryptoTokenForCA(authenticationToken, pin, true, false, tokenName, signKeySpec);
    }

    public static int createCryptoTokenForCA(AuthenticationToken authenticationToken, char[] pin, boolean generateKeys, boolean pkcs11,
            String tokenName, String signKeySpec) {
        return createCryptoTokenForCA(authenticationToken, pin, generateKeys, pkcs11, tokenName, signKeySpec, signKeySpec);
    }
    
    public static int createCryptoTokenForCA(AuthenticationToken authenticationToken, char[] pin, boolean generateKeys, boolean pkcs11,
            String tokenName, String signKeySpec, String encKeySpec) {
       
        final String cryptoTokenImplementation;
        if (pkcs11) {         
            cryptoTokenImplementation = PKCS11CryptoToken.class.getName();
        } else {

            cryptoTokenImplementation = SoftCryptoToken.class.getName();
        }       
        return createCryptoTokenForCA(authenticationToken, pin, generateKeys, cryptoTokenImplementation, tokenName, signKeySpec, encKeySpec);

    }

    /**
     * Creates a simple crypto token, no frills. 
     * 
     * @param pin the pin of the slot
     * @param cryptoTokenImplementation the implemenation name, i.e org.cesecore.keys.token.SoftCryptoToken
     * @param tokenName the name of the crypto token
     * @return the crypto token ID
     */
    public static int createCryptoToken(char[] pin, String cryptoTokenImplementation, String tokenName) {
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
            removeCryptoToken(alwaysAllowToken, oldCryptoTokenId);
        }

        // Set up properties
        final Properties cryptoTokenProperties = new Properties();
        if (cryptoTokenImplementation.equals(SoftCryptoToken.class.getName())) {
            // For CA export tests
            cryptoTokenProperties.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        } else {
            //It's either a PKCS#11 token or a P11NG token
            if (SystemTestsConfiguration.getPkcs11Library() == null) {
                throw new IllegalStateException("No crypto library found.");
            }
            cryptoTokenProperties.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, SystemTestsConfiguration.getPkcs11Library());
            cryptoTokenProperties.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, SystemTestsConfiguration.getPkcs11SlotValue("1"));
            cryptoTokenProperties.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE,
                    SystemTestsConfiguration.getPkcs11SlotType(Pkcs11SlotLabelType.SLOT_NUMBER.getKey()).getKey());
        }

        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        if (pin == null) {
            cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo1234");
        } else {
            cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, String.valueOf(pin));
        }

        // Create the cryptotoken
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(alwaysAllowToken, fullTokenName, cryptoTokenImplementation,
                    cryptoTokenProperties, null, pin);
        } catch (CryptoTokenOfflineException | CryptoTokenAuthenticationFailedException | CryptoTokenNameInUseException | AuthorizationDeniedException
                | NoSuchSlotException e) {
            throw new IllegalStateException(e);
        }

        return cryptoTokenId;
    }
    
    public static int createCryptoTokenForCA(AuthenticationToken authenticationToken, char[] pin, boolean generateKeys,
            String cryptoTokenImplementation, String tokenName, String signKeySpec, String encKeySpec) {
        if (authenticationToken == null) {
            authenticationToken = alwaysAllowToken;
        }
        int cryptoTokenId = createCryptoToken(pin, cryptoTokenImplementation, tokenName);
        try {
            if (generateKeys) {
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,
                        KeyGenParams.builder(signKeySpec).build());
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, CAToken.SOFTPRIVATEDECKEYALIAS,
                        KeyGenParams.builder(encKeySpec).build());
            }
        } catch (AuthorizationDeniedException | InvalidKeyException | CryptoTokenOfflineException | InvalidAlgorithmParameterException e) {
            // Cleanup token if we failed during the key creation stage
            try {
                removeCryptoToken(null, cryptoTokenId);
            } catch (Exception e2) {
                log.error("", e2);
            }
            throw new IllegalStateException(e);
        }
        return cryptoTokenId;
    }

    public static int createSoftCryptoToken(AuthenticationToken authenticationToken, String cryptoTokenName) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        // Remove any old CryptoToken created by this setup
        final Integer oldCryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (oldCryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, oldCryptoTokenId.intValue());
        }
        Properties props = new Properties();
        props.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.TRUE.toString());
        return cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName, SoftCryptoToken.class.getName(), props, null,
                SOFT_TOKEN_PIN);
    }


    /** Remove the cryptoToken, if the crypto token with the given ID does not exist, nothing happens */
    public static void removeCryptoToken(AuthenticationToken authenticationToken, final int cryptoTokenId) {
        if (authenticationToken == null) {
            authenticationToken = alwaysAllowToken;
        }
        try {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        } catch (AuthorizationDeniedException e) {
            throw new RuntimeException(e); // Expect that calling method knows what it's doing
        }
    }

    public static void removeCryptoToken(final AuthenticationToken authenticationToken, final String tokenName) {
        while (true) {
            final Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(tokenName);
            if (cryptoTokenId == null) {
                return;
            }
            removeCryptoToken(authenticationToken, cryptoTokenId);
        }
    }
}
