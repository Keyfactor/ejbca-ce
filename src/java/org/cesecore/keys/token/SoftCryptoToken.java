/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.StringTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * Handles maintenance of the soft devices producing signatures and handling the private key and stored in database.
 * 
 * Based on EJBCA version: 
 *      SoftCAToken.java 9781 2010-09-02 20:52:06Z primelars $
 * CESeCore version:
 *      SoftCryptoToken.java 477 2011-03-09 12:55:57Z mikek
 * 
 * @version $Id$
 */
public class SoftCryptoToken extends BaseCryptoToken {
    private static final long serialVersionUID = 387950849444619646L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SoftCryptoToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * When upgrading this version, you must up the version of the CA as well, otherwise the upgraded CA token will not be stored in the database.
     */
    public static final float LATEST_VERSION = 3;

    private static final String PROVIDER = "BC";

    /** constants needed for soft CA keystores */
    protected static final String SIGNKEYSPEC = "SIGNKEYSPEC";
    protected static final String ENCKEYSPEC = "ENCKEYSPEC";
    protected static final String SIGNKEYALGORITHM = "SIGNKEYALGORITHM";
    protected static final String ENCKEYALGORITHM = "ENCKEYALGORITHM";

    public static final String NODEFAULTPWD = "NODEFAULTPWD";

    private byte[] keystoreData;

    private char[] keyStorePass;

    public SoftCryptoToken() {
        super();
        if (log.isDebugEnabled()) {
            log.debug("Creating SoftCAToken");
        }
    }

    @Override
    public void init(final Properties properties, final byte[] data, final int id) {
        super.setJCAProviderName(PROVIDER);

        // by default, this implementation should allow to extract keys
        this.allowsExtractablePrivateKey = true;

        superInit(properties, data, id);
    }

    /**
     * Sets up some basic properties used in soft keystores and calls init on BaseCryptoToken in order to set up all key string etc.
     * 
     */
    private void superInit(Properties properties, final byte[] data, final int id)  {

        this.keystoreData = data;

        if (properties == null) {
            properties = new Properties();
        }
        // If we don't have an auto activation password set, we try to use the default one if it works to load the keystore with it
        String autoPwd = BaseCryptoToken.getAutoActivatePin(properties);
        if ((autoPwd == null) && (properties.getProperty(NODEFAULTPWD) == null)) {
            final String keystorepass = StringTools.passwordDecryption(CesecoreConfiguration.getCaKeyStorePass(), "ca.keystorepass");
            // Test it first, don't set an incorrect password as autoactivate password
            boolean okPwd = true;
            try {
                // only verify password
                checkSoftKeystorePassword(keystorepass.toCharArray());
                log.debug("Succeded to load keystore with password");
            } catch (Exception e) {
                // Don't do it
                okPwd = false;
                log.debug("Failed to load keystore with password");
            }
            if (okPwd) {
                BaseCryptoToken.setAutoActivatePin(properties, keystorepass, true);
            }
        } else if (autoPwd != null) {
            log.debug("Soft Crypto Token has autoactivation property set.");
        } else if (properties.getProperty(NODEFAULTPWD) != null) {
            log.debug("No default pwd allowed for this soft crypto token.");
        }
        init(null, properties, true, id);
    }

    @Override
    public void activate(final char[] authCode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        if (keystoreData != null) {
            try {
                KeyStore keystore = loadKeyStore(keystoreData, authCode);
                setKeyStore(keystore);
                // If everything was OK we cache the load/save password so we can store the keystore
                keyStorePass = authCode;
            } catch (IOException e) {
                String msg = intres.getLocalizedMessage("token.erroractivate", getId(), e.getMessage());
                log.info(msg, e);
                CryptoTokenAuthenticationFailedException oe = new CryptoTokenAuthenticationFailedException(e.getMessage());
                oe.initCause(e);
                throw oe;
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("token.erroractivate", getId(), e.getMessage());
                log.info(msg, e);
                CryptoTokenOfflineException oe = new CryptoTokenOfflineException(e.getMessage());
                oe.initCause(e);
                throw oe;
            }
            String msg = intres.getLocalizedMessage("token.activated", getId());
            log.info(msg);
        } else {
            String msg = intres.getLocalizedMessage("token.erroractivate", getId(), "No keystore data available yet, creating new PKCS#12 keystore.");
            log.info(msg);
            try {
                KeyStore keystore = KeyStore.getInstance("PKCS12", PROVIDER);
                keystore.load(null, null);
                setKeyStore(keystore);
                // If everything was OK we cache the load/save password so we can store the keystore
                keyStorePass = authCode;
                storeKeyStore();
            } catch (KeyStoreException e) {
                log.error(e);
                throw new CryptoTokenAuthenticationFailedException(e.getMessage());
            } catch (NoSuchProviderException e) {
                log.error(e);
                throw new CryptoTokenAuthenticationFailedException(e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                log.error(e);
                throw new CryptoTokenAuthenticationFailedException(e.getMessage());
            } catch (CertificateException e) {
                log.error(e);
                throw new CryptoTokenAuthenticationFailedException(e.getMessage());
            } catch (IOException e) {
                log.error(e);
                throw new CryptoTokenAuthenticationFailedException(e.getMessage());
            }
        }
    }

    private KeyStore loadKeyStore(final byte[] ksdata, final char[] keystorepass) throws NoSuchAlgorithmException, CertificateException, IOException,
            KeyStoreException, NoSuchProviderException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KeyStore keystore = KeyStore.getInstance("PKCS12", PROVIDER);
        keystore.load(new java.io.ByteArrayInputStream(ksdata), keystorepass);
        return keystore;
    }

    @Override
    public void deactivate() {
        storeKeyStore();
        setKeyStore(null);
        String msg = intres.getLocalizedMessage("token.deactivate", getId());
        log.info(msg);
    }

    void storeKeyStore() {
        // Store keystore at data first so we can activate again
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            if (keyStore != null) {
                this.keyStore.store(baos, keyStorePass);
                this.keystoreData = baos.toByteArray();
            }
        } catch (KeyStoreException e) {
            log.error(e);
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
        } catch (CertificateException e) {
            log.error(e);
        } catch (IOException e) {
            log.error(e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Storing soft keystore of size " + keystoreData.length);
        }
    }

    @Override
    public byte[] getTokenData() {
        storeKeyStore();
        return keystoreData;
    }

    /**
     * Verifies the password for soft keystore by trying to load the keystore
     * 
     * @param authenticationCode
     *            authentication code for the keystore
     * @throws CATokenAuthenticationFailedException
     */
    private void checkSoftKeystorePassword(final char[] authenticationCode) throws KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, CryptoTokenAuthenticationFailedException {
        try {
            if (keystoreData != null) {
                KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
                keystore.load(new java.io.ByteArrayInputStream(keystoreData), authenticationCode);
            }
        } catch (IOException e) {
            // Invalid password
            String msg = intres.getLocalizedMessage("token.wrongauthcode", getId());
            log.info(msg);

            // If it was not the wrong password we need to see what went wrong
            log.debug("Error: ", e);

            throw new CryptoTokenAuthenticationFailedException(msg);
        }
    }

    @Override
    public void deleteEntry(final char[] authenticationCode, final String alias) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            try {
                cont.deleteEntry(alias);
                String msg = intres.getLocalizedMessage("token.deleteentry", getId(), alias);
                log.info(msg);
            } catch (KeyStoreException e) { // NOPMD
                // P12 keystore throws when the alias can not be found, in contrary to PKCS#11 keystores
                // Java API is vague about what should happen so...
            }
            storeKeyStore();
        } else {
            log.debug("Trying to delete keystore entry with empty alias.");
        }
    }

    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, KeyStoreException, CertificateException, IOException,
            CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKeyPair(keySpec, alias);
            storeKeyStore();
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException,
            CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException {
        if (StringUtils.isNotEmpty(alias)) {
            // Soft crypto tokens must do very special things for secret keys, since PKCS#12 keystores are ot designed to hold
            // symmetric keys, we wrap the symmetric key with an RSA key and store it in properties

            // Generate the key
            KeyGenerator generator = KeyGenerator.getInstance(algorithm, getEncProviderName());
            generator.init(keysize);
            Key key = generator.generateKey();
            // Wrap it
            // Find wrapping key
            PublicKey pubK = null;
            try {
                pubK = getPublicKey("symwrap");
            } catch (CryptoTokenOfflineException e) {
                // No such key, generate it
                generateKeyPair("2048", "symwrap");
                pubK = getPublicKey("symwrap");
            }

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", getEncProviderName());
            cipher.init(Cipher.WRAP_MODE, pubK);
            byte[] out = cipher.wrap(key);

            String str = new String(Hex.encode(out));
            Properties prop = getProperties();
            prop.setProperty(alias, str);
            setProperties(prop);
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, KeyStoreException, CertificateException, IOException,
            CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKeyPair(spec, alias);
            storeKeyStore();
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

}
