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

import java.io.ByteArrayInputStream;
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
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyStoreTools;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;


/**
 * Handles maintenance of the soft devices producing signatures and handling the private key and stored in database.
 * 
 */
public class SoftCryptoToken extends BaseCryptoToken {
    private static final long serialVersionUID = 387950849444619646L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SoftCryptoToken.class);

    /**
     * When upgrading this version, you must up the version of the CA as well, otherwise the upgraded CA token will not be stored in the database.
     */
    public static final float LATEST_VERSION = 3;
    
    /**
     * This property value denotes whether the default soft token password is usable on this token (as defined by ca.keystorepass, defaults to 'foo123',
     * which allows it to be activated/deactivated/edited without providing a password. Setting this property (it does not matter what it's value is set to as long as it is present) 
     * means that the default password is not available for use. 
     */
    public static final String NODEFAULTPWD = "NODEFAULTPWD";

    private byte[] keystoreData;
    private char[] keyStorePass;

    public SoftCryptoToken() {
        super();
        if (log.isDebugEnabled()) {
            log.debug("Creating SoftCryptoToken");
        }
    }

    /**
     * Sets up some basic properties used in soft keystores and calls init on BaseCryptoToken in order to set up all key string etc.
     */
    @Override
    public void init(Properties properties, final byte[] data, final int cryptoTokenId) {
        super.setJCAProviderName(BouncyCastleProvider.PROVIDER_NAME);
        this.keystoreData = data;
        if (properties == null) {
            properties = new Properties();
        }
        String autoPwd = BaseCryptoToken.getAutoActivatePin(properties);
        if (autoPwd != null) {
            log.debug("Soft Crypto Token has autoactivation property set.");
        } else if (properties.getProperty(NODEFAULTPWD) != null) {
            log.debug("No default pwd allowed for this soft crypto token.");
        }
        boolean autoActivate = autoPwd != null || properties.getProperty(NODEFAULTPWD) == null;
        init(properties, autoActivate, cryptoTokenId);
    }

    @Override
    public void activate(char[] authCode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        if (keyStore != null) {
            log.debug("Ignoring activation request for already active CryptoToken: " + getId());
            return;
        }
        // If we use auto-activation, we will override whatever is used as parameter (probably null)
        final String autoPwd = BaseCryptoToken.getAutoActivatePin(getProperties());
        if (autoPwd!=null) {
            authCode = autoPwd.toCharArray();
        }
        if (keystoreData != null) {
            try {
                KeyStore keystore = loadKeyStore(keystoreData, authCode);
                setKeyStore(keystore);
                // If everything was OK we cache the load/save password so we can store the keystore
                keyStorePass = authCode;
            } catch (IOException e) {
                String msg = "Error activating Crypto Token with ID " + getId() + ". " + e.getMessage();
                log.info(msg, e);
                CryptoTokenAuthenticationFailedException oe = new CryptoTokenAuthenticationFailedException(e.getMessage());
                oe.initCause(e);
                throw oe;
            } catch (Exception e) {
                String msg = "Error activating Crypto Token with ID " + getId() + ". " + e.getMessage();
                log.info(msg, e);
                CryptoTokenOfflineException oe = new CryptoTokenOfflineException(e.getMessage());
                oe.initCause(e);
                throw oe;
            }
            String msg = "Activated Crypto Token with ID " + getId() + ".";
            log.info(msg);
        } else {
            String msg = "Error activating Crypto Token with ID " + getId() + ". " + "No keystore data available yet, creating new PKCS#12 keystore.";
            log.info(msg);
            try {
                KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
                keystore.load(null, null);
                //keystore.load(null, authCode);
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
    
    /**
     * Throws an exception if the export of this crypto token should be denied.
     * 
     * @param authCode
     * @throws CryptoTokenAuthenticationFailedException if the authentication code is incorrect.
     * @throws CryptoTokenOfflineException if the crypto token is offline or an unknown error occurs.
     * @throws PrivateKeyNotExtractableException if the crypto tokens does not allow it's keys to be extracted.
     */
    public void checkPasswordBeforeExport(char[] authCode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, PrivateKeyNotExtractableException {
        if (!doPermitExtractablePrivateKey()) {
            final String msg = "Crypto Token " + getId() + " does not allow to extract private keys.";
            throw new PrivateKeyNotExtractableException(msg);
        }
        try {
            loadKeyStore(keystoreData, authCode);
        } catch (IOException e) {
            String msg = "Invalid authentication code for Crypto Token with ID " + getId() + ". " + e.getMessage();
            log.info(msg, e);
            CryptoTokenAuthenticationFailedException oe = new CryptoTokenAuthenticationFailedException(e.getMessage());
            oe.initCause(e);
            throw oe;
        } catch (Exception e) {
            String msg = "Error activating Crypto Token with ID " + getId() + ". " + e.getMessage();
            log.info(msg, e);
            CryptoTokenOfflineException oe = new CryptoTokenOfflineException(e.getMessage());
            oe.initCause(e);
            throw oe;
        }
    }

    private KeyStore loadKeyStore(final byte[] ksdata, final char[] keystorepass) throws NoSuchAlgorithmException, CertificateException, IOException,
            KeyStoreException, NoSuchProviderException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        if (log.isDebugEnabled()) {
        	log.debug("Loading keystore data of size: "+ (ksdata == null ? "null" : ksdata.length));
        }
        if (ksdata == null) {
            throw new IOException("Keystore data is null and can not be used for a Soft Crypto Token");
        }
        keystore.load(new ByteArrayInputStream(ksdata), keystorepass);
        return keystore;
    }

    @Override
    public void deactivate() {
        storeKeyStore();
        try {
            setKeyStore(null);
        } catch (KeyStoreException e) {
        	// Exception should only be thrown if loading a non-null KeyStore fails
            throw new IllegalStateException("This should never happen.");
        }
        String msg = "De-activated Crypto Token with ID " + getId() + ".";
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
            log.debug("Storing soft keystore of size " + (keystoreData == null ? "null" : keystoreData.length));
        }
    }

    @Override
    public byte[] getTokenData() {
        storeKeyStore();
        return keystoreData;
    }

    @Override
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            try {
                cont.deleteEntry(alias);
                String msg = "Deleted entry with alias '" + alias + "' from Crypto Token with ID " + getId() + ".";
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
    public void generateKeyPair(KeyGenParams keyGenParams, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        generateKeyPair(keyGenParams.getKeySpecification(), alias);
    }
    
    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException,
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
            // Soft crypto tokens must do very special things for secret keys, since PKCS#12 keystores are not designed to hold
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
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws InvalidAlgorithmParameterException, CertificateException,
    IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKeyPair(spec, alias);
            storeKeyStore();
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return true;
    }

    @Override
    public Set<Long> getKeyUsagesFromKey(String arg0, boolean arg1, long... arg2) throws CryptoTokenOfflineException {
        // Not implemented.
        return new TreeSet<Long>();
    }

    @Override
    public Set<Long> getKeyUsagesFromPrivateKey(String arg0) throws CryptoTokenOfflineException {
        // Not implemented.
        return new TreeSet<Long>();
    }

    @Override
    public Set<Long> getKeyUsagesFromPublicKey(String arg0) throws CryptoTokenOfflineException {
        // Not implemented.
        return new TreeSet<Long>();
    }
}
