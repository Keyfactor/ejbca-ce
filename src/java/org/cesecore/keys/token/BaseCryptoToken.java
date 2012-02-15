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
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.StringTools;

/**
 * Base class for crypto tokens handling things that are common for all crypto tokens, hard or soft.
 *
 * Based on EJBCA version: BaseCAToken.java 10358 2010-11-03 18:34:23Z mikekushner
 *
 * @version $Id$
 */
public abstract class BaseCryptoToken implements CryptoToken {

    private static final long serialVersionUID = 2133644669863292622L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(BaseCryptoToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Used for signatures */
    private String mJcaProviderName = null;
    /** Used for encrypt/decrypt, can be same as for signatures for example for pkcs#11 */
    private String mJceProviderName = null;

    protected String sSlotLabel = null;
    private char[] mAuthCode;

    private Properties properties;

    private int id;

    /** The java KeyStore backing the Crypto Token */
    protected transient KeyStore keyStore;

    /** Identifies if crypto token is allowed to create extractable private keys */
    protected boolean allowsExtractablePrivateKey = false;

    /** public constructor */
    public BaseCryptoToken() {
        super();
    }

    protected void setKeyStore(KeyStore keystore) {
        this.keyStore = keystore;
    }

    /**
     * Return the key store for this crypto token.
     *
     * @return the keystore.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected.
     */
    protected KeyStore getKeyStore() throws CryptoTokenOfflineException {
        autoActivate();
        if (this.keyStore == null) {
            throw new CryptoTokenOfflineException(mJcaProviderName);
        }
        return this.keyStore;
    }

    /**
     * TODO: This structure is confusing, with exceptions being thrown, caught, ignored and then rethrown at a later stage. Please fix.
     *
     */
    protected void autoActivate() {
        if ((this.mAuthCode != null) && (this.keyStore == null)) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to autoactivate CryptoToken");
                }
                activate(this.mAuthCode);
            } catch (Exception e) {
                log.debug(e);
            }
        }
    }

    /**
     * Do we permit extractable private keys? Only SW keys should be permitted to be extractable, an overriding crypto token class can override this
     * value.
     *
     * @return false if the key must not be extractable
     */
    public boolean doPermitExtractablePrivateKey() {
        return allowsExtractablePrivateKey;
    }

    @Override
    public void testKeyPair(PrivateKey privateKey, PublicKey publicKey) throws InvalidKeyException, NoSuchProviderException { // NOPMD:this is not a junit test
        if (log.isDebugEnabled()) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final PrintStream ps = new PrintStream(baos);
            KeyTools.printPublicKeyInfo(publicKey, ps);
            ps.flush();
            log.debug("Testing key of type " + baos.toString());
        }
        if (!doPermitExtractablePrivateKey() && KeyTools.isPrivateKeyExtractable(privateKey)) {
            String msg = intres.getLocalizedMessage("token.extractablekey", CesecoreConfiguration.isPermitExtractablePrivateKeys());
            if (!CesecoreConfiguration.isPermitExtractablePrivateKeys()) {
                throw new InvalidKeyException(msg);
            }
            log.info(msg);
        }
        KeyTools.testKey(privateKey, publicKey, getSignProviderName());
    }

    /**
     * Reads the public key object, does so from the certificate retrieved from the alias from the KeyStore.
     *
     * @param alias alias the key alias to retrieve from the token
     * @return the public key for the certificate represented by the given alias.
     * @throws KeyStoreException if the keystore has not been initialized.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected.
     */
    protected PublicKey readPublicKey(String alias) throws KeyStoreException, CryptoTokenOfflineException {
        Certificate cert = getKeyStore().getCertificate(alias);
        PublicKey pubk = null;
        if (cert != null) {
            pubk = cert.getPublicKey();
        } else {
            log.warn(intres.getLocalizedMessage("token.nopublic", alias));
            if (log.isDebugEnabled()) {
                Enumeration<String> en = getKeyStore().aliases();
                while (en.hasMoreElements()) {
                    log.debug("Existing alias: " + en.nextElement());
                }
            }
        }
        return pubk;
    }

    /**
     * Initiates the class members of this crypto token.
     *
     * @param sSlotLabelKey A String representation of the slot label key.
     * @param properties A Properties object containing properties for this token.
     * @param doAutoActivate Set true if activation of this crypto token should happen in this method.
     * @param id ID of this crypto token.
     */
    protected void init(String sSlotLabelKey, Properties properties, boolean doAutoActivate, int id) {
        if (log.isDebugEnabled()) {
            log.debug(">init: sSlotLabelKey=" + sSlotLabelKey + ", doAutoActivate=" + doAutoActivate);
        }
        this.id = id;
        // Set basic properties that are of dynamic nature
        setProperties(properties);
        // Set properties that can not change dynamically
        this.sSlotLabel = getSlotLabel(sSlotLabelKey, properties);
        if (doAutoActivate) {
            autoActivate();
        }
        if (log.isDebugEnabled()) {
            log.debug("<init: sSlotLabelKey=" + sSlotLabelKey + ", doAutoActivate=" + doAutoActivate);
        }
    }

    @Override
    public int getId() {
        return this.id;
    }

    public void setId(final int id) {
        this.id = id;
    }

    @Override
    public Properties getProperties() {
        return properties;
    }

    @Override
    public void setProperties(Properties properties) {
        if (properties == null) {
            this.properties = new Properties();
        } else {
            if (log.isDebugEnabled()) {
                // This is only a sections for debug logging. If we have enabled debug logging we don't want to display any password in the log.
                // These properties may contain autoactivation PIN codes and we will, only when debug logging, replace this with "hidden".
                if (properties.containsKey(CryptoToken.AUTOACTIVATE_PIN_PROPERTY) || properties.containsKey("PIN")) {
                    Properties prop = new Properties();
                    prop.putAll(properties);
                    if (properties.containsKey(CryptoToken.AUTOACTIVATE_PIN_PROPERTY)) {
                        prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "hidden");
                    }
                    if (properties.containsKey("PIN")) {
                        prop.setProperty("PIN", "hidden");
                    }
                    log.debug("Prop: " + (prop != null ? prop.toString() : "null"));
                } else {
                    // If no autoactivation PIN codes exists we can debug log everything as original.
                    log.debug("Properties: " + (properties != null ? properties.toString() : "null"));
                }
            } // if (log.isDebugEnabled())
            this.properties = properties;
            String authCode = BaseCryptoToken.getAutoActivatePin(properties);
            this.mAuthCode = authCode == null ? null : authCode.toCharArray();

            // check properties if ti should allow to extract private keys
            if (properties.containsKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY)) {
                this.allowsExtractablePrivateKey = Boolean.parseBoolean(properties.getProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY));
            }
        }
    } // updateProperties

    /**
     * Extracts the slotLabel that is used for many tokens in construction of the provider
     *
     * @param sSlotLabelKey which key in the properties that gives us the label
     * @param properties CA token properties
     * @return String with the slot label, trimmed from whitespace
     */
    protected static String getSlotLabel(String sSlotLabelKey, Properties properties) {
        String ret = null;
        if (sSlotLabelKey != null && properties != null) {
            ret = properties.getProperty(sSlotLabelKey);
            if (ret != null) {
                ret = ret.trim();
            }
        }
        return ret;
    }

    /**
     * Retrieves the auto activation PIN code, if it has been set for this crypto token. With an auto activation PIN the token does not have to be
     * manually activated.
     *
     * @param properties the crypto token properties that may contain auto activation PIN code
     * @return String or null
     */
    public static String getAutoActivatePin(Properties properties) {
        final String pin = properties.getProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
        if (pin != null) {
            return StringTools.passwordDecryption(pin, "autoactivation pin");
        }
        if (log.isDebugEnabled()) {
            log.debug("Not using autoactivation pin");
        }
        return null;
    }

    /**
     * Sets auto activation pin in passed in properties. Also returns the string format of the autoactivation properties: pin mypassword
     *
     * @param properties a Properties bag where to set the auto activation pin, can be null if you only want to create the return string, does not set
     *            a null or empty password
     * @param pin the activation password
     * @param encrypt if the PIN should be encrypted with a simple built in encryption with only purpose of hiding the password from simple viewing.
     *            No strong security from this encryption
     * @return A string that can be used to "setProperties" of a CryptoToken or null if pin is null or an empty string, this can safely be ignored if
     *         you don't know what to do with it
     */
    public static String setAutoActivatePin(Properties properties, String pin, boolean encrypt) {
        String ret = null;
        if (StringUtils.isNotEmpty(pin)) {
            String authcode = pin;
            if (encrypt) {
                try {
                    authcode = StringTools.pbeEncryptStringWithSha256Aes192(pin);
                } catch (Exception e) {
                    log.error(intres.getLocalizedMessage("token.nopinencrypt"), e);
                    authcode = pin;
                }
            }
            if (properties != null) {
                properties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, authcode);
            }
            ret = CryptoToken.AUTOACTIVATE_PIN_PROPERTY + " " + authcode;
        }
        return ret;
    }

    /**
     * Sets both signature and encryption providers. If encryption provider is the same as signature provider this class name can be null.
     *
     * @param jcaProviderClassName signature provider class name
     * @param jceProviderClassName encryption provider class name, can be null
     * @throws ClassNotFoundException if the class specified by jcaProviderClassName could not be found.
     * @throws IllegalAccessException if the default constructor for the class specified by jcaProviderClassName was not public
     * @throws InstantiationException if the class specified by jcaProviderClassName was an abstract class, an interface, an array class, a primitive
     *             type, or void; or if it has no nullary constructor; or if the instantiation fails for some other reason.
     * @see {@link #setJCAProvider(Provider)}
     */
    protected void setProviders(String jcaProviderClassName, String jceProviderClassName) throws InstantiationException, IllegalAccessException,
            ClassNotFoundException {
        Provider jcaProvider = (Provider) Class.forName(jcaProviderClassName).newInstance();
        setProvider(jcaProvider);
        this.mJcaProviderName = jcaProvider.getName();
        if (jceProviderClassName != null) {
            try {
                Provider jceProvider = (Provider) Class.forName(jceProviderClassName).newInstance();
                setProvider(jceProvider);
                this.mJceProviderName = jceProvider.getName();
            } catch (Exception e) {
                log.error(intres.getLocalizedMessage("token.jceinitfail"), e);
            }
        } else {
            this.mJceProviderName = null;
        }
    }

    /**
     * If we only have one provider to handle both JCA and JCE, and perhaps it is not so straightforward to create the provider (for example PKCS#11
     * provider), we can create the provider in sub class and set it here, instead of calling setProviders.
     *
     * @param prov the fully constructed Provider
     * @see #setProviders(String, String)
     */
    protected void setJCAProvider(Provider prov) {
        setProvider(prov);
        this.mJcaProviderName = prov != null ? prov.getName() : null;
    }

    /**
     * If we don't use any of the methods to set a specific provider, but use some already existing provider we should set the name of that provider
     * at least.
     *
     * @param pName the provider name as retriever from Provider.getName()
     */
    protected void setJCAProviderName(String pName) {
        this.mJcaProviderName = pName;
    }

    private void setProvider(Provider prov) {
        if (prov != null) {
            String pName = prov.getName();
            if (pName.startsWith("LunaJCA")) {
                // Luna Java provider does not contain support for RSA/ECB/PKCS1Padding but this is
                // the same as the alias below on small amounts of data
                prov.put("Alg.Alias.Cipher.RSA/NONE/NoPadding", "RSA//NoPadding");
                prov.put("Alg.Alias.Cipher.1.2.840.113549.1.1.1", "RSA//NoPadding");
                prov.put("Alg.Alias.Cipher.RSA/ECB/PKCS1Padding", "RSA//PKCS1v1_5");
                prov.put("Alg.Alias.Cipher.1.2.840.113549.3.7", "DES3/CBC/PKCS5Padding");
            }
            if (Security.getProvider(pName) == null) {
                Security.addProvider(prov);
            }
            if (Security.getProvider(pName) == null) {
                throw new ProviderException("Not possible to install provider: " + pName);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No provider passed to setProvider()");
            }
        }
    }

    @Override
    public String getSignProviderName() {
        return this.mJcaProviderName;
    }

    @Override
    public String getEncProviderName() {
        // If we don't have a specific JCE provider, it is most likely the same
        // as the JCA provider
        if (this.mJceProviderName == null) {
            return this.mJcaProviderName;
        }
        return this.mJceProviderName;
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) throws CryptoTokenOfflineException {
        autoActivate();
        try {
            final PrivateKey privateK = (PrivateKey) getKeyStore().getKey(alias, (mAuthCode != null && mAuthCode.length > 0) ? mAuthCode : null);
            if (privateK == null) {
                log.warn(intres.getLocalizedMessage("token.noprivate", alias));
                if (log.isDebugEnabled()) {
                    final Enumeration<String> aliases;
                    aliases = getKeyStore().aliases();
                    while (aliases.hasMoreElements()) {
                        log.debug("Existing alias: " + aliases.nextElement());
                    }
                }
                final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
                throw new CryptoTokenOfflineException(msg);
            }
            return privateK;
        } catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException(e);
        } catch (UnrecoverableKeyException e) {
            throw new CryptoTokenOfflineException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }

    @Override
    public PublicKey getPublicKey(final String alias) throws CryptoTokenOfflineException {
        autoActivate();
        try {
            PublicKey publicK = readPublicKey(alias);
            if (publicK == null) {
                final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
                throw new CryptoTokenOfflineException(msg);
            }
            return publicK;
        } catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }

    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        autoActivate();
        try {
            Key key = getKeyStore().getKey(alias, (mAuthCode != null && mAuthCode.length > 0) ? mAuthCode : null);
            if (key == null) {
                // Do we have it stored as a soft key in properties?
                key = getKeyFromProperties(alias);
                if (key == null) {
                    log.warn(intres.getLocalizedMessage("token.errornosuchkey", alias));
                    if (log.isDebugEnabled()) {
                        Enumeration<String> aliases;
                        aliases = getKeyStore().aliases();
                        while (aliases.hasMoreElements()) {
                            log.debug("Existing alias: " + aliases.nextElement());
                        }
                    }
                    final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
                    throw new CryptoTokenOfflineException(msg);
                }
            }
            return key;
        } catch (KeyStoreException e) {
            throw new CryptoTokenOfflineException(e);
        } catch (UnrecoverableKeyException e) {
            throw new CryptoTokenOfflineException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoTokenOfflineException(e);
        }
    }

    private Key getKeyFromProperties(String alias) {
        Key key = null;
        Properties prop = getProperties();
        String str = prop.getProperty(alias);
        if (StringUtils.isNotEmpty(str)) {
            // TODO: unwrapping with rsa key is also needed later on
            try {
                PrivateKey privK = getPrivateKey("symwrap");
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", getEncProviderName());
                cipher.init(Cipher.UNWRAP_MODE, privK);
                byte[] bytes = Hex.decode(str);
                // TODO: hardcoded AES for now
                key = cipher.unwrap(bytes, "AES", Cipher.SECRET_KEY);
            } catch (CryptoTokenOfflineException e) {
                log.debug(e);
            } catch (NoSuchAlgorithmException e) {
                log.debug(e);
            } catch (NoSuchProviderException e) {
                log.debug(e);
            } catch (NoSuchPaddingException e) {
                log.debug(e);
            } catch (InvalidKeyException e) {
                log.debug(e);
            }
        }
        return key;
    }

    @Override
    public void reset() {
        // do nothing. the implementing class decides whether something could be done to get the HSM working after a failure.
    }

    @Override
    public int getTokenStatus() {
        autoActivate();
        int ret = CryptoToken.STATUS_OFFLINE;
        try {
            getKeyStore();
            ret = CryptoToken.STATUS_ACTIVE;
        } catch (CryptoTokenOfflineException e) {
            // NOPMD, ignore status is offline
        }
        return ret;
    }

    /**
     * This method extracts a PrivateKey from the keystore and wraps it, using a symmetric encryption key
     *
     * @param privKeyTransform - transformation algorithm
     * @param encryptionKeyAlias - alias of the symmetric key that will encrypt the private key
     * @param privateKeyAlias - alias for the PrivateKey to be extracted
     * @return byte[] with the encrypted extracted key
     * @throws NoSuchAlgorithmException if privKeyTransform is null, empty, in an invalid format, or if no Provider supports a CipherSpi
     *             implementation for the specified algorithm.
     * @throws NoSuchPaddingException if privKeyTransform contains a padding scheme that is not available.
     * @throws NoSuchProviderException if BouncyCastle is not registered in the security provider list.
     * @throws InvalidKeyException if the encryption key derived from encryptionKeyAlias was invalid.
     * @throws IllegalBlockSizeException if the Cipher created using privKeyTransform is a block cipher, no padding has been requested, and the length
     *             of the encoding of the key to be wrapped is not a multiple of the block size.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws InvalidAlgorithmParameterException if using CBC mode and the IV 0x0000000000000000 is not accepted.
     */
    public byte[] extractKey(String privKeyTransform, String encryptionKeyAlias, String privateKeyAlias) throws NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, CryptoTokenOfflineException,
            PrivateKeyNotExtractableException, InvalidAlgorithmParameterException {
        IvParameterSpec ivParam = null;
        if (privKeyTransform.matches( ".+\\/CBC\\/.+" )){
            byte[] cbcIv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            ivParam = new IvParameterSpec(cbcIv);
        }
        return extractKey(privKeyTransform, ivParam, encryptionKeyAlias, privateKeyAlias);
    }

    /**
     * This method extracts a PrivateKey from the keystore and wraps it, using a symmetric encryption key
     *
     * @param privKeyTransform - transformation algorithm
     * @param spec - transformation algorithm spec (e.g: IvParameterSpec for CBC mode)
     * @param encryptionKeyAlias - alias of the symmetric key that will encrypt the private key
     * @param privateKeyAlias - alias for the PrivateKey to be extracted
     * @return byte[] with the encrypted extracted key
     * @throws NoSuchAlgorithmException if privKeyTransform is null, empty, in an invalid format, or if no Provider supports a CipherSpi
     *             implementation for the specified algorithm.
     * @throws NoSuchPaddingException if privKeyTransform contains a padding scheme that is not available.
     * @throws NoSuchProviderException if BouncyCastle is not registered in the security provider list.
     * @throws InvalidKeyException if the encryption key derived from encryptionKeyAlias was invalid.
     * @throws IllegalBlockSizeException if the Cipher created using privKeyTransform is a block cipher, no padding has been requested, and the length
     *             of the encoding of the key to be wrapped is not a multiple of the block size.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws InvalidAlgorithmParameterException if spec id not valid or supported.
     * @throws PrivateKeyNotExtractableException if the key is not extractable, does not exist or encryption fails
     */
    public byte[] extractKey(String privKeyTransform, AlgorithmParameterSpec spec, String encryptionKeyAlias, String privateKeyAlias) throws NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, CryptoTokenOfflineException,
            PrivateKeyNotExtractableException, InvalidAlgorithmParameterException {

        if (doPermitExtractablePrivateKey()) {
            // get encryption key
            Key encryptionKey = getKey(encryptionKeyAlias);
            // get private key to wrap
            PrivateKey privateKey = getPrivateKey(privateKeyAlias);
            if (privateKey == null) {
            	throw new PrivateKeyNotExtractableException("Extracting key with alias '"+privateKeyAlias+"' return null.");
            }

            // since SUN PKCS11 Provider does not implements WRAP_MODE,
            // ENCRYPT_MODE with encoded private key will be used instead, giving the same result
            Cipher c = null;
            c = Cipher.getInstance(privKeyTransform, getEncProviderName());
            if (spec == null){
                c.init(Cipher.ENCRYPT_MODE, encryptionKey);
            } else {
              c.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
            }

            // wrap key
            byte[] encryptedKey;
            try {
                byte[] data = privateKey.getEncoded();
                if (StringUtils.containsIgnoreCase(privKeyTransform, "NoPadding")) {
                    // We must add PKCS7/PKCS5 padding ourselves to the data
                    final PKCS7Padding padding = new PKCS7Padding();
                    // Calculate the number of pad bytes needed
                    final int rem = data.length % c.getBlockSize();
                    final int padlen = c.getBlockSize()-rem;
                    if (log.isDebugEnabled()) {
                        log.debug("Padding key data with "+padlen+" bytes, using PKCS7/5Padding. Total len: "+(data.length+padlen));
                    }
                    byte[] newdata = Arrays.copyOf(data, data.length+padlen);
                    padding.addPadding(newdata, data.length);
                    data = newdata;
                }
                encryptedKey = c.doFinal(data);
            } catch (BadPaddingException e) {
                throw new PrivateKeyNotExtractableException("Extracting key with alias '"+privateKeyAlias+"' failed.");
            }

            return encryptedKey;
        } else {
            final String msg = intres.getLocalizedMessage("token.errornotextractable", privateKeyAlias, encryptionKeyAlias);
            throw new PrivateKeyNotExtractableException(msg);
        }
    }

    @Override
    public Enumeration<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        return getKeyStore().aliases();
    }

}
