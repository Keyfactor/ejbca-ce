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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.P11Slot;
import org.cesecore.keys.token.p11.P11SlotUser;
import org.cesecore.keys.token.p11.Pkcs11SlotLabel;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyStoreTools;

/**
 * Class implementing a keystore on PKCS11 tokens.
 * 
 * @version $Id$
 */
public class PKCS11CryptoToken extends BaseCryptoToken implements P11SlotUser {

    private static final long serialVersionUID = 7719014139640717867L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(PKCS11CryptoToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Keys, specific to PKCS#11, that can be defined in CA token properties */
    public static final String SLOT_LABEL_VALUE = "slotLabelValue";
    public static final String SLOT_LABEL_TYPE = "slotLabelType";
    public static final String SHLIB_LABEL_KEY = "sharedLibrary";
    public static final String ATTRIB_LABEL_KEY = "attributesFile";
    public static final String PASSWORD_LABEL_KEY = "pin";
    /** Flag that if set, prevent adding the P11 provider with Security.addProvider.
     * Can be used to create a crypto token without actually installing it in Java Security, so it
     * can be created temporarily */
    public static final String DO_NOT_ADD_P11_PROVIDER = "doNotAddP11Provider";
    
    @Deprecated //Remove once upgrading from 5.0->6.0 is no longer supported
    public static final String SLOT_LIST_INDEX_KEY = "slotListIndex";
    @Deprecated //Remove once upgrading from 5.0->6.0 is no longer supported
    public static final String SLOT_LABEL_KEY = "slot";

    
    /** A user defined name of the slot provider. Used in order to be able to have two different providers
     * (with different PKCS#11 attributes) for the same slot. If this is not set (null), the default
     * java provider name is used (SunPKCS11-pkcs11LibName-slotNr for example SunPKCS11-libcryptoki.so-slot1).
     */
    public final static String TOKEN_FRIENDLY_NAME = "tokenFriendlyName";
    
    private transient P11Slot p11slot;

    private String sSlotLabel = null;
    
    /**
     * @param providerClass
     * @throws InstantiationException
     */
    public PKCS11CryptoToken() throws InstantiationException {
        super();
        try {
            Thread.currentThread().getContextClassLoader().loadClass(Pkcs11SlotLabel.SUN_PKCS11_CLASS);
        } catch (ClassNotFoundException t) {
            throw new InstantiationException("PKCS11 provider class " + Pkcs11SlotLabel.SUN_PKCS11_CLASS + " not found.");
        }
    }

    @Override
    public void init(final Properties properties, final byte[] data, final int id) throws CryptoTokenOfflineException, NoSuchSlotException {
        if (log.isDebugEnabled()) {
            log.debug(">init: id=" + id);
        }
        // Don't autoactivate this right away, we must dynamically create the auth-provider with a slot
        setProperties(properties);
        init(properties, false, id);
        sSlotLabel = getSlotLabel(SLOT_LABEL_VALUE, properties);
        Pkcs11SlotLabelType type = Pkcs11SlotLabelType.getFromKey(getSlotLabel(SLOT_LABEL_TYPE, properties));
        String sharedLibrary = properties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY);
        String attributesFile = properties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY);
        Boolean addProvider = !BooleanUtils.toBoolean(properties.getProperty(PKCS11CryptoToken.DO_NOT_ADD_P11_PROVIDER));

        String friendlyName = properties.getProperty(TOKEN_FRIENDLY_NAME);

        if(friendlyName != null){
            p11slot = P11Slot.getInstance(friendlyName, sSlotLabel, sharedLibrary, type, attributesFile, this, id, addProvider);
        } else {
            // getInstance will run autoActivate()
            p11slot = P11Slot.getInstance(sSlotLabel, sharedLibrary, type, attributesFile, this, id, addProvider);
            
        }
        final Provider provider = p11slot.getProvider();
        if (addProvider) {
            setJCAProvider(provider);
        } else {
            setJCAProviderName(provider.getName());
            log.info("Configured to not add PKCS#11 Provider: "+provider.getName());
        }
        if (log.isDebugEnabled()) {
            log.debug("<init: id=" + id);
        }
    }

    @Override
    public boolean isActive() {
        return getTokenStatus() == CryptoToken.STATUS_ACTIVE;
    }

    @Override
    public void activate(final char[] authCode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        if (this.p11slot == null) {
            throw new CryptoTokenOfflineException("Slot not initialized.");
        }
        try {
            final KeyStore keyStore = createKeyStore(authCode);
            setKeyStore(keyStore);
        } catch (Throwable t) { // NOPMD: when dealing with HSMs we need to catch everything
            log.warn("Failed to initialize PKCS11 provider slot '" + this.sSlotLabel + "'.", t);
            CryptoTokenAuthenticationFailedException authfe = new CryptoTokenAuthenticationFailedException(
                    "Failed to initialize PKCS11 provider slot '" + this.sSlotLabel + "'.");
            authfe.initCause(t);
            throw authfe;
        }
        String msg = intres.getLocalizedMessage("token.activated", getId());
        log.info(msg);
    }

    private KeyStore createKeyStore(final char[] authCode) throws NoSuchAlgorithmException, CertificateException, UnsupportedEncodingException,
            IOException, KeyStoreException {
        final Provider provider = this.p11slot.getProvider();
        final KeyStore keyStore = KeyStore.getInstance( "PKCS11", provider );
        log.debug("Loading key from slot '" + this.sSlotLabel + "' using pin.");
        // See ECA-1395 for an explanation of this special handling for the IAIK provider.
        // If the application uses several instances of the IAIKPkcs11 provider, it has two options to get an initialized key store. First, it can get
        // the initialized key store directly from the provider instance. This looks like this
        // KeyStore tokenKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();
        // where pkcs11Provider_ is the instance of the IAIKPkcs11 provider. Second, the application can instantiate the key store as usual and then
        // initialize it. For initialization, the application must provide the name of the instance that this key store shall operate with. Just
        // instantiating the key store is not enough, and if the application calls tokenKeyStore.load(null, null), it always(!) binds the key store to
        // the first instance of the IAIKPkcs11 provider. This is the case, because there is no means for the KeyStoreSPI class to get the instance of
        // the provider that was used to instantiate it. This means, it does not help to provide the provider name and calling
        // KeyStore.getInstance("PKCS11KeyStore", providerName), the call to the load(InputStream, char[]) method with appropriate arguments is
        // required nevertheless. The correct usage will look like this
        // KeyStore cardKeyStore = KeyStore.getInstance("PKCS11KeyStore");
        // String providerName = pkcs11Provider_.getName();
        // ByteArrayInputStream providerNameInpustStream =
        // new ByteArrayInputStream(providerName.getBytes("UTF-8"));
        // cardKeyStore.load(providerNameInpustStream, null);
        // The password parameter of the load method (this is the second parameter, which is null here) will be used if provided (i.e. if it is not
        // null). If it is null, the default login manager will use the configured method for prompting the PIN on demand. If the application just
        // provides the instance number as a string instead of the complete provider name, the key store will also accept it.
        if (provider.getClass().getName().equals(Pkcs11SlotLabel.IAIK_PKCS11_CLASS)) {
            keyStore.load(new ByteArrayInputStream(getSignProviderName().getBytes("UTF-8")), authCode);
        } else {
            // For the Sun provider no provider name is used.
            keyStore.load(null, authCode);
        }
        return keyStore;
    }

    @Override
    public void deactivate() {
        try {
            setKeyStore(null);
        } catch (KeyStoreException e) {
            // Exception should only be thrown if loading a non-null KeyStore fails
            throw new IllegalStateException("This should never happen.");
        }
        if (this.p11slot != null) {
            this.p11slot.logoutFromSlotIfNoTokensActive();            
        } else {
            log.debug("p11slot was null, token was not active trying to deactivate.");
        }
        final String msg = intres.getLocalizedMessage("token.deactivate", getId());
        log.info(msg);
    }

    @Override
    public void reset() {
        if (this.p11slot != null) {
            this.p11slot.reset();
        }
    }

    @Override
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.deleteEntry(alias);
            String msg = intres.getLocalizedMessage("token.deleteentry", alias, getId());
            log.info(msg);
        } else {
            log.debug("Trying to delete keystore entry with empty alias.");
        }
    }

    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException,
            CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKeyPair(keySpec, alias);
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws 
            InvalidAlgorithmParameterException, CertificateException, IOException,
            CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKeyPair(spec, alias);
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("Generate key, "+algorithm+", "+keysize+", "+alias);
        }
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.generateKey(algorithm, keysize, alias);
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public byte[] getTokenData() {
        return null;
    }
    
    /** Used for testing */
    protected P11Slot getP11slot() {
        return p11slot;
    }
    
    /**
     * Extracts the slotLabel that is used for many tokens in construction of the provider
     *
     * @param sSlotLabelKey which key in the properties that gives us the label
     * @param properties CA token properties
     * @return String with the slot label, trimmed from whitespace
     */
    private static String getSlotLabel(String sSlotLabelKey, Properties properties) {
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
     * Will replace deprecated properties values with the new ones. 
     * 
     * @param properties a properties file of the old format.
     * @return a defensive copy of the submitted properties
     */
    @Deprecated
    //Remove when we no longer support upgrading from 5.0.x -> 6.0.x 
    public static Properties upgradePropertiesFileFrom5_0_x(final Properties properties) {
        Properties returnValue = new Properties();
        
        for (Object key : properties.keySet()) {
            final String keyString = (String) key;
            if (log.isDebugEnabled()) {
                log.debug(">upgradePropertiesFileFrom5_0_x, keyString: "+key);
            }
            if (keyString.equalsIgnoreCase(SLOT_LABEL_KEY)) {
                String keyValue = properties.getProperty(keyString);
                if (log.isDebugEnabled()) {
                    log.debug(">upgradePropertiesFileFrom5_0_x, keyValue: "+keyValue);
                }
                // In 5.0.11, the "slot" value may contain just an integer, but may also encode an integer, an index
                // a token label or a config file. 
                final String oldLabelPrefix = "TOKEN_LABEL:";
                final String oldIndexPrefix = "SLOT_LIST_IX:";
                final String oldSlotNumberPrefix = "SLOT_ID:";
                final String oldSunFilePrefix = "SUN_FILE:";
                final String delimiter = ":";
                if(Pkcs11SlotLabelType.SLOT_NUMBER.validate(keyValue)) {
                    //If it was a straight integer, then save as is
                    returnValue.setProperty(SLOT_LABEL_VALUE, keyValue);
                    returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_NUMBER.getKey());
                } else if(keyValue.startsWith(oldSlotNumberPrefix)) {
                   //If not, check with the rest of the values 
                    returnValue.setProperty(SLOT_LABEL_VALUE, keyValue.split(delimiter, 2)[1]);
                    returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_NUMBER.getKey());
                } else if(keyValue.startsWith(oldIndexPrefix)) {
                    returnValue.setProperty(SLOT_LABEL_VALUE, keyValue.split(delimiter, 2)[1]);
                    returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_INDEX.getKey());
                } else if(keyValue.startsWith(oldLabelPrefix)) {
                    returnValue.setProperty(SLOT_LABEL_VALUE, keyValue.split(delimiter, 2)[1]);
                    returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_LABEL.getKey());
                } else if(keyValue.startsWith(oldSunFilePrefix)) {
                    returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SUN_FILE.getKey());
                }
                
            } else if (keyString.equalsIgnoreCase(SLOT_LIST_INDEX_KEY)) {
                String indexValue = properties.getProperty(keyString);
                if (indexValue.charAt(0) != 'i') {
                    indexValue = "i" + indexValue;
                }
                if (log.isDebugEnabled()) {
                    log.debug(">upgradePropertiesFileFrom5_0_x, indexValue: "+indexValue);
                }
                returnValue.setProperty(SLOT_LABEL_VALUE, indexValue);
                returnValue.setProperty(SLOT_LABEL_TYPE, Pkcs11SlotLabelType.SLOT_INDEX.getKey());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(">upgradePropertiesFileFrom5_0_x, keyString is neither "+SLOT_LABEL_KEY+" or "+SLOT_LIST_INDEX_KEY+", just setting the property without SLOT_LABEL_TYPE.");
                }
                returnValue.setProperty(keyString, properties.getProperty(keyString));
            }
        }
        return returnValue;
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return doPermitExtractablePrivateKey();
    }
}
