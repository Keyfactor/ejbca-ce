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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SignatureException;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.security.auth.DestroyFailedException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.P11Slot;
import org.cesecore.keys.token.p11.P11SlotUser;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.keys.util.KeyTools;

/**
 * Class implementing a keystore on PKCS11 tokens.
 * 
 * Based on EJBCA version: 
 *      PKCS11CAToken.java 9024 2010-05-06 14:09:14Z anatom $
 * CESeCore version:
 *      PKCS11CryptoToken.java 933 2011-07-07 18:53:11Z mikek
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
    public final static String SLOT_LABEL_KEY = "slot";
    public final static String SHLIB_LABEL_KEY = "sharedLibrary";
    public final static String ATTRIB_LABEL_KEY = "attributesFile";
    public final static String SLOT_LIST_INDEX_LABEL_KEY = "slotListIndex";
    public final static String PASSWORD_LABEL_KEY = "pin";

    private P11Slot p11slot;

    /**
     * @param providerClass
     * @throws InstantiationException
     */
    public PKCS11CryptoToken() throws InstantiationException {
        super();
        try {
            Thread.currentThread().getContextClassLoader().loadClass(KeyTools.SUNPKCS11CLASS);
        } catch (Throwable t) {
            throw new InstantiationException("Pkcs11 provider class " + KeyTools.SUNPKCS11CLASS + " not found.");
        }
    }

    @Override
    public void init(final Properties properties, final byte[] data, final int id) throws CryptoTokenOfflineException {
        // Don't autoactivate this right away, we must dynamically create the auth-provider with a slot
        setProperties(properties);
        init("slot", properties, false, id);
        final boolean isIndex;
        if (this.sSlotLabel == null) {
            this.sSlotLabel = properties.getProperty(SLOT_LIST_INDEX_LABEL_KEY);
            this.sSlotLabel = this.sSlotLabel != null ? this.sSlotLabel.trim() : "-1";
            isIndex = this.sSlotLabel != null;
        } else {
            isIndex = false;
        }
        String sharedLibrary = properties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY);
        String attributesFile = properties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY);
        // getInstance will run autoActivate()
        this.p11slot = P11Slot.getInstance(this.sSlotLabel, sharedLibrary, isIndex, attributesFile, this, id);
        final Provider provider = this.p11slot.getProvider();
        setJCAProvider(provider);
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
            KeyStore keyStore = createKeyStore(authCode);
            setKeyStore(keyStore);
        } catch (Throwable t) {
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
        final PasswordProtection pwp = new PasswordProtection(authCode);
        Provider provider = this.p11slot.getProvider();
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, pwp);
        final KeyStore keyStore = builder.getKeyStore();
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
        if (provider.getClass().getName().equals(KeyTools.IAIKPKCS11CLASS)) {
            keyStore.load(new ByteArrayInputStream(getSignProviderName().getBytes("UTF-8")), authCode);
        } else {
            // For the Sun provider this works fine to initialize the provider using previously provided protection parameters.
            keyStore.load(null, null);
        }
        try {
            pwp.destroy();
        } catch (DestroyFailedException e) {
            // Log but otherwise ignore
            log.info("Detroy failed: ", e);
        }
        return keyStore;
    }

    @Override
    public void deactivate() {
        setKeyStore(null);
        this.p11slot.logoutFromSlotIfNoTokensActive();
        String msg = intres.getLocalizedMessage("token.deactivate", getId());
        log.info(msg);
    }

    @Override
    public void reset() {
        if (this.p11slot != null) {
            this.p11slot.reset();
        }
    }

    @Override
    public void deleteEntry(final char[] authenticationCode, final String alias) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            KeyStoreTools cont = new KeyStoreTools(getKeyStore(), getSignProviderName());
            cont.deleteEntry(alias);
            String msg = intres.getLocalizedMessage("token.deleteentry", getId(), alias);
            log.info(msg);
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
        } else {
            log.debug("Trying to generate keys with empty alias.");
        }
    }

    @Override
    public void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, CryptoTokenOfflineException {
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

}
