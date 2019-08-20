package org.cesecore.keys.token.p11ng.cryptotoken;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.P11SlotUser;
import org.cesecore.keys.token.p11.Pkcs11SlotLabel;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.SlotEntry;

/**
 * 
 * @version $Id$
 */
public class JackNJI11CryptoToken extends BaseCryptoToken implements P11SlotUser {

    private static final long serialVersionUID = 1L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(JackNJI11CryptoToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static final int KAK_SIZE = 2048;
    
    public static final String SLOT_LABEL_VALUE = "slotLabelValue";
    public static final String SLOT_LABEL_TYPE = "slotLabelType";
    public static final String SHLIB_LABEL_KEY = "sharedLibrary";
    public static final String ATTRIB_LABEL_KEY = "attributesFile";
    public static final String PASSWORD_LABEL_KEY = "pin";

    protected CryptokiDevice.Slot slot;

    private String sSlotLabel = null;

    public JackNJI11CryptoToken() throws InstantiationException {
        super();
        try {
            Thread.currentThread().getContextClassLoader().loadClass(Pkcs11SlotLabel.JACKJNI_CLASS);
        } catch (ClassNotFoundException t) {
            throw new InstantiationException("PKCS11 provider class " + Pkcs11SlotLabel.JACKJNI_CLASS + " not found.");
        }
    }

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug(">init: id=" + id);
        }
        // Don't auto activate this right away, we must dynamically create the auth-provider with a slot
        setProperties(properties);
        init(properties, false, id);
        sSlotLabel = getSlotLabel(SLOT_LABEL_VALUE, properties);
        Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(getSlotLabel(SLOT_LABEL_TYPE, properties));
        String sharedLibrary = properties.getProperty(SHLIB_LABEL_KEY);
        String attributesFile = properties.getProperty(ATTRIB_LABEL_KEY);

        //        TODO Not sure if needed here...
        //        Boolean addProvider = !BooleanUtils.toBoolean(properties.getProperty(PKCS11CryptoToken.DO_NOT_ADD_P11_PROVIDER));
        //        String friendlyName = properties.getProperty(TOKEN_FRIENDLY_NAME);

        //        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFile.getName(), libDir); <-----------SignServer way of doing it
        String libraryFileDir = sharedLibrary.substring(0, sharedLibrary.lastIndexOf("/") + 1);
        String libraryFileName = sharedLibrary.substring(sharedLibrary.lastIndexOf("/") + 1, sharedLibrary.length());

        // TODO used during development remove when done
        log.info("sSlotLabel: " + sSlotLabel);
        log.info("sharedLibrary: " + sharedLibrary);
        log.info("attributesFile: " + attributesFile);
        log.info("libraryFileDir: " + libraryFileDir);
        log.info("libraryFileName: " + libraryFileName);

        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFileName, libraryFileDir);
        device.getSlots();
        if (slotLabelType == Pkcs11SlotLabelType.SLOT_NUMBER) {
            slot = device.getSlot(Long.valueOf(sSlotLabel));
        } else if (slotLabelType == Pkcs11SlotLabelType.SLOT_INDEX) {
            // Removing 'i' e.g. from 'i0'
            final String slotIndex = sSlotLabel.substring(1, sSlotLabel.length());
            slot = device.getSlotByIndex(Integer.valueOf(slotIndex));
        } else {
            slot = device.getSlotByLabel(sSlotLabel);
        }
        
        if (slot == null) {
            throw new NoSuchSlotException("Unable to obtain token in slot");
        }
        //        TODO Seems to be done automatically at crypto token creation in EJBCA
        //        String authCode = props.getProperty("pin");
        //        if (authCode != null) {
        //            try {
        //                slot.login(authCode);
        //            } catch (Exception e) {
        //                log.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(), e);
        //            }
        //        }
        setJCAProvider(slot.getProvider());

    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        log.info("Activating CP5 token...");
        log.info("State before login: " + slot);
        if (slot == null) {
            throw new CryptoTokenOfflineException("Slot not initialized.");
        }
        try {
            slot.prepareLogin();
        } catch (Exception e) {
            final String msg = "Failed to initialize PKCS#11 provider slot '" + sSlotLabel + "'.";
            log.warn(msg, e);
            throw new CryptoTokenOfflineException(msg, e);
        }
        try {
            slot.login(String.valueOf(authenticationcode));
        } catch (Exception e) {
            final String msg = "Failed to login to PKCS#11 provider slot '" + sSlotLabel + "'.";
            log.warn(msg, e);
            CryptoTokenAuthenticationFailedException authFailException = new CryptoTokenAuthenticationFailedException(msg);
            authFailException.initCause(e);
            throw authFailException;
        }
        log.info("State after login: " + slot.toString());
    }

    @Override
    public void deactivate() {
        log.info("Deactivating CP5 token...");
        this.slot.logout();
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) throws CryptoTokenOfflineException {
        final PrivateKey privateKey = slot.getReleasableSessionPrivateKey(alias);
        if (privateKey == null) {
            log.error("No key found for alias: " + alias);
            throw new CryptoTokenOfflineException("No private key with alias: " + alias);
        }
        return privateKey;
    }

    @Override
    public boolean doesPrivateKeyExist(final String alias) {
        try {
            final PrivateKey privateKey = slot.aquirePrivateKey(alias);
            if (privateKey != null) {
                slot.releasePrivateKey(privateKey);
                return true;
            }
            return false;
        } catch (CryptoTokenOfflineException e) {
            return false;
        }
    }

    @Override
    public PublicKey getPublicKey(final String alias) throws CryptoTokenOfflineException {
        PublicKey publicKey = slot.getPublicKey(alias);
        if (publicKey == null) {
            final Certificate certificate = slot.getCertificate(alias);
            if (certificate == null) {
                final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
                throw new CryptoTokenOfflineException(msg);
            }
            publicKey = certificate.getPublicKey();
        }
        return publicKey;
    }

    @Override
    public boolean isAliasUsed(final String alias) {
        return slot.isAliasUsed(alias);
    }
    
    @Override
    public void deleteEntry(String alias)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {
        if (StringUtils.isNotEmpty(alias)) {
            slot.removeKey(alias);
        } else {
            log.debug("Trying to delete keystore entry with empty alias.");
        }

    }

    @Override
    public void testKeyPair(final String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        final PublicKey publicKey = getPublicKey(alias);
        final PrivateKey privateKey = slot.aquirePrivateKey(alias);
        try {
            testKeyPair(alias, publicKey, privateKey);
        } finally {
            slot.releasePrivateKey(privateKey);
        }
    }
    
    @Override
    public void generateKeyPair(String keySpec, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        log.info("Generating Key Pair...");
        final Map<Long, Object> publicAttributesMap = new HashMap<>();
        final Map<Long, Object> privateAttributesMap = new HashMap<>();
        try {
            slot.generateKeyPair("RSA", "2048", alias, true, publicAttributesMap, privateAttributesMap, null, false);
            log.debug("Successfully generated key pair");
        } catch (CertificateException | OperatorCreationException ex) {
            log.error("Dummy certificate generation failed. Objects might still have been created in the device: ", ex);
            System.err.println("Dummy certificate generation failed. Objects might still have been created in the device: " + ex.getMessage());
        }
    }
    
    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
            throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException {
        log.info("Generating Key Pair (existing public key)");
        // TODO Auto-generated method stub

    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException,
            IOException, NoSuchPaddingException, IllegalBlockSizeException {
        log.info("Generating Key...");
        // TODO Auto-generated method stub

    }

    @Override
    public void keyAuthorizeInit(String alias, KeyPair kakPair, String signProviderName) {
        log.info("Key Authorize Init..."); //TODO remove
        slot.keyAuthorizeInit(alias, kakPair, signProviderName);
    }
    
    @Override
    public void keyAuthorize(String alias, KeyPair kakPair, String signProviderName, long maxOperationCount) {
        log.info("Key Authorize...");
        slot.keyAuthorize(alias, kakPair, maxOperationCount, signProviderName);
    }
    
    @Override
    public boolean isKeyInitialized(final String alias) {
        return slot.isKeyAuthorized(alias);
    }
    
    @Override
    public long maxOperationCount(final String alias) {
        return slot.maxOperationCount(alias);
    }
    
    @Override
    public List<String> getAliases() throws CryptoTokenOfflineException {
        final List<String> aliases = new ArrayList<>();
        if (slot == null) { // Happens if we try to list aliases while the CryptoToken is offline
            return aliases;
        }
        final Enumeration<SlotEntry> e = slot.aliases();
        while (e.hasMoreElements()) {
            final SlotEntry slotEntry = e.nextElement();
            aliases.add(slotEntry.getAlias());
        }
        return aliases;
        //        return Collections.list(getKeyStore().aliases()); <---- Traditional way of doing it. TODO Remove this line.
    }

    @Override
    public byte[] getTokenData() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isActive() {
        return getTokenStatus() == CryptoToken.STATUS_ACTIVE;
    }

    @Override
    public int getTokenStatus() {
        // TODO temporary solution. Works to detect if not logged in and allow doing so (in GUI). 
        // However we can not take token "offline" this way
        if (this.slot == null || this.slot.getActiveSessions().size() == 0) {
            return CryptoToken.STATUS_OFFLINE;
        }
        log.info("Session Status: " + this.slot.toString());
        return CryptoToken.STATUS_ACTIVE;
// SignServer way of doing it >        
//        int ret = CryptoToken.STATUS_OFFLINE;
//        try {
//            for (String testKey : new String[]{keyAlias, nextKeyAlias}) {
//                if (testKey != null && !testKey.isEmpty()) {
//                    PrivateKey privateKey = null;
//                    try {
//                        privateKey = slot.aquirePrivateKey(testKey);
//                        if (privateKey != null) {
//                            PublicKey publicKey = slot.getPublicKey(testKey);
//                            if (publicKey == null) {
//                                publicKey = slot.getCertificate(testKey).getPublicKey();
//                            }
//                            CryptoTokenHelper.testSignAndVerify(privateKey, publicKey, slot.getProvider().getName(), signatureAlgorithm);
//                            ret = CryptoToken.STATUS_ACTIVE;
//                        }
//                    } finally {
//                        if (privateKey != null) {
//                            slot.releasePrivateKey(privateKey);
//                        }
//                    }
//                }
//            }
//        } catch (Throwable th) {
//            log.error("Error getting token status", th);
//            ret = CryptoToken.STATUS_OFFLINE;
//        }
//        return ret;
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
    
}
