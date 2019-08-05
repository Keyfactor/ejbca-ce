package org.cesecore.keys.token.p11ng.cryptotoken;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.KeyCreationException;
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
import org.cesecore.keys.util.ISignOperation;
import org.cesecore.keys.util.SignWithWorkingAlgorithm;
import org.cesecore.keys.util.TaskWithSigningException;
import org.cesecore.util.CertTools;

/**
 * 
 * @version $Id$
 *
 */
public class JackNJI11CryptoToken extends BaseCryptoToken implements P11SlotUser {

    private static final long serialVersionUID = 1L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(JackNJI11CryptoToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

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
            //            TODO add support
            //            this.slot = device.getSlot(Long.valueOf(slotLabelValue)); <---- SignServer way of doing it
            throw new UnsupportedOperationException("Slot by label not supported for this Crypto Tokne Type");
        } else if (slotLabelType == Pkcs11SlotLabelType.SLOT_INDEX) {
            // Removing 'i' e.g. from 'i0'
            final String slotIndex = sSlotLabel.substring(1, sSlotLabel.length());
            this.slot = device.getSlotByIndex(Integer.valueOf(slotIndex));
        } else {
            //          TODO Fix. Note: Throwing exception here will fail loading this class on deployment
            log.info("Unknown slot label reference type");
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
        log.info("State before login: " + this.slot);
        if (this.slot == null) {
            throw new CryptoTokenOfflineException("Slot not initialized.");
        }
        try {
            this.slot.login(String.valueOf(authenticationcode));
        } catch (Exception e) {
            log.warn("Failed to initialize PKCS11 provider slot '" + this.sSlotLabel + "'.", e);
            CryptoTokenAuthenticationFailedException authFailException = new CryptoTokenAuthenticationFailedException(
                    "Failed to initialize PKCS11 provider slot '" + this.sSlotLabel + "'.");
            authFailException.initCause(e);
            throw authFailException;
        }
        log.info("State after login: " + this.slot.toString());
    }

    @Override
    public void deactivate() {
        log.info("Deactivating CP5 token...");
        this.slot.logout();
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) throws CryptoTokenOfflineException {
        final PrivateKey privateKey = slot.aquirePrivateKey(alias);
        if (privateKey == null) {
            log.error("No key found for alias: " + alias);
            throw new CryptoTokenOfflineException("No private key with alias: " + alias);
        }
        return privateKey;
    }

    @Override
    public PublicKey getPublicKey(final String alias) throws CryptoTokenOfflineException {
        PublicKey publicKey = slot.getPublicKey(alias);
        if (publicKey == null) {
            publicKey = slot.getCertificate(alias).getPublicKey();

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
        boolean aliasInUse = false;
        try {
            getPublicKey(alias);
            aliasInUse = true;
        } catch (CryptoTokenOfflineException e) {
            try {
                getPrivateKey(alias);
                aliasInUse = true;
            } catch (CryptoTokenOfflineException e1) {
                if (slot.getSecretKey(alias) != null) {
                    aliasInUse = true;
                }
            }
        } catch (IllegalArgumentException e) {
            // NOOP no certificate references found. Alias not in use.
        }
        return aliasInUse;
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
    public List<String> getAliases() throws CryptoTokenOfflineException {
        final List<String> aliases = new ArrayList<>();
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
        log.info("Session Status: " + this.slot.toString());
        if (this.slot.getActiveSessions().size() == 0) {
            return CryptoToken.STATUS_OFFLINE;
        }
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

    // TODO Copied from KeyStoreTools. Should be able to unify
    private X509Certificate getSelfCertificate(String myname, long validity, List<String> sigAlgs, KeyPair keyPair) throws InvalidKeyException,
        CertificateException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        final X500Name issuer = new X500Name(myname);
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());
        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new InvalidKeyException("Public key is null");
        }

        try {
            final X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(issuer, serno, firstDate, lastDate, issuer, publicKey);
            final CertificateSignOperation cso = new CertificateSignOperation(keyPair.getPrivate(), cb);
            SignWithWorkingAlgorithm.doSignTask(sigAlgs, getSignProviderName(), cso);
            final X509CertificateHolder cert = cso.getResult();
            if ( cert==null ) {
                throw new CertificateException("Self signing of certificate failed.");
            }
            return CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
        } catch (TaskWithSigningException e) {
            log.error("Error creating content signer: ", e);
            throw new CertificateException(e);
        } catch (IOException e) {
            throw new CertificateException("Could not read certificate", e);
        } catch (NoSuchProviderException e) {
            throw new CertificateException(String.format("Provider '%s' does not exist.", getSignProviderName()), e);
        }
    }
    // TODO Copied from KeyStoreTools. Should be able to unify
    private class CertificateSignOperation implements ISignOperation {

        final private PrivateKey privateKey;
        final private X509v3CertificateBuilder certificateBuilder;
        private X509CertificateHolder result;

        public CertificateSignOperation(
                final PrivateKey pk,
                final X509v3CertificateBuilder cb) {
            this.privateKey = pk;
            this.certificateBuilder = cb;
        }
        @SuppressWarnings("synthetic-access")
        @Override
        public void taskWithSigning(String sigAlg, Provider provider) throws TaskWithSigningException {
            log.debug("Keystore signing algorithm " + sigAlg);
            final ContentSigner signer;
            try {
                signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider.getName()).build(this.privateKey), 20480);
            } catch (OperatorCreationException e) {
                throw new TaskWithSigningException(String.format("Signing certificate failed: %s", e.getMessage()), e);
            }
            this.result = this.certificateBuilder.build(signer);
        }
        public X509CertificateHolder getResult() {
            return this.result;
        }
    }
    
    
}
