/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.token.p11ng.cryptotoken;

import java.io.IOException;
import java.nio.file.Path;
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
import java.util.List;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyGenParams;
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
public class Pkcs11NgCryptoToken extends BaseCryptoToken implements P11SlotUser {

    private static final long serialVersionUID = 1L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(Pkcs11NgCryptoToken.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Keys, specific to PKCS#11, that can be defined in CA token properties */
    public static final String SLOT_LABEL_VALUE = "slotLabelValue";
    public static final String SLOT_LABEL_TYPE = "slotLabelType";
    public static final String SHLIB_LABEL_KEY = "sharedLibrary";
    public static final String ATTRIB_LABEL_KEY = "attributesFile";
    public static final String PASSWORD_LABEL_KEY = "pin";

    protected CryptokiDevice.Slot slot;

    private String sSlotLabel = null;

    public Pkcs11NgCryptoToken() throws InstantiationException {
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

        //        Boolean addProvider = !BooleanUtils.toBoolean(properties.getProperty(PKCS11CryptoToken.DO_NOT_ADD_P11_PROVIDER));
        //        String friendlyName = properties.getProperty(TOKEN_FRIENDLY_NAME);

        String libraryFileDir = sharedLibrary.substring(0, sharedLibrary.lastIndexOf("/") + 1);
        String libraryFileName = sharedLibrary.substring(sharedLibrary.lastIndexOf("/") + 1, sharedLibrary.length());

        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFileName, libraryFileDir);
        device.getSlots();
        if (slotLabelType == Pkcs11SlotLabelType.SLOT_NUMBER) {
            slot = device.getSlot(Long.valueOf(sSlotLabel));
        } else if (slotLabelType == Pkcs11SlotLabelType.SLOT_INDEX) {
            // Removing 'i' e.g. from 'i0'
            final String slotIndex = sSlotLabel.substring(1);
            slot = device.getSlotByIndex(Integer.valueOf(slotIndex));
        } else {
            slot = device.getSlotByLabel(sSlotLabel);
        }
        
        if (slot == null) {
            throw new NoSuchSlotException("Unable to obtain token in slot");
        }

        String autoActivatePin = BaseCryptoToken.getAutoActivatePin(properties);
        try {
            if (autoActivatePin != null) {
                activate(autoActivatePin.toCharArray());
            }
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw new CryptoTokenOfflineException(e);
        }
        
        setJCAProvider(slot.getProvider());
        slot.setUseCache(true);
    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        if (slot == null) {
            throw new CryptoTokenOfflineException("Slot not initialized.");
        }
        try {
            slot.prepareLogin();
        } catch (Exception e) {
            final String msg = "Failed to initialize PKCS#11 provider slot '" + sSlotLabel + "': "  + e.getMessage();
            log.warn(msg, e);
            throw new CryptoTokenOfflineException(msg, e);
        }
        try {
            slot.login(String.valueOf(authenticationcode));
        } catch (Exception e) {
            final String msg = "Failed to login to PKCS#11 provider slot '" + sSlotLabel + "': " + e.getMessage();
            log.warn(msg, e);
            CryptoTokenAuthenticationFailedException authFailException = new CryptoTokenAuthenticationFailedException(msg);
            authFailException.initCause(e);
            throw authFailException;
        }
    }

    @Override
    public void deactivate() {
        this.slot.logout();
        autoActivate();
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) throws CryptoTokenOfflineException {
        if (slot == null) {
            throw new CryptoTokenOfflineException(intres.getLocalizedMessage("token.nodevice"));
        }
        final PrivateKey privateKey = slot.getReleasableSessionPrivateKey(alias);
        if (privateKey == null) {
            final String msg = intres.getLocalizedMessage("token.errornosuchkey", alias);
            log.error(msg);
            throw new CryptoTokenOfflineException(msg);
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
        PublicKey publicKey = slot.getPublicKey(alias,
                Boolean.parseBoolean(getProperties().getProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS)));
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
    public void generateKeyPair(final KeyGenParams keyGenParams, final String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        final String keySpec = keyGenParams.getKeySpecification();
        
        String keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
        try {
            if (keySpec.toUpperCase().startsWith(AlgorithmConstants.KEYALGORITHM_DSA)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSA;
            } else if (AlgorithmTools.isGost3410Enabled() && keySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
            } else if (AlgorithmTools.isDstu4145Enabled() && keySpec.startsWith(CesecoreConfiguration.getOidDstu4145() + ".")) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSTU4145;
            } else if (!Character.isDigit(keySpec.charAt(0))) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
            }
            if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_RSA)) {
                slot.generateRsaKeyPair(keySpec, alias, true, keyGenParams.getPublicAttributesMap(), keyGenParams.getPrivateAttributesMap(), null, false);
            } else if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final String oidString = AlgorithmTools.getEcKeySpecOidFromBcName(keySpec);
                if (!StringUtils.equals(oidString, keySpec)) {
                    slot.generateEccKeyPair(new ASN1ObjectIdentifier(oidString), alias);
                } else {
                    throw new InvalidAlgorithmParameterException("The elliptic curve " + keySpec + " is not supported.");
                }
            } else {
                throw new InvalidAlgorithmParameterException("The key specification " + keySpec + " is not supported.");
            }
            log.debug("Successfully generated keypair");
        } catch (CertificateException | OperatorCreationException ex) {
            log.error("Dummy certificate generation failed. Objects might still have been created in the device: ", ex);
        }
        
    }
    
    @Override
    public void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        // No attribute override used here
        generateKeyPair(KeyGenParams.builder(keySpec).build(), alias);
    }
    
    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias)
            throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException {
    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException,
            IOException, NoSuchPaddingException, IllegalBlockSizeException {
    }

    @Override
    public void keyAuthorizeInit(String alias, KeyPair kakPair, String signProviderName, String selectedPaddingScheme) {
        slot.keyAuthorizeInit(alias, kakPair, signProviderName, selectedPaddingScheme);
    }
    
    @Override
    public void keyAuthorize(String alias, KeyPair kakPair, String signProviderName, long maxOperationCount, String selectedPaddingScheme) {
        slot.keyAuthorize(alias, kakPair, maxOperationCount, signProviderName, selectedPaddingScheme);
    }
    
    @Override
    public void changeAuthData(String alias, KeyPair currentKakPair, KeyPair newKakPair, String signProviderName, String selectedPaddingScheme) {
        slot.changeAuthData(alias, currentKakPair, newKakPair, signProviderName, selectedPaddingScheme);
    }
    
    @Override
    public void backupKey(final int keySpecId, final Path backupFilePath) {
        slot.backupObject(keySpecId, backupFilePath.toString());
    }
    
    @Override
    public void restoreKey(final int keySpecId, final Path backupFilePath) {
        slot.restoreObject(keySpecId, backupFilePath);
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
    }

    @Override
    public byte[] getTokenData() {
        return null;
    }

    @Override
    public boolean permitExtractablePrivateKeyForTest() {
        return false;
    }

    @Override
    public boolean isActive() {
        return getTokenStatus() == CryptoToken.STATUS_ACTIVE;
    }

    @Override
    public int getTokenStatus() {
        autoActivate();
        if (slot == null || slot.getActiveSessions().isEmpty()) {
            return CryptoToken.STATUS_OFFLINE;
        }
        return CryptoToken.STATUS_ACTIVE;
    }

    /**
     * Extracts the slotLabel that is used for many tokens in construction of the provider
     *
     * @param sSlotLabelKey which key in the properties that gives us the label
     * @param properties CA token properties
     * @return String with the slot label, trimmed from whitespace. Never null
     */
    private static String getSlotLabel(String sSlotLabelKey, Properties properties) {
        String ret = "";
        if (properties != null) {
            ret = properties.getProperty(sSlotLabelKey);
            if (ret != null) {
                ret = ret.trim();
            }
        }
        return ret;
    }

}
