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
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.SlotEntry;

import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.BaseCryptoToken;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.P11SlotUser;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabel;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

/** CESeCore Crypto token implementation using the JackNJI11 PKCS#11 to access PKCS#11 tokens 
 */
public class Pkcs11NgCryptoToken extends BaseCryptoToken implements P11SlotUser {

    private static final long serialVersionUID = 1L;

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(Pkcs11NgCryptoToken.class);
    
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
        sSlotLabel = getSlotLabel(PKCS11CryptoToken.SLOT_LABEL_VALUE, properties);
        // Create the slot from the PKCS#11 driver, creating the JCE/JCA provider in Java 
        initSlot(properties);
        // If autoactivation is enabled, login to the slot, otherwise leave it to be logged in manually
        String autoActivatePin = BaseCryptoToken.getAutoActivatePin(properties);
        try {
            if (autoActivatePin != null) {
                activate(autoActivatePin.toCharArray());
            }
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw new CryptoTokenOfflineException(e);
        }        
    }

    private void initSlot(Properties properties) throws NoSuchSlotException, CryptoTokenOfflineException {
        final Pkcs11SlotLabelType slotLabelType = Pkcs11SlotLabelType.getFromKey(getSlotLabel(PKCS11CryptoToken.SLOT_LABEL_TYPE, properties));
        final String sharedLibrary = properties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY);
        final String libraryFileDir = sharedLibrary.substring(0, sharedLibrary.lastIndexOf("/") + 1);
        final String libraryFileName = sharedLibrary.substring(sharedLibrary.lastIndexOf("/") + 1, sharedLibrary.length());
        if (log.isDebugEnabled()) {
            log.debug(">initSlot: id=" + getId() + ", slotLabelType=" + slotLabelType.toString() + 
                    ", sharedLibrary=" + sharedLibrary +
                    ", libraryFileDir=" + libraryFileDir +
                    ", libraryFileName=" + libraryFileName);
        }
        try {
            final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libraryFileName, libraryFileDir, true);
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
        } catch (RuntimeException | LinkageError e) {
            log.error("Failed to load PKCS#11 library: " + e.getMessage(), e);
            throw new CryptoTokenOfflineException(e);
        }
        
        if (slot == null) {
            final String msg = "Unable to obtain token in slot: id=" + getId();
            log.debug(msg);
            throw new NoSuchSlotException(msg);
        }
        setJCAProvider(slot.getProvider());
        if (log.isDebugEnabled()) {
            log.debug("Created a slot with provider: " + slot.getProvider());
        }

    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        if (slot == null) {
            // After a network disconnect and enough errors it can happen that that slot is gone
            // if it is, reconnect by re-creating it here when we try to activate it again
            if (log.isDebugEnabled()) {
                log.debug(">activate: slot is null, calling initSlot: id=" + getId());
            }
            try {
                initSlot(getProperties());
            } catch (NoSuchSlotException e) {
                throw new CryptoTokenOfflineException("Slot not initialized: id=" + getId());
            }
        }
        try {
            // Acquires a session and releases it. Called before login to check for non-authorization related exception
            slot.releaseSession(slot.aquireSession());
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
        if (log.isDebugEnabled()) {
            log.debug(">deactivate: id=" + getId());
        }
        if (slot != null) {
            // Logout will close all sessions, logging out from the HSM 
            // sessions, but till keep the "public" slot reference so we can 
            // create new sessions and log in again easily
            slot.logout();
            // Using for example Utimaco, it will still give "0x00000032: DEVICE_REMOVED" when trying to 
            // create new sessions and logging in the a session again, we have to re-create the slot from scratch
            slot = null;
            // Note that if database protection is using the HSM, and the same slot, 
            // it will be logged out as well. If auto-activation is not used here 
            // log entries can then not be written to the (database) audit log.
            // It will cause one failed audit log write, but if the error ProtectedDataIntegrityImpl
            // detects is OBJECT_HANDLE_INVALID it will try to reload the databaseprotection and re-activate
            // the crypto token, so it will recover after one failed operation
            // Note: only works when database protection also uses P11NG, not SunP11
        }
        autoActivate();
    }

    @Override
    public PrivateKey getPrivateKey(final String alias) throws CryptoTokenOfflineException {
        if (slot == null) {
            throw new CryptoTokenOfflineException("Could not instantiate crypto token. Device unavailable.");
        }
        final PrivateKey privateKey = slot.getReleasableSessionPrivateKey(alias);
        if (privateKey == null) {
            final String msg = " No key with alias '" + alias + "'."; 
            log.warn(msg);
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
        PublicKey publicKey = slot.getPublicKey(alias);
        if (publicKey == null) {
            if (log.isDebugEnabled()) {
                log.debug("No publicKey object object found for alias '" + alias + "', looking for a certificate object instead (i.e. if key was generated using SunP11)"); 
            }
            final Certificate certificate = slot.getCertificate(alias);
            if (certificate == null) {
                final String msg = " No key with alias '" + alias + "'."; 
                throw new CryptoTokenOfflineException(msg);
            }
            publicKey = certificate.getPublicKey();
        }
        final boolean explicitEccParameters = Boolean.parseBoolean(getProperties().getProperty(CryptoToken.EXPLICIT_ECC_PUBLICKEY_PARAMETERS));
        if (explicitEccParameters && publicKey.getAlgorithm().startsWith("EC")) {
            if (log.isDebugEnabled()) {
                log.debug("Using explicit parameter encoding for EC key.");
            }
            try {
                publicKey = ECKeyUtil.publicToExplicitParameters(publicKey, BouncyCastleProvider.PROVIDER_NAME);
            } catch (NoSuchAlgorithmException | IllegalArgumentException | NoSuchProviderException e) {
                throw new CryptoTokenOfflineException(e);
            }
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
        final PrivateKey privateKey = slot.getReleasableSessionPrivateKey(alias);
        testKeyPair(alias, publicKey, privateKey);
    }
    
    @Override
    public void generateKeyPair(final KeyGenParams keyGenParams, final String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        final String keySpec = keyGenParams.getKeySpecification();
        
        String keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
        try {
            if (keySpec.toUpperCase().startsWith(AlgorithmConstants.KEYALGORITHM_DSA)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSA;
            } else if (AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled() && keySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
            } else if (AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled() && keySpec.startsWith(AlgorithmConstants.DSTU4145_OID + ".")) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSTU4145;
            } else if (!Character.isDigit(keySpec.charAt(0))) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
                // ECDSA also handled generation of EdDSA keys, because this is done in PKCS#11 v3 with CKA.EC_PARAMS, but with CKM.EC_EDWARDS_KEY_PAIR_GEN
            }
            // TODO: keySpec of ECC keys of PKCS11NG starts with OID as string, starts with number but has '.'
            // now they resolve to RSA
            if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_RSA)) {
                slot.generateRsaKeyPair(keySpec, alias, true, keyGenParams.getPublicAttributesMap(), keyGenParams.getPrivateAttributesMap(), null, false);
            } else if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final String oidString = AlgorithmTools.getEcKeySpecOidFromBcName(keySpec);
                if (!StringUtils.equals(oidString, keySpec)) {
                    slot.generateEccKeyPair(new ASN1ObjectIdentifier(oidString), alias, true, keyGenParams.getPublicAttributesMap(), keyGenParams.getPrivateAttributesMap(), null, false);
                } else if (keySpec.equals(AlgorithmConstants.KEYALGORITHM_ED25519)) {
                    slot.generateEccKeyPair(new ASN1ObjectIdentifier(EdECObjectIdentifiers.id_Ed25519.getId()), alias, true, keyGenParams.getPublicAttributesMap(), keyGenParams.getPrivateAttributesMap(), null, false);
                } else if (keySpec.equals(AlgorithmConstants.KEYALGORITHM_ED448)) {
                    slot.generateEccKeyPair(new ASN1ObjectIdentifier(EdECObjectIdentifiers.id_Ed448.getId()), alias, true, keyGenParams.getPublicAttributesMap(), keyGenParams.getPrivateAttributesMap(), null, false);
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
        // If there is no slot or there are no sessions to the HSM, consider it offline 
        if (slot == null || (slot.getActiveSessions().isEmpty() && slot.getIdleSessions().isEmpty())) {
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
