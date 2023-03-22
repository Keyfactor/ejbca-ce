/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.provider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.ejb.EJBException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTHORIZE_PARAMS;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTH_DATA;
import org.cesecore.keys.token.p11ng.CK_CP5_CHANGEAUTHDATA_PARAMS;
import org.cesecore.keys.token.p11ng.CK_CP5_INITIALIZE_PARAMS;
import org.cesecore.keys.token.p11ng.P11NGStoreConstants;
import org.cesecore.keys.token.p11ng.PToPBackupObj;
import org.cesecore.keys.token.p11ng.TokenEntry;
import org.cesecore.keys.token.p11ng.jacknji11.CP5Constants;
import org.cesecore.keys.token.p11ng.jacknji11.ExtendedCryptokiE;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKC;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.LongRef;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

/**
 * Instance managing the cryptoki library and allowing access to its slots.
 */
public class CryptokiDevice {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptokiDevice.class);

    private final ExtendedCryptokiE c;
    private final JackNJI11Provider provider;
    private final String libName;
    private final ArrayList<Slot> slots = new ArrayList<>();
    private final HashMap<Long, Slot> slotMap = new HashMap<>();
    private final HashMap<String, Slot> slotLabelMap = new HashMap<>();
    
    private static final int SIGN_HASH_SIZE = 32;
    private static final int MAX_CHAIN_LENGTH = 100;
    
    CryptokiDevice(final ExtendedCryptokiE c, final boolean withCache, final JackNJI11Provider provider, final String libName) {
        if (c == null) {
            throw new IllegalArgumentException("c must not be null");
        }
        this.c = c;
        this.provider = provider;
        this.libName = libName;
        try {
            if (LOG.isTraceEnabled()) {
                LOG.trace("c.Initialize(): "+ libName);
            }
            c.Initialize();
        } catch (CKRException ex) {
            if (ex.getCKR() == CKR.CRYPTOKI_ALREADY_INITIALIZED) {
                LOG.info("Cryptoki already initialized for '" + libName + "'");
            } else if (ex.getCKR() == CKR.GENERAL_ERROR) {
                LOG.info("Cryptoki initialization failed");
                throw new EJBException("Cryptoki initialization failed for '" + libName + "'.", ex);
            } else {
                throw ex;
            }
        }
        
        // Assumes static slots, not dynamically changing for every call, which works with all known HSMs at this time (2022)
        if (LOG.isTraceEnabled()) {
            LOG.trace("c.GetSlotList(true): " + libName);
        }
        try {
            final long[] slotsWithTokens = c.GetSlotList(true);
            for (long slotId : slotsWithTokens) {
                final CK_TOKEN_INFO tokenInfo = c.GetTokenInfo(slotId);
                    String label = null;
                    try {
                        label = decodeUtf8(tokenInfo.label).trim();
                    } catch (CharacterCodingException e) {
                        LOG.info("Label of slot " + slotId + " / index " + slots.size() + " could not be parsed as UTF-8. This slot/token must be referenced by index or ID");
                    }
                    Slot s  = withCache ?
                            new Slot(slotId, label, new CryptokiWithCache(new CryptokiWithoutCache(c)), tokenInfo) :
                            new Slot(slotId, label, new CryptokiWithoutCache(c), tokenInfo);
                    slots.add(s);
                    slotMap.put(slotId, s);
                    slotLabelMap.put(label, s);
            }
        } catch (CKRException ex) {
            throw new EJBException("Slot list retrieval failed.", ex);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("slots (" + libName + "): " + slots);
        }
    }
    
    private String decodeUtf8(final byte[] bytes) throws CharacterCodingException {
        final CharsetDecoder cd = StandardCharsets.UTF_8.newDecoder();
        cd.onMalformedInput(CodingErrorAction.REPORT);
        cd.onUnmappableCharacter(CodingErrorAction.REPORT);
        return cd.decode(ByteBuffer.wrap(bytes)).toString();
    }
    
    public Slot getSlot(final Long slotId) {
        return slotMap.get(slotId);
    }
    
    public Slot getSlotByIndex(final int slotIndex) {
        return slots.get(slotIndex);
    }

    public Slot getSlotByLabel(final String slotLabel) {
        return slotLabelMap.get(slotLabel);
    }
    
    public List<Slot> getSlots() {
        return Collections.unmodifiableList(slots);
    }
    
    public class Slot {
        private final long id;
        private final String label;
        private final LinkedList<NJI11Session> activeSessions = new LinkedList<>();
        private final LinkedList<NJI11Session> idleSessions = new LinkedList<>();
        private final CryptokiFacade cryptoki;
        private final CK_TOKEN_INFO tokenInfo;
        
        private Slot(final long id, final String label, CryptokiFacade cryptoki, CK_TOKEN_INFO tokenInfo) {
            this.id = id;
            this.label = label;
            this.cryptoki = cryptoki;
            this.tokenInfo = tokenInfo;
        }

        public long getId() {
            return id;
        }

        public String getLabel() {
            return label;
        }
        
        final protected String getLibName() {
            return libName;
        }

        final protected ExtendedCryptokiE getCryptoki() {
            return c;
        }
        
        public LinkedList<NJI11Session> getActiveSessions() {
            return activeSessions;
        }
        
        public LinkedList<NJI11Session> getIdleSessions() {
            return idleSessions;
        }
        
        public synchronized NJI11Session aquireSession() {
            NJI11Session session;
            if (!idleSessions.isEmpty()) {
                session = idleSessions.pop();
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Popped session: " + session + ", " + this);
                }
            } else {
                try {
                    final long sessionId = c.OpenSession(id, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    session = new NJI11Session(sessionId);
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("c.OpenSession: " + session + ", " + this);
                    }
                } catch (CKRException ex) {
                    throw new EJBException("Failed to open session.", ex);
                }
            }
            activeSessions.add(session);
            
            if (LOG.isTraceEnabled()) {
                LOG.trace(this);
            }
            
            return session;
        }
        
        public synchronized void releaseSession(final NJI11Session session) {
            // TODO: Checks
            if (session.hasOperationsActive()) {
                LOG.warn("PKCS#11 session up to be released but had potentially active operation so closing instead: " + session);
                closeSession(session);
            } else {
                if (!activeSessions.remove(session)) {
                    LOG.warn("Releasing session not active: " + session + ", " + this);
                }
                idleSessions.push(session);

                if (LOG.isTraceEnabled()) {
                    LOG.trace("Released session: " + session + ", " + this);
                }
            }
        }
        
        /** 
         * Closes a session, but making sure that the last session is not closed so we 
         * are logged out. If you try to close the last session, a new one will be created
         * in the idle pool before the requested session is closed.
         * Unless creating a new session fails of course, then this will be the last session 
         * closed and you will become logged out of the HSM
         * @param session the PKCS#11 session to close
         */
        protected synchronized void closeSession(final NJI11Session session) {
            if (activeSessions.size() <=1 && idleSessions.size() == 0) { // session in param is the 1
                // Put a new session in the idle pool
                releaseSession(aquireSession());
            }
            closeSessionFinal(session);
        }

        /**
         * Closes a session, removing it from active and idle pools. If it's the last session open, 
         * it's closed an you will get logged out of the HSM
         * @param session the PKCS#11 session to close
         */
        private synchronized void closeSessionFinal(final NJI11Session session) {
            try {
                // Close the session and mark it as closed so this NJI11Session object can not be used anymore
                c.CloseSession(session.getId());
                session.markClosed();
            } catch (CKRException ex) {
                throw new EJBException("Could not close session " + session, ex);
            }
            activeSessions.remove(session);
            if (idleSessions.contains(session)) {
                LOG.warn("Session that was closed is marked as idle (removing): " + session + ", " + this);
                idleSessions.remove(session);
            }
            
            if (LOG.isTraceEnabled()) {
                LOG.trace("Closed session " + session + ", " + this);
            }
        }

        public synchronized void login(final String pin) {
            final NJI11Session loginSession = aquireSession();
            if (LOG.isTraceEnabled()) {
                LOG.trace("c.Login: " + loginSession + ", " + this);
            }
            try {
                // PKCS#11 C_Login: 
                // https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472658
                // "When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the application's 
                // sessions will enter either the "R/W SO Functions" state, the "R/W User Functions" state, 
                // or the "R/O User Functions" state."
                // 
                // So it doesn't matter which session we login to and we don't have to keep track of which session was used for login
                c.Login(loginSession.getId(), CKU.USER, pin.getBytes(StandardCharsets.UTF_8));
                // The loginSession can be used as a normal session, push it back to the idle pool if no error occurred
                releaseSession(loginSession);
            } catch (Exception e) {
                try {
                    // Avoid session leak. Close the acquired session if login failed.
                    LOG.info("Exception logging into PKCS#11 session, closing session: " + e.getMessage());
                    closeSessionFinal(loginSession);
                } catch (Exception e1) {
                    // No point in throwing
                }
                throw e;
            }
        }
        
        public synchronized void logout() {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Logout c_CloseAllSessions" + ", " + this);
            }
            // See PKCS#11 specification for C_CloseAllSessions: 
            // https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/pkcs11-base-v3.0-csprd01.html#_Toc10472653
            // "After successful execution of this function, the login state of the token for the application returns to public sessions. 
            // Any new sessions to the token opened by the application will be either R/O Public or R/W Public sessions."
            //
            // So there is no need to explicitly call C_Logout, which just does the same but keeps sessions open as Public sessions.
            c.CloseAllSessions(this.id);
            // After closing all sessions we don't want to keep references to them any longer, clear all our session caches
            idleSessions.clear();
            activeSessions.clear();
            // Clear object and attribute caches
            cryptoki.clear();
        }
        
        /** Finds a PrivateKey object by either certificate label or by private key label 
         * @return the PKCS#11 reference pointer to the private key object, or null if it does not exist 
         */
        // TODO: Support alias that is hexadecimal or label or Id
        private Long getPrivateKeyRefByLabel(final NJI11Session session, final String alias) {
            // We need to optimize so we don't make any unnecessary calls to the HSM, as latency for network HSMs
            // can easily destroy performance of unnecessary FindObject calls are made. So first we check in the 
            // cache only, only if not in the cache will we fall back to look on the HSM, hopefully populating
            // the cache until next time we try to get the private key
            Long ret = getPrivateKeyRefByLabel(session, alias, true);
            if (ret == null) {
                // We did not find anything in the cache, fall back to also check in the HSM, populating the cache
                ret = getPrivateKeyRefByLabel(session, alias, false);
            }
            return ret;
        }
        private Long getPrivateKeyRefByLabel(final NJI11Session session, final String alias, boolean onlyCache) {
            final List<Long> certificateRefs;
            if (onlyCache) {
                certificateRefs = findCertificateObjectsByLabelInCache(session, alias);
            } else {
                certificateRefs = findCertificateObjectsByLabel(session, alias);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Certificate Objects for alias '" + alias + "': " +  certificateRefs);
            }
          
            List<Long> privateKeyRefs = null;
            if (certificateRefs.size() > 0) {
                final CKA ckaId = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_ID);
                if (ckaId == null) {
                    LOG.warn("Missing ID attribute on certificate object with label " + alias);
                    return null;
                }
                if (onlyCache) {
                    privateKeyRefs = findPrivateKeyObjectsByIDInCache(session, ckaId.getValue());
                } else {
                    privateKeyRefs = findPrivateKeyObjectsByID(session, ckaId.getValue());                    
                }
                if (privateKeyRefs.size() > 1) {
                    LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()) + " for alias '" + alias + "'.");
                    return null;
                }
            } else {
                // In this case, we assume the private/public key has the alias in the ID attribute
                if (onlyCache) {
                    privateKeyRefs = findPrivateKeyObjectsByIDInCache(session, alias.getBytes(StandardCharsets.UTF_8));
                } else {
                    privateKeyRefs = findPrivateKeyObjectsByID(session, alias.getBytes(StandardCharsets.UTF_8));                    
                }
                if (privateKeyRefs.size() == 0) {
                    // No private key found with ID same as the label were looking for, look for a private key by label
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Did not find PrivateKey by ID, looking for PrivateKey by label: " + alias);
                    }
                    if (onlyCache) {
                        privateKeyRefs = findPrivateKeyObjectsByLabelInCache(session, alias);                    
                    } else {
                        privateKeyRefs = findPrivateKeyObjectsByLabel(session, alias);                    
                    }
                }
                if (privateKeyRefs.size() > 1) {
                    LOG.warn("More than one private key object sharing CKA_LABEL=" + alias);
                    return null;
                }
            }
            if (!onlyCache && privateKeyRefs.size() == 0) {
                // Don't log warning if we only look in the cache. Only looking in the cache can cause privateKeyRefs to be null for the return though
                LOG.warn("No private key found for alias " + alias);
                return null;
            }
            final Long ret = (privateKeyRefs == null || privateKeyRefs.size() == 0 ? null : privateKeyRefs.get(0));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Private Key Object: " +  ret);
            }
            return ret;
        }

        // TODO: Support alias that is hexadecimal or label or Id
        private Long getPublicKeyRefByLabel(final NJI11Session session, final String alias, boolean onlyCache) {
            final List<Long> certificateRefs = (onlyCache == true ? findCertificateObjectsByLabelInCache(session, alias) : findCertificateObjectsByLabel(session, alias));
            if (LOG.isDebugEnabled()) {
                LOG.debug("Certificate Objects: " +  certificateRefs);
            }
          
            final byte[] publicKeyId;
            if (certificateRefs.size() > 0) {
                final CKA ckaId = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_ID);
                if (ckaId == null) {
                    LOG.warn("Missing ID attribute on object with label " + alias);
                    return null;
                }
                publicKeyId = ckaId.getValue();
            } else {
                // In this case, we assume the private/public key has the alias in the ID attribute
                publicKeyId = alias.getBytes(StandardCharsets.UTF_8);
            }
            final List<Long> publicKeyRefs = (onlyCache == true ? findPublicKeyObjectsByIDInCache(session, publicKeyId) : findPublicKeyObjectsByID(session, publicKeyId));
            if (publicKeyRefs.size() == 0) {
                // A missing public key is fine, since you can have a certificate + private key instead
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No publicKeyRef found on object with label '" + alias + "', which may be fine if there is a certificate object.");
                }
                return null;
            } else if (publicKeyRefs.size() > 1) {
                LOG.warn("More than one public key object sharing CKA_ID=0x" + Hex.toHexString(publicKeyId) + " for alias '" + alias + "'.");
                return null;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Public Key Object: " +  publicKeyRefs.get(0));
            }
            return publicKeyRefs.get(0);
        }
        
        public PrivateKey unwrapPrivateKey(final byte[] wrappedPrivateKey, final String wrappedKeyType, final String unwrapkey, final long wrappingCipher) {
            // Get CKA_KEY_TYPE
            final long wrappedKeyTypeId;
            switch (wrappedKeyType) {
                case "RSA":
                    wrappedKeyTypeId = CKK.RSA;
                    break;
                case "EC":
                case "ECDSA":
                    wrappedKeyTypeId = CKK.EC;
                    break;
                default: // TODO Ed support
                    throw new IllegalArgumentException("Unsuppored key type for key to unwrap: " + wrappedKeyType);
            }

            NJI11Session session = aquireSession();
            // Find unWrapKey
            final List<Long> secretObjects = findSecretKeyObjectsByLabel(session, unwrapkey);

            final long unWrapKey;
            if (secretObjects.size() == 1) {
                unWrapKey = secretObjects.get(0);
            } else if (secretObjects.size() > 1) {
                throw new RuntimeException("More than one secret key found with alias: " + unwrapkey); // TODO
            } else {
                throw new RuntimeException("No such secret key found: " + unwrapkey); // TODO
            }

            CKA[] unwrappedPrivateKeyTemplate = new CKA[]{
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                new CKA(CKA.KEY_TYPE, wrappedKeyTypeId),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.DECRYPT, true),
                new CKA(CKA.SIGN, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.EXTRACTABLE, true),
            };

            long privateKey = getUnwrappedPrivateKey(session, wrappingCipher, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unwrapped key: " + privateKey + ", unwrap key: " + 
                          unWrapKey + ", session: " + session);
            }

            NJI11StaticSessionPrivateKey result = new NJI11StaticSessionPrivateKey(session, privateKey, wrappedKeyType, this, true);
            return result;
        }
        
        public void releasePrivateKey(PrivateKey privateKey) {
            // TODO: Checks
            if (privateKey instanceof NJI11StaticSessionPrivateKey) {
                NJI11StaticSessionPrivateKey priv = (NJI11StaticSessionPrivateKey) privateKey;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Releasing private key: " + ((NJI11StaticSessionPrivateKey) privateKey).getObject() +
                              ", session: " + priv.getSession());
                }

                // Unwrapped keys should be removed
                if (priv.isRemovalOnRelease()) {
                    try {
                        cryptoki.destroyObject(priv.getSession().getId(), priv.getObject());
                    } catch (CKRException ex) {
                        throw new EJBException("Unwrapped key removal failed.", ex);
                    }
                }

                // Release the session
                releaseSession(priv.getSession());
            } else {
                LOG.warn("Not a closable PrivateKey: " + privateKey.getClass().getName());
            }
        }
        
        @Override
        public String toString() {
            return "Slot{" + "id=" + id + ", activeSessions=" + activeSessions + ", idleSessions=" + idleSessions + '}';
        }
        
        public SecretKey getSecretKey(String alias) {
            NJI11Session session = null;
            String keySpec = "n/a";
            try {
                session = aquireSession();

                // Searching by LABEL is sufficient but using SECRET_KEY also just to be extra safe
                final List<Long> secretObjects = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Secret Objects: " + secretObjects);
                }
                if (secretObjects.size() > 1) {
                    LOG.warn("More than one secret key with CKA_LABEL=" + alias);
                } else if (secretObjects.size() == 1) {
                    final CKA keyTypeObj = cryptoki.getAttributeValue(session.getId(), secretObjects.get(0), CKA.KEY_TYPE);
                    final String keyType = CKK.L2S(keyTypeObj.getValueLong());

                    final CKA keySpecObj = cryptoki.getAttributeValue(session.getId(), secretObjects.get(0), CKA.VALUE_LEN);
                    if (keySpecObj != null && keySpecObj.getValueLong() != null) { // This check is required as keySpecObj.getValueLong() may be null in case of DES keys for some HSMs like SOFT HSM
                        keySpec = String.valueOf(keySpecObj.getValueLong() * 8);
                    }

                    return new NJI11ReleasebleSessionSecretKey(secretObjects.get(0), keyType, keySpec, this);
                }
                return null;
            } catch (CKRException ex) {
                throw new EJBException("Failed to get secret key.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);   // XXX Shouldn't we use a static session instead, now the key can't be used!
                }
            }
        }
        
        /**
         * Get a PrivateKey instance including a dedicated session.
         *
         * Note: Caller must eventually call releasePrivateKey(PrivateKey)
         *
         * @param alias of key entry
         * @return  The PrivateKey reference or null if no such key exists
         * @throws CryptoTokenOfflineException
         */
        public PrivateKey aquirePrivateKey(String alias) throws CryptoTokenOfflineException {
            final NJI11Session session;
            try {
                session = aquireSession();
            } catch (CKRException ex) { // throw CryptoTokenOfflineException when device error
                throw new CryptoTokenOfflineException(ex);
            }
            try {
                final Long privateRef = getPrivateKeyRefByLabel(session, alias);
                if (privateRef != null) {
                    return new NJI11StaticSessionPrivateKey(session, privateRef, getPrivateKeyAlgorithm(session, privateRef), this, false);
                }
            } catch (CKRException e) {
                // If a CKRException happens here, it's likely someting wrong with the session. 
                // Close it so we can create a new session instead 
                closeSession(session);
                throw e;
            }
            // And if we ended up here...we could not get a private key...again something wrong with the session? 
            closeSession(session);
            return null;
        }

        private String getPrivateKeyAlgorithm(NJI11Session session, long privateObject) {
            // PKCS#11 v2.40, section 2.9.1, RSA private key objects
            // The only attributes from Table 26 for which a Cryptoki implementation is required to be able to return values are
            // CKA_MODULUS, CKA_PRIVATE_EXPONENT, and CKA_PUBLIC_EXPONENT.
            final CKA modulus = getAttribute(session, privateObject, P11NGStoreConstants.CKA_MODULUS);
            // If we have a modulus value, it's an RSA key. Otherwise, bravely assume it's EC.
            final BigInteger mod;
            final String keyAlg;
            if (modulus.getValue() == null) {
                mod = null;
                keyAlg = "EC";
            } else {
                // We need special treatment for RSA private keys because OpenJDK make a bitLength check
                // on the RSA private key in the TLS implementation
                // SignatureScheme.getSignerOfPreferableAlgorithm->KeyUtil.getKeySize
                // hence we need to modulus also in the private key, not only in the public
                final byte[] modulusBytes = modulus.getValue();
                mod = new BigInteger(1, modulusBytes);
                keyAlg = "RSA";
            }
            return keyAlg;
        }
        
        /**
         * Get a PrivateKey instance that dynamically obtains a session when the Signature instance is being initialized and which is released 
         * automatically when the signing is finished.
         * 
         * Note: If Signature instance is being initialized but never carried out the session might remain.
         * @param alias of key entry
         * @return The PrivateKey object, usable with the P11NG provider, or null if no key with the specified alias exists
         */
        public PrivateKey getReleasableSessionPrivateKey(String alias) { 
            NJI11Session session = null;
            try {
                // A session needed just to get the private key, will be released before return of method
                session = aquireSession();
                final Long privateRef = getPrivateKeyRefByLabel(session, alias);
                if (privateRef != null) {
                    // PKCS#11 v2.40, section 2.9.1, RSA private key objects 
                    // The only attributes from Table 26 for which a Cryptoki implementation is required to be able to return values are 
                    // CKA_MODULUS, CKA_PRIVATE_EXPONENT, and CKA_PUBLIC_EXPONENT. 
                    final CKA modulus = getAttribute(session, privateRef, P11NGStoreConstants.CKA_MODULUS);
                    // If we have a modulus value, it's an RSA key. Otherwise, bravely assume it's EC.
                    final BigInteger mod;
                    final String keyAlg;
                    if (modulus.getValue() == null) {
                        mod = null;
                        keyAlg = "EC";
                    } else {
                        // We need special treatment for RSA private keys because OpenJDK make a bitLength check 
                        // on the RSA private key in the TLS implementation
                        // SignatureScheme.getSignerOfPreferableAlgorithm->KeyUtil.getKeySize
                        // hence we need to modulus also in the private key, not only in the public
                        final byte[] modulusBytes = modulus.getValue();
                        mod = new BigInteger(1, modulusBytes);
                        keyAlg = "RSA";
                    }
                    return NJI11ReleasebleSessionPrivateKey.getInstance(privateRef, keyAlg, this, mod);
                }
                return null;
            } catch (CKRException e) {
                // If a CKRException happens here, it's likely something wrong with the session. 
                // Close it so we can create a new session instead, don't release it to the idle pool. 
                closeSession(session);
                session = null;
                throw e;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        /** Reads a public key from the HSM, from the public key object if it exists, or from a certificate object if no public key object exists
         * First tries to read from the cache to speed things up, but reverts back to checking the HSM is nothing exists in the cache (no public key and no certificate).
         * 
         * @param alias the alias of the public key object to read from PKCS#11 (or the cache)
         * @return null if no key can be found, otherwise a PublicKey which can be an ECPublicKey (BouncyCastle) using named parameters encoding (OID), an EdPublicKey (BouncyCastle), or an RSAPublicKey (BC as well)
         */
        public PublicKey getPublicKey(final String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();

                // We need to optimize so we don't make any unnecessary calls to the HSM, as latency for network HSMs
                // can easily destroy performance of unnecessary FindObject calls are made. So first we check in the
                // cache only, only if not in the cache will we fall back to look on the HSM, hopefully populating
                // the cache until next time we try to get the private key

                // Do we have a certificate already cached? In that case just return it's public key
                final List<Long> certs = findCertificateObjectsByLabelInCache(session, alias);
                if (certs.size() > 0) {
                    final Certificate cert = getCertificate(alias);
                    if (cert != null) {
                        return cert.getPublicKey();
                    }
                }
                // If no cert was found in the cache, try to find a public key, if that fails, finally try to find a cert in the HSM
                // If we have a publicKey it will then be cached for the next round, if we don't have a public key but a cert, it will be cached
                // and tried first in the next round
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Looking for public key with alias '" + alias + "'.");
                }
                Long publicKeyRef;
                // First check in cache only, if not in cache go out to PKCS#11 api and look, adding to cache if it exists
                if ( ((publicKeyRef = getPublicKeyRefByLabel(session, alias, true)) != null) || ((publicKeyRef = getPublicKeyRefByLabel(session, alias, false)) != null)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Fetching public key '" + alias + "' with publicKeyRef = " + publicKeyRef + ".");
                    }
                    return getPublicKeyFromRef(session, publicKeyRef, alias);
                } else {
                    // No public key object found, look for a cert in the HSM, this will then be cached and returned immediately next time method is called
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No public key with alias '" + alias + "' found, trying to fetch certificate with alias instead.");
                    }
                    final Certificate cert = getCertificate(alias);
                    if (cert != null) {
                        return cert.getPublicKey();
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No certificate with alias '" + alias + "' found.");
                    }
                }
                return null;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | IOException | CKRException ex) {
                throw new RuntimeException("Unable to fetch public key with alias '" + alias + "'.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        /** From a public key reference, looks up the relevant attributes on the object (MODULUS, EC_POINT, EC_PARAMS)
         * and created the PublicKey object to be used for signature verification.
         *  
         * @param session the PKCS#11 session to use for GetAttributeValue calls
         * @param publicKeyRef the reference to the public key object
         * @param aliasForLogging the alias of the public key, just used for user friendly logging
         * @return PublicKey or null if no attributes found for the object
         * @throws IOException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws InvalidKeySpecException
         */
        private PublicKey getPublicKeyFromRef(NJI11Session session, final Long publicKeyRef, final String aliasForLogging)
                throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
            
            final CKA modulus = getAttribute(session, publicKeyRef, P11NGStoreConstants.CKA_MODULUS);
            if (modulus.getValue() == null) {
                // No modulus, we will assume it is an EC key
                final CKA ckaQ = getAttribute(session, publicKeyRef, P11NGStoreConstants.CKA_EC_POINT);
                final CKA ckaParams = getAttribute(session, publicKeyRef, P11NGStoreConstants.CKA_EC_PARAMS);
                if (ckaQ.getValue() == null || ckaParams.getValue() == null) {
                    if (ckaQ.getValue() == null) {
                        LOG.warn("Mandatory attribute CKA_EC_POINT is missing for key with alias '" + aliasForLogging + "'.");
                    } else if (ckaParams.getValue() == null) {
                        LOG.warn("Mandatory attribute CKA_EC_PARAMS is missing for key with alias '" + aliasForLogging + "'.");
                    }
                    return null;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying to decode public elliptic curve OID. The DER encoded parameters look like this: " 
                            + StringTools.hex(ckaParams.getValue()) + ".");
                }
                ASN1ObjectIdentifier oid = null;
                try (ASN1InputStream ain = new ASN1InputStream(ckaParams.getValue())) {
                    final ASN1Primitive primitive = ain.readObject();
                    // Here we have some specific things if the key is EdDSA, it can be either an OID or a String
                    // PKCS#11v3 section 2.3.10
                    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
                    // "These curves can only be specified in the CKA_EC_PARAMS attribute of the template for the 
                    // public key using the curveName or the oID methods"
                    // nCipher only supports the curveName, see Integration_Guide_nShield_Cryptographic_API_12.60.pdf section 3.9.16 (12)
                    // CKA_EC_PARAMS is a DER-encoded PrintableString curve25519
                    if (primitive instanceof ASN1String) {
                        final ASN1String string = (ASN1String) primitive;
                        if ("curve25519".equalsIgnoreCase(string.getString())) {
                            oid = EdECObjectIdentifiers.id_Ed25519;
                        } else if ("Ed25519".equalsIgnoreCase(string.getString())) {
                            oid = EdECObjectIdentifiers.id_Ed25519;
                        } else if ("curve448".equalsIgnoreCase(string.getString())) {
                            oid = EdECObjectIdentifiers.id_Ed448;
                        }
                    } else {
                        oid = ASN1ObjectIdentifier.getInstance(ckaParams.getValue());                            
                    }
                } catch (IOException ex) {
                    // P11 states that the curve/oid shoudl be DER encoded, but (at least) Utimaco 
                    // don't do that but just put the curve in a string
                    final String plainString = new String(ckaParams.getValue());
                    if ("curve25519".equalsIgnoreCase(plainString)) {
                        oid = EdECObjectIdentifiers.id_Ed25519;
                    } else if ("Ed25519".equalsIgnoreCase(plainString)) {
                        oid = EdECObjectIdentifiers.id_Ed25519;
                    } else if ("edwards25519".equalsIgnoreCase(plainString)) {
                        oid = EdECObjectIdentifiers.id_Ed25519;
                    } else if ("curve448".equalsIgnoreCase(plainString)) {
                        oid = EdECObjectIdentifiers.id_Ed448;
                    } else {
                        throw new IOException(ex);
                    }
                }
                if (oid == null) {
                    LOG.warn("Unable to reconstruct curve OID from DER encoded data: " + StringTools.hex(ckaParams.getValue()));
                    return null;
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying to decode public elliptic curve point Q using the curve with OID " + oid.getId() 
                        + ". The DER encoded point looks like this: " + StringTools.hex(ckaQ.getValue()));
                }

                // Construct the public key object (Bouncy Castle)
                // Always return a public key with OID form of parameters, which means we probably don't support EC keys with fully custom EC parameters using this code
                {
                    final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(oid.getId());
                    try {
                        if (bcspec != null) {
                            final java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(bcspec.getCurve(), bcspec.getSeed());
                            final java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve,
                                    ASN1OctetString.getInstance(ckaQ.getValue()).getOctets());
                            final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), ecPoint);
                            final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecp, bcspec);
                            final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
                            return keyfact.generatePublic(pubKeySpec);
                        } else if (EdECObjectIdentifiers.id_Ed25519.equals(oid) || EdECObjectIdentifiers.id_Ed448.equals(oid)) {
                            // It is an EdDSA key
                            final X509EncodedKeySpec edSpec = createEdDSAPublicKeySpec(ckaQ.getValue());
                            final KeyFactory keyfact = KeyFactory.getInstance(oid.getId(), BouncyCastleProvider.PROVIDER_NAME);
                            return keyfact.generatePublic(edSpec);
                        } 
                        // Not a known EC curve, and not a known EdDSA algorithm, it's something we can't handle
                        // (will end out returning null below)
                    } catch (IOException e) {
                        // If a point has some invalid encoding, you may end up with an error like
                        // java.io.IOException: DER length more than 4 bytes: 110
                        // Ignore these, this key will not be visible by EJBCA, but the log will show info
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Unable to parse EC point for public key with alias '" + aliasForLogging +"'.", e);
                        }
                    }
                    // If we get here, there was an error
                    LOG.warn("Could not find an elliptic curve with the specified OID " + oid.getId() + " and point " + StringTools.hex(ckaQ.getValue()) + ", not returning public key with alias '" + aliasForLogging +"'.");
                    return null;
                }
            } else {
                final byte[] modulusBytes = modulus.getValue();
                final CKA publicExponent = getAttribute(session, publicKeyRef, P11NGStoreConstants.CKA_PUBLIC_EXPONENT);
                final byte[] publicExponentBytes = publicExponent.getValue();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Trying to decode RSA modulus: " + StringTools.hex(modulusBytes) + " and public exponent: "
                            + StringTools.hex(publicExponentBytes));
                }
                if (publicExponentBytes == null) {
                    LOG.warn("Mandatory attribute CKA_PUBLIC_EXPONENT is missing for RSA key, not returning public key with alias '" + aliasForLogging +"'.");
                    return null;
                }

                final BigInteger n = new BigInteger(1, modulusBytes);
                final BigInteger e = new BigInteger(1, publicExponentBytes);
                return KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).generatePublic(new RSAPublicKeySpec(n, e));
            }
        }
        
        /** Takes the EC point bytes from an EdDSA key and creates a keyspec that we can use to generate the public key object */ 
        private X509EncodedKeySpec createEdDSAPublicKeySpec(byte[] encPoint) throws IOException {
            final byte[] rawPoint;
            // Turns out that different HSMs store this field differently, guess because P11v3 is not fully implemented yet
            // SoftHSM2 uses OctetString, same as for ECDSA keys (I think this is what it should be in P11v3)
            // nCipher (12.60.x) used BitString
            ASN1Primitive asn1 = ASN1Primitive.fromByteArray(encPoint);
            if (asn1 instanceof DERBitString) {
                rawPoint = ((DERBitString) asn1).getOctets();
            } else {
                // If something else than ASN1OctetString we'll get an exception here, which will propagate well 
                // and give us an informative error message
                rawPoint = ((ASN1OctetString) asn1).getOctets();
            }
            AlgorithmIdentifier algId;
            if (rawPoint.length == 32) {
                algId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
            } else {
                algId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
            }
            return new X509EncodedKeySpec(new SubjectPublicKeyInfo(algId, rawPoint).getEncoded());
        }


        public JackNJI11Provider getProvider() {
            return provider;
        }

        public GeneratedKeyData generateWrappedKey(String wrapKeyAlias, String keyAlgorithm, String keySpec, long wrappingCipher) {
            if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
                return generateRSAWrappedKey(wrapKeyAlias, keyAlgorithm, keySpec, wrappingCipher);
            } else if ("ECDSA".equalsIgnoreCase(keyAlgorithm)) {
                return generateEccWrappedKey(wrapKeyAlias, keyAlgorithm, new ASN1ObjectIdentifier(AlgorithmTools.getEcKeySpecOidFromBcName(keySpec)), wrappingCipher);
            } else {
                throw new IllegalArgumentException("Only RSA and ECDSA supported as key algorithms");
            }
        }

        public GeneratedKeyData generateRSAWrappedKey(String wrapKeyAlias, String keyAlgorithm, String keySpec, long wrappingCipher) {

            final int keyLength = Integer.parseInt(keySpec);
            
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Find wrapKey
                final List<Long> secretObjects = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true),
                        new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, wrapKeyAlias));
                
                long wrapKey = -1;
                if (secretObjects.size() == 1) {
                    wrapKey = secretObjects.get(0);
                } else {
                    if (secretObjects.size() < 0) {
                        throw new RuntimeException("No such secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                    if (secretObjects.size() > 1) {
                        throw new RuntimeException("More than one secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                }                

                long[] mechanisms = c.GetMechanismList(id);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mechanisms: " + toString(mechanisms));
                }

                CKA[] publicKeyTemplate = new CKA[] {
                    new CKA(CKA.ENCRYPT, true),
                    new CKA(CKA.VERIFY, true),
                    new CKA(CKA.WRAP, true),
                    new CKA(CKA.MODULUS_BITS, keyLength),
                    new CKA(CKA.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray()),
                };

                CKA[] privateKeyTemplate = new CKA[] {
                    new CKA(CKA.PRIVATE, true),
                    new CKA(CKA.SENSITIVE, true),
                    new CKA(CKA.DECRYPT, true),
                    new CKA(CKA.SIGN, true),
                    new CKA(CKA.UNWRAP, true),
                    new CKA(CKA.EXTRACTABLE, true)
                };

                LongRef publicKeyRef = new LongRef();
                LongRef privateKeyRef = new LongRef();

                cryptoki.generateKeyPair(session.getId(), new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), publicKeyTemplate, privateKeyTemplate, publicKeyRef, privateKeyRef);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated public key: " + publicKeyRef.value + " and private key: " + privateKeyRef.value);
                }

                final CKA modulusValue = cryptoki.getAttributeValue(session.getId(), publicKeyRef.value, CKA.MODULUS);
                final byte[] modulusBytes = modulusValue.getValue();
                final CKA expValue = cryptoki.getAttributeValue(session.getId(), publicKeyRef.value, CKA.PUBLIC_EXPONENT);
                final byte[] publicExponentBytes = expValue.getValue();

                final BigInteger n = new BigInteger(1, modulusBytes);
                final BigInteger e = new BigInteger(1, publicExponentBytes);
                try {
                    RSAPublicKey publicKey = new RSAPublicKey(n, e);
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Public key: " + Base64.toBase64String(publicKey.getEncoded()));
                    }

                    CKM cipherMechanism = new CKM(wrappingCipher);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using mechanism: " + cipherMechanism);
                    }
                    
                    byte[] wrapped = c.WrapKey(session.getId(), cipherMechanism, wrapKey, privateKeyRef.value);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Wrapped private key: " + Base64.toBase64String(wrapped));
                    }

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), publicKey.getEncoded()).getEncoded())); // TODO: Maybe not the shortest

                    return new GeneratedKeyData(wrapped, pubKey);
                } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | CKRException ex) {
                    throw new RuntimeException("Failed to generate wrapped key.", ex);
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public GeneratedKeyData generateEccWrappedKey(String wrapKeyAlias, String keyAlgorithm, final ASN1ObjectIdentifier oid, long wrappingCipher) {
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Find wrapKey ----------------------
                final List<Long> secretObjects = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true),
                        new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, wrapKeyAlias));

                long wrapKey = -1;
                if (secretObjects.size() == 1) {
                    wrapKey = secretObjects.get(0);
                } else {
                    if (secretObjects.size() < 0) {
                        throw new RuntimeException("No such secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                    if (secretObjects.size() > 1) {
                        throw new RuntimeException("More than one secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                }

                final HashMap<Long, Object> publicKeyTemplate = new HashMap<>();
                publicKeyTemplate.put(CKA.ENCRYPT, true);
                publicKeyTemplate.put(CKA.VERIFY, true);
                publicKeyTemplate.put(CKA.WRAP, true);
                publicKeyTemplate.put(CKA.EC_PARAMS, oid.getEncoded());

                final HashMap<Long, Object> privateKeyTemplate = new HashMap<>();
                privateKeyTemplate.put(CKA.DECRYPT, true);
                privateKeyTemplate.put(CKA.SIGN, true);
                privateKeyTemplate.put(CKA.UNWRAP, true);

                privateKeyTemplate.put(CKA.SENSITIVE, true);
                privateKeyTemplate.put(CKA.EXTRACTABLE, true);
                privateKeyTemplate.put(CKA.PRIVATE, true);

                final LongRef publicKeyRef = new LongRef();
                final LongRef privateKeyRef = new LongRef();
                final CKM ckm;
  /*            TODO: Enabled below when adding support for key wrapping with EdDSA (DSS-2476).
                Also compare with similar code block in generateEccKeyPair():
                if (oid.equals(EdECObjectIdentifiers.id_Ed25519) || oid.equals(EdECObjectIdentifiers.id_Ed448)) {
                    // PKCS#11v3 section 2.3.10
                    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
                    // "These curves can only be specified in the CKA_EC_PARAMS attribute of the template for the
                    // public key using the curveName or the oID methods"
                    // nCipher only supports the curveName, see Integration_Guide_nShield_Cryptographic_API_12.60.pdf section 3.9.16 (12)
                    // CKA_EC_PARAMS is a DER-encoded PrintableString curve25519
                    // Generating keys for SoftHSM however, the keys generate fine with PrintableString, but can not be used
                    final String curve = (oid.equals(EdECObjectIdentifiers.id_Ed25519) ? "curve25519" : "curve448");
                    if (StringUtils.contains(libName, "cknfast")) { // only use String for nCipher

                        // actually only Ed25519 is supported (nCipher v12.60 nov2020)
                        final DERPrintableString str = new DERPrintableString(curve);
                        publicKeyTemplate.put(CKA.EC_PARAMS, str.getEncoded());
                    }
                    if (StringUtils.contains(libName, "Cryptoki2")) { // vendor defined mechanism for Thales Luna
                        // Workaround for EdDSA where HSMs are not up to P11v3 yet
                        // In a future where PKCS#11v3 is ubiquitous, this need to be removed.
                        // From cryptoki_v2.h in the lunaclient sample package
                        final long LUNA_CKM_EC_EDWARDS_KEY_PAIR_GEN = (0x80000000L + 0xC01L);
                        // Also using the OID is not good enough...just as for nCipher
                        // actually only Ed25519 is supported (Luna 7 nov2020)
                        final String lunacurve = (oid.equals(EdECObjectIdentifiers.id_Ed25519) ? "Ed25519" : "Ed448");
                        final DERPrintableString str = new DERPrintableString(lunacurve);
                        publicKeyTemplate.put(CKA.EC_PARAMS, str.getEncoded());
                        ckm = new CKM(LUNA_CKM_EC_EDWARDS_KEY_PAIR_GEN);
                    } else {
                        ckm = new CKM(CKM.EC_EDWARDS_KEY_PAIR_GEN);
                    }
                } else {
                    ckm = new CKM(CKM.ECDSA_KEY_PAIR_GEN);
                }*/
                ckm = new CKM(CKM.ECDSA_KEY_PAIR_GEN);
                cryptoki.generateKeyPair(session.getId(), ckm, toCkaArray(publicKeyTemplate), toCkaArray(privateKeyTemplate),
                        publicKeyRef, privateKeyRef);

                CKM cipherMechanism = new CKM(wrappingCipher);

                byte[] wrapped = c.WrapKey(session.getId(), cipherMechanism, wrapKey, privateKeyRef.value);

                final CKA ckaQ = c.GetAttributeValue(session.getId(), publicKeyRef.value, CKA.EC_POINT);
                final CKA ckaParams = c.GetAttributeValue(session.getId(), publicKeyRef.value, CKA.EC_PARAMS);

                if (ckaQ.getValue() == null) {
                    throw new RuntimeException("Failed to read EC point");
                } else if (ckaParams.getValue() == null) {
                    throw new RuntimeException("Failed to read EC parameters");
                } else {
                    // Construct the public key object (Bouncy Castle)
                    // Always return a public key with OID form of parameters, which means we probably don't support EC keys with fully custom EC parameters using this code
                    final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(oid.getId());
                    final PublicKey publicKey;
                    if (bcspec != null) {
                        final java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(bcspec.getCurve(), bcspec.getSeed());
                        final java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve,
                                ASN1OctetString.getInstance(ckaQ.getValue()).getOctets());
                        final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), ecPoint);
                        final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecp, bcspec);
                        final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
                        publicKey = keyfact.generatePublic(pubKeySpec);
/*                  TODO: Enabled below when adding support for key wrapping with EdDSA (DSS-2476).
                    } else if (EdECObjectIdentifiers.id_Ed25519.equals(oid) || EdECObjectIdentifiers.id_Ed448.equals(oid)) {
                        // It is an EdDSA key
                        X509EncodedKeySpec edSpec = createEdDSAPublicKeySpec(ckaQ.getValue());
                        final KeyFactory keyfact = KeyFactory.getInstance(oid.getId(), BouncyCastleProvider.PROVIDER_NAME);
                        publicKey = keyfact.generatePublic(edSpec);
 */
                    } else {
                        throw new RuntimeException("Failed to find an curve with specified OID");
                    }

                    return new GeneratedKeyData(wrapped, publicKey);
                }

            } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException |
                     NoSuchProviderException ex) {
                throw new EJBException(ex);
            } catch (CKRException ex) {
                throw new EJBException("Failed to get public key during ECC key pair generation", ex);
            } finally {
                releaseSession(session);
            }
        }

        public void keyAuthorizeInit(String alias, KeyPair keyAuthorizationKey, String signProviderName, String selectedPaddingScheme) {
            final int KEY_AUTHORIZATION_ASSIGNED = 1;
            NJI11Session session = null;
            try {
                session = aquireSession();
                final PublicKey kakPublicKey = keyAuthorizationKey.getPublic();
                final PrivateKey kakPrivateKey = keyAuthorizationKey.getPrivate();
                final int kakLength = KeyTools.getKeyLength(kakPublicKey);

                CK_CP5_INITIALIZE_PARAMS params = new CK_CP5_INITIALIZE_PARAMS();
                params.authData = getAuthData(kakPublicKey, selectedPaddingScheme);
                params.bAssigned = KEY_AUTHORIZATION_ASSIGNED;
                params.write(); // Write data before passing structure to function
                CKM mechanism = new CKM(CP5Constants.CKM_CP5_INITIALIZE, params.getPointer(), params.size());
                
                final byte[] initSig = getSignatureByteArray(alias, signProviderName, selectedPaddingScheme, session, kakPrivateKey, kakLength, mechanism);

                long rvAuthorizeKey = c.authorizeKey(session.getId(), initSig, initSig.length);
                if (rvAuthorizeKey != CKR.OK) {
                    throw new EJBException("Failed to authorize key.");
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public void keyAuthorize(String alias, KeyPair keyAuthorizationKey, long authorizedoperationCount, String signProviderName, String selectedPaddingScheme) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                final PrivateKey kakPrivateKey = keyAuthorizationKey.getPrivate();
                final PublicKey kakPublicKey = keyAuthorizationKey.getPublic();
                final int kakLength = KeyTools.getKeyLength(kakPublicKey);
                
                CK_CP5_AUTHORIZE_PARAMS params = new CK_CP5_AUTHORIZE_PARAMS();
                params.ulCount = authorizedoperationCount;
                params.write(); // Write data before passing structure to function
                CKM mechanism = new CKM(CP5Constants.CKM_CP5_AUTHORIZE, params.getPointer(), params.size());
                
                final byte[] authSig = getSignatureByteArray(alias, signProviderName, selectedPaddingScheme, session, kakPrivateKey, kakLength, mechanism);
                
                long rvAuthorizeKey = c.authorizeKey(session.getId(), authSig, authSig.length);
                if (rvAuthorizeKey != CKR.OK) {
                    throw new EJBException("Key authorization failed.");
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public void changeAuthData(String alias, KeyPair currentKeyAuthorizationKey, KeyPair newKeyAuthorizationKey, String signProviderName, String selectedPaddingScheme) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                final PublicKey kakPublicKey = newKeyAuthorizationKey.getPublic();
                final PrivateKey kakPrivateKey = currentKeyAuthorizationKey.getPrivate();
                final int kakLength = KeyTools.getKeyLength(kakPublicKey);

                CK_CP5_CHANGEAUTHDATA_PARAMS params = new CK_CP5_CHANGEAUTHDATA_PARAMS();
                params.authData = getAuthData(kakPublicKey, selectedPaddingScheme);
                params.write(); // Write data before passing structure to function
                CKM mechanism = new CKM(CP5Constants.CKM_CP5_CHANGEAUTHDATA, params.getPointer(), params.size());
                
                final byte[] authSig = getSignatureByteArray(alias, signProviderName, selectedPaddingScheme, session, kakPrivateKey, kakLength, mechanism);
                
                long rvAuthorizeKey = c.authorizeKey(session.getId(), authSig, authSig.length);
                if (rvAuthorizeKey != CKR.OK) {
                    throw new EJBException("Failed to authorize key.");
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public void backupObject(final long objectHandle, final String backupFile) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                
                PToPBackupObj ppBackupObj = new PToPBackupObj(null);
                LongByReference backupObjectLength = new LongByReference();
                
                try {
                    c.backupObject(session.getId(), objectHandle, ppBackupObj.getPointer(), backupObjectLength);
                } catch (CKRException ex) {
                    LOG.error("Error while backuping up key. ", ex);
                    throw new EJBException("Backup operation returned with error.");
                }
                int length = (int) backupObjectLength.getValue();
                byte[] resultBytes = ppBackupObj.getValue().getByteArray(0, length);
                
                write2File(resultBytes, backupFile);

            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public void restoreObject(final long objectHandle, final Path backupFilePath) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                final byte[] bytes = Files.readAllBytes(backupFilePath);
                final long flags = 0; // alternative value here would be something called "CXI_KEY_FLAG_VOLATILE" but this causes 0x00000054: FUNCTION_NOT_SUPPORTED
                c.restoreObject(session.getId(), flags, bytes, objectHandle);
            
            } catch (IOException e) {
                LOG.error("Error while restoring key from backup file ", e);
            } catch (CKRException e) {
                throw new EJBException("Restore operation returned with error.");
            }
            finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public boolean isKeyAuthorized(String alias) {
            return false; // TODO: Call the actual check via native commands (if possible, waiting for reply from Utimaco Dev team)
        }
        
        public long maxOperationCount(String alias) {
            return 0; // TODO: Call the actual check via native commands (if possible, waiting for reply from Utimaco Dev team)
        }
        
        /**
         * Generate an ECC keypair in the HSM.
         * 
         * @param oid the OID of the curve to use for key generation, e.g. <code>new ASN1ObjectIdentifier("1.2.840.10045.3.1.7")</code>.
         * @param alias the CKA_LABEL of the key.
         * @throws IllegalStateException if a key with the specified alias already exists on the token.
         */
        public void generateEccKeyPair(final ASN1ObjectIdentifier oid, final String alias, final boolean publicKeyToken,
                                       final Map<Long, Object> overridePublic, final Map<Long, Object> overridePrivate, final CertificateGenerator certGenerator, final boolean storeCertificate) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                if (isAliasUsed(session, alias)) {
                    throw new IllegalArgumentException("Key with CKA_LABEL " + alias + " already exists.");
                }

                final HashMap<Long, Object> publicKeyTemplate = new HashMap<>();
                // Attributes from PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.8 - Public key objects
                /* CK_TRUE if key supports encryption. */
                publicKeyTemplate.put(CKA.ENCRYPT, false);
                /* CK_TRUE if key supports verification where the signature is an appendix to the data. */
                publicKeyTemplate.put(CKA.VERIFY, true);
                /* CK_TRUE if key supports verification where the data is recovered from the signature. */
                // *Comment* ECDSA does not support data recovery on signature verification, but some other ECC signature schemes such as Abe-Okamoto does.
                // Some HSMs (Cavium/Marvell) does not work when specifying this flag but will fail with TEMPLATE_INCONSISTENT, as this 
                // should be false by default on all sensible HSMs, leave it out completely
                //publicKeyTemplate.put(CKA.VERIFY_RECOVER, false);
                /* CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys) */
                publicKeyTemplate.put(CKA.WRAP, false);

                // Attributes from PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.4 - Storage objects
                /* CK_TRUE if object is a token object or CK_FALSE if object is a session object. */
                publicKeyTemplate.put(CKA.TOKEN, publicKeyToken);
                /* Description of the object (default empty). */
                publicKeyTemplate.put(CKA.LABEL, ("pub-" + alias).getBytes(StandardCharsets.UTF_8));

                // PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.7 - Key objects
                /* Key identifier for key (default empty). The CKA_ID field is intended to distinguish among multiple keys. In the case of 
                 * public and private keys, this field assists in handling multiple keys held by the same subject; the key identifier for 
                 * a public key and its corresponding private key should be the same */
                publicKeyTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));

                // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms Specification Version 2.40 section 2.3.3 - ECDSA public key objects
                /* DER-encoding of an ANSI X9.62 Parameters, also known as "EC domain parameters". */
                // *Comment* See X9.62-1998 Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)
                // page 27.
                publicKeyTemplate.put(CKA.EC_PARAMS, oid.getEncoded());

                final HashMap<Long, Object> privateKeyTemplate = new HashMap<>();
                // Attributes from PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.9 - Private key objects
                privateKeyTemplate.put(CKA.DERIVE, true);
                /* CK_TRUE if key supports decryption */
                privateKeyTemplate.put(CKA.DECRYPT, false);
                /* CK_TRUE if key supports signatures where the signature is an appendix to the data. */
                privateKeyTemplate.put(CKA.SIGN, true);
                /* CK_TRUE if key supports signatures where the data can be recovered from the signature. */
                // Some HSMs (Cavium/Marvell) does not work when specifying this flag but will fail with TEMPLATE_INCONSISTENT, as this 
                // should be false by default on all sensible HSMs, leave it out completely
                //privateKeyTemplate.put(CKA.SIGN_RECOVER, false);
                /* CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys. */
                privateKeyTemplate.put(CKA.UNWRAP, false);

                /* CK_TRUE if key is sensitive. */
                privateKeyTemplate.put(CKA.SENSITIVE, true);
                /* CK_TRUE if key is extractable and can be wrapped. */
                privateKeyTemplate.put(CKA.EXTRACTABLE, false);
                // Attributes from PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.4 - Storage objects
                /* CK_TRUE if object is a token object or CK_FALSE if object is a session object. */
                privateKeyTemplate.put(CKA.TOKEN, true);
                /* By default the private key can not be accessed until the user is authenticated */
                privateKeyTemplate.put(CKA.PRIVATE, true);
                /* Description of the object (default empty). */
                privateKeyTemplate.put(CKA.LABEL, ("priv-" + alias).getBytes(StandardCharsets.UTF_8));

                // PKCS #11 Cryptographic Token Interface Base Specification Version 2.40, section 4.7 - Key objects
                /* Key identifier for key (default empty). The CKA_ID field is intended to distinguish among multiple keys. In the case of 
                 * public and private keys, this field assists in handling multiple keys held by the same subject; the key identifier for 
                 * a public key and its corresponding private key should be the same */
                privateKeyTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));
                
                // Override attributes, depending on what was chosen SIGN, ENCRYPT, SIGN/ENCRYPT
                publicKeyTemplate.putAll(overridePublic);
                privateKeyTemplate.putAll(overridePrivate);

                final LongRef publicKeyRef = new LongRef();
                final LongRef privateKeyRef = new LongRef();
                final CKM ckm;
                if (oid.equals(EdECObjectIdentifiers.id_Ed25519) || oid.equals(EdECObjectIdentifiers.id_Ed448)) {
                    // PKCS#11v3 section 2.3.10
                    // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
                    // "These curves can only be specified in the CKA_EC_PARAMS attribute of the template for the 
                    // public key using the curveName or the oID methods"
                    // nCipher only supports the curveName, see Integration_Guide_nShield_Cryptographic_API_12.60.pdf section 3.9.16 (12)
                    // CKA_EC_PARAMS is a DER-encoded PrintableString curve25519
                    // Generating keys for SoftHSM however, the keys generate fine with PrintableString, but can not be used
                    final String curve = (oid.equals(EdECObjectIdentifiers.id_Ed25519) ? "curve25519" : "curve448");
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("EC_EDWARDS_KEY_PAIR_GEN with curve: " + curve);
                    }
                    if (isNcipherHsm()) { // only use String for nCipher
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("cknfast detected, using PrintableString CKA_EC_PARAMS: " + curve);
                        }
                        // actually only Ed25519 is supported (nCipher v12.60 nov2020)
                        final DERPrintableString str = new DERPrintableString(curve);
                        publicKeyTemplate.put(CKA.EC_PARAMS, str.getEncoded());
                        ckm = new CKM(CKM.EC_EDWARDS_KEY_PAIR_GEN);
                    } else if (isThalesLunaHsm()) { // vendor defined mechanism for Thales Luna
                        // Workaround for EdDSA where HSMs are not up to P11v3 yet
                        // In a future where PKCS#11v3 is ubiquitous, this need to be removed.
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Cryptoki2 detected, using CKM_VENDOR_DEFINED + 0xC01 instead of P11v3 for CKM_EC_EDWARDS_KEY_PAIR_GEN: " + curve);
                        }
                        // From cryptoki_v2.h in the lunaclient sample package
                        final long LUNA_CKM_EC_EDWARDS_KEY_PAIR_GEN = (0x80000000L + 0xC01L);
                        // Also using the OID is not good enough...just as for nCipher
                        // actually only Ed25519 is supported (Luna 7 nov2020)
                        final String lunacurve = (oid.equals(EdECObjectIdentifiers.id_Ed25519) ? "Ed25519" : "Ed448");
                        final DERPrintableString str = new DERPrintableString(lunacurve);
                        publicKeyTemplate.put(CKA.EC_PARAMS, str.getEncoded());
                        ckm = new CKM(LUNA_CKM_EC_EDWARDS_KEY_PAIR_GEN);
                    } else if (isUtimacoHsm()) { // utimaco SecurityServer / CryptoServer Se52 Series "P11R3"
                        // Just as the other HSMs, Utimaco only supports Ed25519 (as of today fall 2022), so we expect 
                        // keygen for Ed448 to fail with a P11 error from the HSM until it's implemented (hopefully standardized)
                        // Undocumented deviations from the OASIS PKCS#11 v3
                        // - EC_KEY_PAIR_GEN instead of EC_EDWARDS_KEY_PAIR_GEN
                        // - curve name specified as CKA_EC_PARAM
                        //      - but NOT as DER encoded
                        //      - and NOT curve25519 but edwards25519
                        // disregarding any of these deviations will allow to generate a key just fine, it will be shown as Ed25519, but will fail to Sign...
                        final String utimacoCurve = oid.equals(EdECObjectIdentifiers.id_Ed448) ? "edwards448" : "edwards25519";
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("cs_pkcs11_R3 / utimaco detected: CKM.EC_EDWARDS_KEY_PAIR_GEN=>CKM.EC_KEY_PAIR_GEN, CKA.EC_PARAMS=" + utimacoCurve);
                        }
                        publicKeyTemplate.put(CKA.EC_PARAMS, utimacoCurve.getBytes());
                        ckm = new CKM(CKM.EC_KEY_PAIR_GEN);
                    } else {
                        ckm = new CKM(CKM.EC_EDWARDS_KEY_PAIR_GEN);
                    }
                } else {
                    LOG.trace("Using ECDSA_KEY_PAIR_GEN");
                    ckm = new CKM(CKM.ECDSA_KEY_PAIR_GEN);
                }
                cryptoki.generateKeyPair(session.getId(), ckm, toCkaArray(publicKeyTemplate), toCkaArray(privateKeyTemplate),
                        publicKeyRef, privateKeyRef);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated EC public key " + publicKeyRef.value + " and EC private key " + privateKeyRef.value + ".");
                }

                if (certGenerator != null) {
                    try {
                        final CKA ckaQ = c.GetAttributeValue(session.getId(), publicKeyRef.value, CKA.EC_POINT);
                        final CKA ckaParams = c.GetAttributeValue(session.getId(), publicKeyRef.value, CKA.EC_PARAMS);

                        if (ckaQ.getValue() == null) {
                            LOG.warn("Mandatory attribute CKA_EC_POINT is missing for key with alias '" + alias + "'.");
                            throw new RuntimeException("Failed to read EC point");
                        } else if (ckaParams.getValue() == null) {
                            LOG.warn("Mandatory attribute CKA_EC_PARAMS is missing for key with alias '" + alias + "'.");
                            throw new RuntimeException("Failed to read EC parameters");
                        } else {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Trying to decode public elliptic curve OID. The DER encoded parameters look like this: "
                                        + StringTools.hex(ckaParams.getValue()) + ".");
                            }

                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Trying to decode public elliptic curve point Q using the curve with OID " + oid.getId()
                                    + ". The DER encoded point looks like this: " + StringTools.hex(ckaQ.getValue()));
                            }

                            // Construct the public key object (Bouncy Castle)
                            // Always return a public key with OID form of parameters, which means we probably don't support EC keys with fully custom EC parameters using this code
                            final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(oid.getId());
                            final PublicKey publicKey;
                            if (bcspec != null) {
                                final java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(bcspec.getCurve(), bcspec.getSeed());
                                final java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve,
                                        ASN1OctetString.getInstance(ckaQ.getValue()).getOctets());
                                final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), ecPoint);
                                final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ecp, bcspec);
                                final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
                                publicKey = keyfact.generatePublic(pubKeySpec);
                            } else if (EdECObjectIdentifiers.id_Ed25519.equals(oid) || EdECObjectIdentifiers.id_Ed448.equals(oid)) {
                                // It is an EdDSA key
                                X509EncodedKeySpec edSpec = createEdDSAPublicKeySpec(ckaQ.getValue());
                                final KeyFactory keyfact = KeyFactory.getInstance(oid.getId(), BouncyCastleProvider.PROVIDER_NAME);
                                publicKey = keyfact.generatePublic(edSpec);
                            } else {
                                LOG.warn("Could not find an elliptic curve with the specified OID " + oid.getId() + ", not returning public key with alias '" + alias +"'.");
                                throw new RuntimeException("Failed to find an curve with specified OID");
                            }


                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Public key: " + Base64.toBase64String(publicKey.getEncoded()));
                            }

                            KeyPair keyPair = new KeyPair(publicKey, new NJI11StaticSessionPrivateKey(session, privateKeyRef.value, "EC", this, false));

                            X509Certificate cert = certGenerator.generateCertificate(keyPair, provider); // Note: Caller might want to store the certificate so we need to call this even if storeCertificate==false

                            if (storeCertificate) {
                                CKA[] cert0Template = new CKA[] {
                                    new CKA(CKA.CLASS, CKO.CERTIFICATE),
                                    new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                                    new CKA(CKA.TOKEN, true),
                                    new CKA(CKA.LABEL, alias),
                                    new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
                                    new CKA(CKA.ID, alias),
                                    new CKA(CKA.VALUE, cert.getEncoded())
                                };
                                cryptoki.createObject(session.getId(), cert0Template);
                            }
                        }
                    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException | CertificateException ex) {
                        throw new EJBException(ex);
                    } catch (CKRException ex) {
                        throw new EJBException("Failed to get public key during ECC key pair generation", ex);
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException("Unable to encode OID.", e);
            } catch (CKRException e) {
                throw new EJBException("Key pair generation failed.", e);
            } finally {
                releaseSession(session);
            }
        }

        public void generateRsaKeyPair(final String keySpec, final String alias, final boolean publicKeyToken, final Map<Long, Object> overridePublic,
                                       final Map<Long, Object> overridePrivate, final CertificateGenerator certGenerator, final boolean storeCertificate)
                throws CertificateException, OperatorCreationException {
            final RSAKeyGenParameterSpec rsaKeyGenParameterSpec;
            final String formatCheckedKeySpec = KeyGenParams.getKeySpecificationNumeric(keySpec);
            final int keyLength = Integer.parseInt(formatCheckedKeySpec);

            rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(keyLength, RSAKeyGenParameterSpec.F4);
            generateRsaKeyPair(rsaKeyGenParameterSpec, alias, publicKeyToken, overridePublic, overridePrivate, certGenerator, storeCertificate);
        }

        public void generateRsaKeyPair(final RSAKeyGenParameterSpec rsaKeyGenParameterSpec, final String alias, final boolean publicKeyToken, final Map<Long, Object> overridePublic,
                                       final Map<Long, Object> overridePrivate, final CertificateGenerator certGenerator, final boolean storeCertificate)
                throws CertificateException, OperatorCreationException {
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Check if any key with provided alias exists 
                if (isAliasUsed(session, alias)) {
                    throw new IllegalArgumentException("Key with ID or label " + alias + " already exists");
                }
                try {
                    long[] mechanisms = c.GetMechanismList(id);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Mechanisms: " + toString(mechanisms));
                    }
                } catch (CKRException ex) {
                    throw new EJBException("Mechanism list retrieval failed.", ex);
                }
                
                final HashMap<Long, Object> publicTemplate = new HashMap<>();
                publicTemplate.put(CKA.TOKEN, publicKeyToken);
                publicTemplate.put(CKA.ENCRYPT, false);
                publicTemplate.put(CKA.VERIFY, true);
                publicTemplate.put(CKA.WRAP, false);
                publicTemplate.put(CKA.MODULUS_BITS, rsaKeyGenParameterSpec.getKeysize());
                publicTemplate.put(CKA.PUBLIC_EXPONENT, rsaKeyGenParameterSpec.getPublicExponent().toByteArray());
                publicTemplate.put(CKA.LABEL, ("pub-" + alias).getBytes(StandardCharsets.UTF_8));
                publicTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));

                final HashMap<Long, Object> privateTemplate = new HashMap<>();
                privateTemplate.put(CKA.DERIVE, false);
                privateTemplate.put(CKA.TOKEN, true);
                privateTemplate.put(CKA.PRIVATE, true);
                privateTemplate.put(CKA.SENSITIVE, true);
                privateTemplate.put(CKA.DECRYPT, false);
                privateTemplate.put(CKA.SIGN, true);
                privateTemplate.put(CKA.UNWRAP, false);
                privateTemplate.put(CKA.EXTRACTABLE, false);
                privateTemplate.put(CKA.LABEL, ("priv-" + alias).getBytes(StandardCharsets.UTF_8));
                privateTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));

                // Override attributes
                publicTemplate.putAll(overridePublic);
                privateTemplate.putAll(overridePrivate);

                final CKA[] publicTemplateArray = toCkaArray(publicTemplate);
                final CKA[] privateTemplateArray = toCkaArray(privateTemplate);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public Template:\n" + Arrays.toString(publicTemplateArray));
                    LOG.debug("Private Template:\n" + Arrays.toString(privateTemplateArray));
                }

                LongRef publicKeyRef = new LongRef();
                LongRef privateKeyRef = new LongRef();
                
                try {
                    cryptoki.generateKeyPair(session.getId(), new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), publicTemplateArray, privateTemplateArray, publicKeyRef, privateKeyRef);
                } catch (CKRException ex) {
                    throw new EJBException("Failed to generate RSA key pair.", ex);
                }
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated public key: " + publicKeyRef.value + " and private key: " + privateKeyRef.value);
                }
                if (certGenerator != null) {
                    try {
                        CKA publicValue = getAttribute(session, publicKeyRef.value, P11NGStoreConstants.CKA_MODULUS);
        
                        final byte[] modulusBytes = publicValue.getValue();
        
                        publicValue = getAttribute(session, publicKeyRef.value, P11NGStoreConstants.CKA_PUBLIC_EXPONENT);
                        final byte[] publicExponentBytes = publicValue.getValue();
        
                        final BigInteger n = new BigInteger(1, modulusBytes);
                        final BigInteger e = new BigInteger(1, publicExponentBytes);

                        RSAPublicKey publicKey = new RSAPublicKey(n, e);
    
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Public key: " + Base64.toBase64String(publicKey.getEncoded()));
                        }
    
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), publicKey.getEncoded()).getEncoded())); // TODO: Maybe not the shortest
    
                        KeyPair keyPair = new KeyPair(pubKey, new NJI11StaticSessionPrivateKey(session, privateKeyRef.value, "RSA", this, false));

                        X509Certificate cert = certGenerator.generateCertificate(keyPair, provider); // Note: Caller might want to store the certificate so we need to call this even if storeCertificate==false
                        
                        if (storeCertificate) {
                            CKA[] cert0Template = new CKA[] {
                                new CKA(CKA.CLASS, CKO.CERTIFICATE),
                                new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                                new CKA(CKA.TOKEN, true),
                                new CKA(CKA.LABEL, alias),
                                new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
                                new CKA(CKA.ID, alias),
                                new CKA(CKA.VALUE, cert.getEncoded())
                            };
                            cryptoki.createObject(session.getId(), cert0Template);
                        }
                    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
                        throw new RuntimeException(ex); // TODO
                    } catch (CKRException ex) {
                        throw new EJBException("Failed to get public key during RSA key pair generation", ex);
                    }
                }
                
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        private CK_CP5_AUTH_DATA getAuthData(final PublicKey kakPublicKey, final String selectedPaddingScheme) {
            CK_CP5_AUTH_DATA authData = new CK_CP5_AUTH_DATA();
            RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) generateKeySpec(kakPublicKey);
            BigInteger kakPublicExponent  = publicSpec.getPublicExponent();
            BigInteger kakModulus = publicSpec.getModulus();

            int kakModLen = kakModulus.toByteArray().length;
            int kakPubExpLen = kakPublicExponent.toByteArray().length;
            
            byte[] kakModBuf = new byte[kakModLen];
            byte[] kakPubExpBuf = new byte[kakPubExpLen];
            
            kakModBuf = kakModulus.toByteArray();
            kakPubExpBuf = kakPublicExponent.toByteArray();
            
            authData.ulModulusLen = new NativeLong(kakModLen);
            
            // Allocate sufficient native memory to hold the java array Pointer ptr = new Memory(arr.length);
            // Copy the java array's contents to the native memory ptr.write(0, arr, 0, arr.length);
            Pointer kakModulusPointer = new Memory(kakModLen);
            kakModulusPointer.write(0, kakModBuf, 0, kakModLen);
            authData.pModulus = kakModulusPointer;
            authData.ulPublicExponentLen = new NativeLong(kakPubExpLen);
            
            Pointer kakPublicKeyExponentPointer = new Memory(kakPubExpLen);
            kakPublicKeyExponentPointer.write(0, kakPubExpBuf, 0, kakPubExpLen);
            authData.pPublicExponent = kakPublicKeyExponentPointer;

            if ("PSS".equals(selectedPaddingScheme)) {
                authData.protocol = (byte) CP5Constants.CP5_KEY_AUTH_PROT_RSA_PSS_SHA256;
            } else {
                authData.protocol = (byte) CP5Constants.CP5_KEY_AUTH_PROT_RSA_PKCS1_5_SHA256;
            }
            return authData;
        }
        
        private byte[] getSignatureByteArray(final String alias, final String signProviderName, final String selectedPaddingScheme, 
                final NJI11Session session, final PrivateKey kakPrivateKey, final int kakLength, CKM mechanism) {
            byte[] hash = new byte[SIGN_HASH_SIZE];
            long hashLen = hash.length;
            // Getting the key to initialize and associate with KAK if it exist on the HSM slot with the provided alias.
            final List<Long> privateKeyObjects = findPrivateKeyObjectsByID(session,
                    new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)).getValue());
            if (privateKeyObjects.size() == 0) {
                throw new IllegalStateException("No private key for signing found for alias '" + alias + "'");
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Private key  with Id: '" + privateKeyObjects.get(0) + "' found for key alias '" + alias + "'");
            }   
            long rvAuthorizeKeyInit = c.authorizeKeyInit(session.getId(), mechanism, privateKeyObjects.get(0), hash, new LongRef(hashLen));
            if (rvAuthorizeKeyInit != CKR.OK) {
                throw new EJBException("Failed to initialize key.");
            }
   
            byte[] initSig = new byte[bitsToBytes(kakLength)];
            if ("PSS".equals(selectedPaddingScheme)) {
                try {
                    initSig = signHashPss(hash, hashLen, initSig.length, kakPrivateKey, signProviderName);
                } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
                        | InvalidAlgorithmParameterException | SignatureException e) {
                    LOG.error("Error occurred while signing the hash!", e);
                    throw new EJBException("An error occurred while signing the hash using the PSS padding scheme.");
                }                    
            } else {
                try {
                    initSig = signHashPkcs1(hash, kakPrivateKey, signProviderName);
                } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | DigestException | NoSuchProviderException e) {
                    LOG.error("Error occurred while signing the hash!", e);
                    throw new EJBException("An error occurred while signing the hash using the PKCS#1 padding scheme.");
                }
            }
            return initSig;
        }
        
        private void write2File(byte[] bytes, String filePath) {
            try (OutputStream os = new FileOutputStream(new File(filePath))) {
                os.write(bytes);
            } catch (Exception e) {
                LOG.error("Error happened while writing key to file!", e);
            }
        }
        
        private KeySpec generateKeySpec(final Key key) {
            KeyFactory kf = null;
            KeySpec spec = null;
            try {
                kf = KeyFactory.getInstance("RSA");
                spec = kf.getKeySpec(key, KeySpec.class);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                LOG.error("Error occurred while getting the key spec!", e);
            }
            return spec;
        }
        
        private int bitsToBytes(final int kakSize) {
            int result = (((kakSize) + 7)/8);
            return result;
        }
        
        private byte[] signHashPss(byte[] hash, long hashLen, int length, Key privateKey, String signProviderName) 
                throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
            final int KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE = 32;
            // Due to requirements at the HSM side we have to use RAW signer
            Signature signature = Signature.getInstance("RawRSASSA-PSS", signProviderName);
            PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE, 
                    PSSParameterSpec.DEFAULT.getTrailerField());
            signature.setParameter(pssParameterSpec);
            signature.initSign((PrivateKey) privateKey, new SecureRandom());
            signature.update(hash);
            byte[] signBytes = signature.sign();
            return signBytes;
        }
        
        private byte[] signHashPkcs1(byte[] hash, Key privateKey, String signProviderName) 
                throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, DigestException, NoSuchProviderException {
            Signature signer = Signature.getInstance("NONEwithRSA", signProviderName);
            signer.initSign((PrivateKey) privateKey);
            signer.update(wrapForRsaSign(hash, "SHA-256"));
            byte[] signed = signer.sign();
            return signed;
        }
        
        private byte[] wrapForRsaSign(byte[] dig, String hashAlgo) throws DigestException {
            // PKCS#1 [RFC3447] requires that the padding used for RSA signatures (EMSA-PKCS1-v1_5) MUST use SHA2 AlgorithmIdentifiers with NULL parameters
            final DigestInfo di = new DigestInfo(new AlgorithmIdentifier(new DefaultDigestAlgorithmIdentifierFinder().find(hashAlgo).getAlgorithm(), 
                    DERNull.INSTANCE), dig);
            try {
                return di.getEncoded();
            } catch (IOException e) {
                throw new DigestException(e);
            }
        }
        
        private CKA[] toCkaArray(HashMap<Long, Object> map) {
            final List<CKA> result = new ArrayList<>(map.size());
            for (Map.Entry<Long, Object> entry: map.entrySet()) {
                result.add(new CKA(entry.getKey(), entry.getValue()));
            }
            return result.toArray(new CKA[0]);
        }

        public void generateKey(long keyAlgorithm, int keySpec, String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Check if any key with provided alias exists 
                long[] objs = c.FindObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with label " + alias + " already exists");
                }
                objs = c.FindObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with ID " + alias + " already exists");
                }
                
                final CKA[] secretKeyTemplate;
                
                if (keyAlgorithm == CKM.DES_KEY_GEN || keyAlgorithm == CKM.DES2_KEY_GEN || keyAlgorithm == CKM.DES3_KEY_GEN) {
                    long newMechanism = getMechanismForDESKey(keyAlgorithm, keySpec);
                    keyAlgorithm = newMechanism;
                    // Don't set CKA.VALUE_LEN for DES key as length is fixed
                    secretKeyTemplate = new CKA[]{
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)),
                        new CKA(CKA.WRAP, true),
                        new CKA(CKA.UNWRAP, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8))};
                } else {
                    secretKeyTemplate = new CKA[]{
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)),
                        new CKA(CKA.WRAP, true),
                        new CKA(CKA.UNWRAP, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.VALUE_LEN, keySpec/8),
                        new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8))};
                }                

                LongRef newObjectRef = new LongRef();
                cryptoki.generateKey(session.getId(), new CKM(keyAlgorithm), secretKeyTemplate, newObjectRef);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated secret key: " + newObjectRef.value + " with alias " + alias);
                }
                
            } catch (CKRException ex) {
                throw new EJBException("Key generation failed.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }       
                
        private long getMechanismForDESKey(long keyAlgorithm, int keySpec) {
            Long mechanism = null;
            switch ((int) keyAlgorithm) {
                case (int) CKM.DES_KEY_GEN:
                    if ((keySpec != 64) && (keySpec != 56)) {
                        throw new IllegalArgumentException("DES key length is invalid");
                    }
                    mechanism = CKM.DES_KEY_GEN;
                    break;
                case (int) CKM.DES2_KEY_GEN:
                case (int) CKM.DES3_KEY_GEN:
                    if ((keySpec == 112) || (keySpec == 128)) {
                        mechanism = CKM.DES2_KEY_GEN;
                    } else if ((keySpec == 168) || (keySpec == 192)) {
                        mechanism = CKM.DES3_KEY_GEN;
                    } else {
                        throw new IllegalArgumentException("DESede key length is invalid");
                    }
                    break;
            }
            return mechanism;
        }
        
        public boolean removeKey(String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();

                // 1. Search for a certificate
                final List<Long> certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("removeKey: Found Certificate Objects: " + certificateRefs);
                }
                
                if (certificateRefs.size() > 0) {
                    boolean allDeleted = true;
                    // Find those that have matching private keys
                    for (long certRef : certificateRefs) {
                        CKA ckaId = cryptoki.getAttributeValue(session.getId(), certRef, CKA.ID);
                        if (ckaId == null) {
                            allDeleted = false;
                        } else {
                            final List<Long> privRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                            if (privRefs.size() > 1) {
                                LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                                allDeleted = false;
                            } else if (privRefs.size() == 1) {
                                // Remove private key
                                cryptoki.destroyObject(session.getId(), privRefs.get(0));
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Destroyed private key: " + privRefs.get(0) + " for alias " + alias);
                                }
                                
                                // Now find and remove the certificate and its CA certificates if they are not used
                                removeCertificateAndChain(session, certRef, new HashSet<String>());
                                // If the private key is not there anymore, let's call it a success
                                final List<Long> objectsAfterDeletion = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                                allDeleted = allDeleted && objectsAfterDeletion.size() == 0;
                            }
                        }
                    }
                    // Also delete public key objects, if any
                    removeKeysByType(session, CKO.PUBLIC_KEY, alias);
                    return allDeleted;
                } else {
                    // No certificate found. Find and remove keys directly by label and ID
                    removeKeysByType(session, CKO.SECRET_KEY, alias);
                    removeKeysByType(session, CKO.PRIVATE_KEY, alias);
                    removeKeysByType(session, CKO.PUBLIC_KEY, alias);

                    // Check whether key exists after deletion 
                    final List<Long> objectsAfterDeletion = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                    return objectsAfterDeletion.size() == 0;
                }
            } catch (CKRException ex) {
                throw new EJBException("Key removal failed.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        private void removeKeysByType(final NJI11Session session, final long objectTypeCko, final String alias) {
            final byte[] encodedAlias = alias.getBytes(StandardCharsets.UTF_8);
            removeKeysByType(session, objectTypeCko, CKA.LABEL, encodedAlias);
            removeKeysByType(session, objectTypeCko, CKA.ID, encodedAlias);
        }

        private void removeKeysByType(final NJI11Session session, final long objectTypeCko, final long searchTypeCka, final byte[] alias) {
            try {
                final List<Long> objs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, objectTypeCko), new CKA(searchTypeCka, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("removeKeysByType: Found objects of type " + CKO.L2S(objectTypeCko) + " by " + CKA.L2S(searchTypeCka) + ": " +  objs);
                }
                for (long object : objs) {
                    // Destroy secret key
                    cryptoki.destroyObject(session.getId(), object);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Destroyed Key: " + object + " with alias " + Arrays.toString(alias));
                    }
                }
            } catch (CKRException ex) {
                throw new EJBException("Failed to remove keys.", ex);
            }
        }
                
        private String toString(long[] mechanisms) {
            final StringBuilder results = new StringBuilder();
            for (long l : mechanisms) {
                results.append(CKM.L2S(l));
                results.append(" ");
            }
            return results.toString();
        }
        
        private void removeCertificateAndChain(NJI11Session session, long certRef, final Set<String> keptSubjects) {
            // Remove old certificate objects
             //keptSubjects: Subject DN of certificates that was not deleted
            try {
                List<Long> certificateRefs;
                int i = 0;
                for (; i < MAX_CHAIN_LENGTH; i++) {
                    CKA ckaSubject = cryptoki.getAttributeValue(session.getId(), certRef, CKA.SUBJECT);

                    // If there is no subject there is no chain to look for so just remove this single object
                    if (ckaSubject.getValue() == null) {
                        cryptoki.destroyObject(session.getId(), certRef);
                        break;
                    }

                    CKA ckaIssuer = cryptoki.getAttributeValue(session.getId(), certRef, CKA.ISSUER);
    
                    // 4. Find any certificate objects having this object as issuer, if no found delete the object
                    certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.ISSUER, ckaSubject.getValue()));
                    if (certificateRefs.size() == 0 || (certificateRefs.size() == 1 && certificateRefs.get(0) == certRef)) {
                        cryptoki.destroyObject(session.getId(), certRef);
                    } else {
                        keptSubjects.add(StringTools.hex(ckaSubject.getValue()));
                    }
    
                    // 5. Unless the certificate is self-signed, find the issuer certificate object or if no found skip to 7
                    if (Arrays.equals(ckaSubject.getValue(), ckaIssuer.getValue())) {
                        break;
                    } else {
                        certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, ckaIssuer.getValue()));
    
                        if (certificateRefs.size() == 0) {
                            break;
                        } else if (certificateRefs.size() > 1) {
                            LOG.warn("Multiple certificate objects sharing the same CKA_SUBJECT: " + StringTools.hex(ckaIssuer.getValue()));
                        }
                        // 6. Do step 4 for that object
                        certRef = certificateRefs.get(0);
                    }
                }
                // Either there was more than 100 certificates in the chain or there was some object having an issuer pointing to an earlier object,
                // so lets bail out instead of looping forever if this happens.
                if (i == MAX_CHAIN_LENGTH) {
                    LOG.warn("More than " + MAX_CHAIN_LENGTH + " certificates in chain (or circular subject/issuer chain). All certificates might not have been removed."); 
                }
            } catch (CKRException ex) {
                throw new EJBException("Failed to remove certificate chain.", ex);
            }
        }
        
        /**
         * Import a certificate chain for a private key to the token.
         *
         * Known limitations:
         * - It is not supported to have multiple different CA certificates with the same DN. The existing certificate will be replaced.
         * 
         * Operations that needs to be performed:
         * - Remove previous certificates unless they (i.e. CA certificates) are used by any other key entry
         * - Add the new certificates
         *
         * Algorithm:
         * 1. Find certificate object with provided CKA_LABEL=alias
         * 2. Get the CKA_ID
         * 3. Find the matching private key (just as sanity check)
         *
         * 4. Find any certificate objects having this object as issuer, if no found delete the object otherwise store the name of the subject
         * 5. Unless the certificate is self-signed, find the issuer certificate object or if no found skip to 7
         * 6. Do step 4 for that object
         *
         * 7. Add the new certificate objects, excluding those subjects that was not deleted in step 4
         *
         * @param certChain
         * @param alias 
         */
        public void importCertificateChain(List<Certificate> certChain, String alias) {
            NJI11Session session = null;
            try {
                // TODO: Make some sanity checks on the certificates
                
                session = aquireSession();
                
                // 1. Find certificate object
                final List<Long> certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects for alias '" + alias + "' : " +  certificateRefs);
                }

                CKA ckaId;
                if (certificateRefs.size() > 0) {
                    ckaId = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_ID);
                    if (ckaId == null) {
                        LOG.warn("Missing ID attribute on certificate object with label " + alias);
                        throw new IllegalArgumentException("No such key '" + alias +"': Missing ID attribute on certificate object");
                    }
                } else {
                    // In this case, we assume the private/public key has the alias in the ID attribute
                    ckaId = new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));
                }

                // 3. Find the matching private key (just as sanity check)
                final List<Long> privateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Private Objects for alias '" + alias + "': " +  privateRefs);
                }
                if (privateRefs.size() < 1) {
                    throw new IllegalArgumentException("No such key '" + alias +"'");
                }
                if (privateRefs.size() > 1) {
                    LOG.warn("Warning: More than one private key objects available with CKA_ID: 0x" + Hex.toHexString(ckaId.getValue()) + " for alias '" + alias +"'.");
                }

                // 4. 5. 6. Remove old certificate objects
                final Set<String> keptSubjects = new HashSet<>(); // Subject DN of certificates that was not deleted
                if (certificateRefs.size() > 0) {
                    removeCertificateAndChain(session, certificateRefs.get(0), keptSubjects);
                }

                // 7. Add the new certificate objects, excluding those subjects that was not deleted in step 4.
                // Following the convention used by Oracle Java PKCS#11 Reference Guide
                if (!certChain.isEmpty()) {
                    final Iterator<Certificate> iterator = certChain.iterator();
                    X509Certificate cert = (X509Certificate) iterator.next();

                    byte[] subject = cert.getSubjectX500Principal().getEncoded();
                    
                    CKA[] cert0Template = new CKA[] {           // TODO: Add support for specifying attributes like for keygen
                        new CKA(CKA.CLASS, CKO.CERTIFICATE),
                        new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.LABEL, alias),
                        new CKA(CKA.SUBJECT, subject),
                        new CKA(CKA.ISSUER, cert.getIssuerX500Principal().getEncoded()),
                        new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                        new CKA(CKA.ID, alias),
                        new CKA(CKA.VALUE, cert.getEncoded())
                    };
                    long newCertRef = cryptoki.createObject(session.getId(), cert0Template);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Stored signer certificate object: " + newCertRef);
                    }
                    
                    while (iterator.hasNext()) {
                        cert = (X509Certificate) iterator.next();
                        subject = cert.getSubjectX500Principal().getEncoded();
                        
                        // Note: For now we assume CA certificate subject DN:s are unique
                        final List<Long> existingRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, subject));
                        
                        // Remove existing certificate that we will be replacing now
                        for (long existing : existingRefs) {
                            cryptoki.destroyObject(session.getId(), existing);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Destroyed certificate : " + existing + " for alias " + alias);
                            }
                        }

                        CKA[] certTemplate = new CKA[] {
                            new CKA(CKA.CLASS, CKO.CERTIFICATE),
                            new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                            new CKA(CKA.TOKEN, true),
                            new CKA(CKA.SUBJECT, subject),
                            new CKA(CKA.ISSUER, cert.getIssuerX500Principal().getEncoded()),
                            new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                            new CKA(CKA.VALUE, cert.getEncoded()),
                            new CKA(CKA.ID, getCertID(cert))
                        };
                        newCertRef = cryptoki.createObject(session.getId(), certTemplate);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Stored CA certificate object: " + newCertRef);
                        }
                    }
                }
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(ex);
            } catch (CKRException ex) {
                throw new EJBException("Failed to import certificate chain.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public Certificate getCertificate(String alias) { // TODO: Support for alias that are hexadecimal of label or Id
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Search for all certificate objects on token
                final List<Long> certificateRefs = findCertificateObjectsByLabel(session, alias);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  certificateRefs);
                }

                if (certificateRefs.size() < 1) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Certificate with this alias does not exist: " + alias);
                    }
                    return null;
                }
                final CKA ckaValue = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_VALUE);
                final CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
                final Certificate cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                return cert;
            } catch (CertificateException | NoSuchProviderException ex) {
                throw new IllegalArgumentException(ex);
            } catch (CKRException ex) {
                throw new EJBException("Failed to get certificate", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public List<Certificate> getCertificateChain(String alias) { // TODO: Support for finding aliases that are hexadecimal label or Id
            final LinkedList<Certificate> result = new LinkedList<>();
            NJI11Session session = null;
            try {
                session = aquireSession();

                // Search for all certificate objects on token
                List<Long> certificateRefs = findCertificateObjectsByLabel(session, alias);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  certificateRefs);
                }

                if (certificateRefs.size() > 0) {
                    CKA ckaValue = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_VALUE);
                    final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                    Certificate cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                    result.add(cert);
                    
                    X509Certificate xcert = (X509Certificate) cert;
                    // Don't continue if we found a self-signed cert
                    if (!xcert.getSubjectX500Principal().equals(xcert.getIssuerX500Principal())) {
                        certificateRefs = findCertificateObjectsBySubject(session, ((X509Certificate) cert).getIssuerX500Principal().getEncoded());
                        while (certificateRefs.size() > 0) { // TODO: We might loop forever for incorrect subject/issuer attributes in a circle
                            ckaValue = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_VALUE);
                            cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                            result.add(cert);
                            xcert = (X509Certificate) cert;

                            // Don't continue if we found a self-signed cert
                            if (xcert.getSubjectX500Principal().equals(xcert.getIssuerX500Principal())) {
                                certificateRefs = new ArrayList<>();
                            } else {
                                certificateRefs = findCertificateObjectsBySubject(session, xcert.getIssuerX500Principal().getEncoded());
                            }
                        }
                    }
                }
                return result;
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(ex);
            } catch (CertificateException | NoSuchProviderException ex) {
                throw new IllegalArgumentException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        /**
         * Compute an alias from the CKA_LABEL and CKA_ID of a key.
         * 
         * @param ckaId the CKA_ID of the key whose alias should be computed.
         * @param ckaLabel the CKA_LABEL of the key whose alias should be computed.
         * @return an alias derived from CKA_LABEL if it exists, or CKA_ID if CKA_LABEL does not exist, or null if neither CKA_LABEL nor CKA_ID exists.
         */
        private String toAlias(final CKA ckaId, final CKA ckaLabel) {
            // TODO: It could also happen that label or ID is not UTF-8 in which case we should use hex
            if (ckaLabel == null || ckaLabel.getValue() == null || ckaLabel.getValue().length == 0) {
                if (ckaId == null || ckaId.getValue() == null || ckaId.getValue().length == 0) {
                    return null;
                } else {
                    return new String(ckaId.getValue(), StandardCharsets.UTF_8);
                }
            } else {
                return new String(ckaLabel.getValue(), StandardCharsets.UTF_8);
            }
        }
        
        public Enumeration<SlotEntry> aliases() throws CryptoTokenOfflineException { // TODO: For now we just read all aliases but we should only read chunks and load the next one on demand to scale, see FindObjectsInit, but in that case remember to do session.markFindObjectsStarted() and session.markFindObjectsFinished() in case there is a failure before FindObjectsFinal
            final LinkedList<SlotEntry> result = new LinkedList<>();            
            NJI11Session session = null;
            try {
                session = aquireSession();
                
                // Map private keys to certificate labels, or use the CKA_ID if not found
                final List<Long> privkeyRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Private key objects for aliases: " + privkeyRefs);
                }
                for (long privkeyRef : privkeyRefs) {
                    CKA ckaId = getAttribute(session, privkeyRef, P11NGStoreConstants.CKA_ID);
                    if (ckaId != null && ckaId.getValue() != null && ckaId.getValue().length > 0) {
                        final List<Long> certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.ID, ckaId.getValue()), new CKA(CKA.CLASS, CKO.CERTIFICATE));
                        CKA ckaLabel = null;
                        if (certificateRefs != null && certificateRefs.size() >= 1) {
                            // If a Certificate object exists, use its label. Otherwise, use the ID
                            ckaLabel = getAttribute(session, certificateRefs.get(0), P11NGStoreConstants.CKA_LABEL);
                        } else if (LOG.isTraceEnabled()) {
                            LOG.trace("Private key does not have a corresponding certificate, CKA_ID will be used for Label: " + Hex.toHexString(ckaId.getValue()));
                        }
                        result.add(new SlotEntry(toAlias(ckaId, ckaLabel), TokenEntry.TYPE_PRIVATEKEY_ENTRY));
                    }
                }

                // Add all secret keys
                final List<Long> secretRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Secret Key Objects for aliases: " + secretRefs);
                }
                for (long secretRef : secretRefs) {
                    CKA ckaId = getAttribute(session, secretRef, P11NGStoreConstants.CKA_ID);
                    if (ckaId != null) {
                        CKA ckaLabel = getAttribute(session, secretRef, P11NGStoreConstants.CKA_LABEL);
                        if (ckaLabel != null) {
                            result.add(new SlotEntry(toAlias(ckaId, ckaLabel), TokenEntry.TYPE_SECRETKEY_ENTRY));
                        }
                    }
                }
                return new Enumeration<SlotEntry>() { // XXX
                    int pos = 0;
                    @Override
                    public boolean hasMoreElements() {
                        return pos < result.size();
                    }
                    @Override
                    public SlotEntry nextElement() {
                        return result.get(pos++);
                    }
                };
            } catch (CKRException ex) {
                throw new CryptoTokenOfflineException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
       /**
         * Check if there is a private key entry for the given key alias.
         *
         * A private key entry is defined as having a certificate object with a
         * label that matches the private key ID, or that there is a private key
         * with that ID.
         *
         * @param alias to check
         * @return True if entry was found (either in cache or by querying HSM)
         */
        public boolean hasPrivateKeyEntry(final String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                return getPrivateKeyRefByLabel(session, alias) != null;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        /**
         * Check if there is a secret key entry for the given key alias.
         *
         * @param alias to check
         * @return True if entry was found (either in cache or by querying HSM)
         */
        public boolean hasSecretKeyEntry(final String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                return !findSecretKeyObjectsByLabel(session, alias).isEmpty();
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

       /**
        * Same as CESeCoreUtils#securityInfo.
        * Writes info about security related attributes.
        * @param alias The alias of the private key to get info about.
        * @param sb Buffer to write to, or 'No private key object with alias' if no key with the specified alias can be found
        */
        public void securityInfo(String alias, final StringBuilder sb) {
            NJI11Session session = null;
            try {
                session = aquireSession();

                final Long privateKeyRef = getPrivateKeyRefByLabel(session, alias);
                if (privateKeyRef == null ) {
                    sb.append("No private key object with alias '" + alias + "'");
                } else {
                    final CKA attrs[] = c.GetAttributeValue(session.getId(), privateKeyRef, 
                            CKA.SENSITIVE, 
                            CKA.ALWAYS_SENSITIVE,
                            CKA.EXTRACTABLE,
                            CKA.NEVER_EXTRACTABLE,
                            CKA.PRIVATE,
                            CKA.DERIVE,
                            CKA.MODIFIABLE);

                    for ( final CKA attr : attrs ) {
                        sb.append("  ");
                        sb.append(CKA.L2S(attr.type));
                        sb.append("=");
                        try {
                            sb.append(attr.getValueBool());
                        } catch (IllegalStateException ignored) { // NOPMD
                            sb.append("0x").append(Hex.toHexString(attr.getValue()));
                        }
                    }
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        /**
         * Note: format from SunPKCS11's P11KeyStore.
         * @param cert
         * @return 
         */
        private String getCertID(X509Certificate cert) {
            return cert.getSubjectX500Principal().getName(X500Principal.CANONICAL) +
                "/" +
                cert.getIssuerX500Principal().getName(X500Principal.CANONICAL) +
                "/" +
                cert.getSerialNumber().toString();
        }

        /**
        * Fetches certificate objects with given label, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
        * If the Slot global setting 'usecache' is false, the method will always go out to the HSM with a c.FindObjects.
        *
        * @param session session in HSM slot used to fetch objects
        * @param alias label of certificate
        * @return found certificate objects or an empty list (Collections.emptyList) if no certificate objects found
        */
        List<Long> findCertificateObjectsByLabel(NJI11Session session, String alias) {
            return findCertificateObjectsInternal(session, alias, false);
        }
        /**
        * Fetches certificate objects with given label, returning cached object if cache is enabled and object is present in the cache, not returning enything otherwise.
        *
        * @param session session in HSM slot used to fetch objects
        * @param alias label of certificate
        * @return found certificate objects or an empty list (Collections.emptyList) if no certificate objects found
        */
        List<Long> findCertificateObjectsByLabelInCache(NJI11Session session, String alias) {
            return findCertificateObjectsInternal(session, alias, true);
        }
        /**
         * @param onlyCache Only look into the cache, and return empty list if there is nothing in the cache, ignoring calling the underlying PKCS#11 api
         */
        private List<Long> findCertificateObjectsInternal(NJI11Session session, String alias, boolean onlyCache) {
            try {
                List<Long> certificateRefs = null;
                if (onlyCache) {
                    Optional<List<Long>> cacheret  = cryptoki.findObjectsInCache(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                    if (cacheret.isPresent()) {
                        certificateRefs = cacheret.get(); 
                    }
                } else {
                    certificateRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));                    
                }
                if (certificateRefs != null && certificateRefs.size() > 1) {
                    LOG.warn("More than one certificate object with label " + alias);
                }
                return (certificateRefs == null ? Collections.emptyList() : certificateRefs);
            } catch (CKRException ex) {
                throw new EJBException("Failed to find certificate objects.", ex);
            }
        }

        /**
        * Fetches certificate objects with given subject, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param ckaSubjectValue CKA_SUBJECT of certificate
        * @return found certificate objects, which can be an empty array if no objects are found
        */
        List<Long> findCertificateObjectsBySubject(NJI11Session session, byte[] ckaSubjectValue) {
            try {
                return cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true),
                        new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, ckaSubjectValue));
            } catch (CKRException ex) {
                throw new EJBException("Failed to find certificate objects.", ex);
            }
        }
        
        /**
         * Fetches public key objects with given ID, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
         * If the Slot global setting 'usecache' is false, the method will always go out to the HSM with a c.FindObjects.
         *
         * @param session session in HSM slot used to fetch objects 
         * @param ckaIdValue CKA_ID of public key
         * @return found public key objects, which can be an empty list ((Collections.emptyList)) if no objects are found
         */
        List<Long> findPublicKeyObjectsByID(NJI11Session session, byte[] ckaIdValue) {
            return findKeyObjectsByIDInternal(session, ckaIdValue, CKO.PUBLIC_KEY, false);
        }
        /**
         * Fetches public key objects with given ID, only returning cached object if cache is enabled and object is present in the cache, not returning anything otherwise.
         * 
         * @param session session in HSM slot used to fetch objects 
         * @param ckaIdValue CKA_ID of public key
         * @return found public key objects, which can be an empty list ((Collections.emptyList)) if no objects are found
         */
        List<Long> findPublicKeyObjectsByIDInCache(NJI11Session session, byte[] ckaIdValue) {
            return findKeyObjectsByIDInternal(session, ckaIdValue, CKO.PUBLIC_KEY, true);
        }
        /**
         * @param onlyCache Only look into the cache, and return empty list if there is nothing in the cache, ignoring calling the underlying PKCS#11 api
         * @param type CKO.PUBLIC_KEY or CKO.PRIVATE_KEY 
         */
        private List<Long> findKeyObjectsByIDInternal(NJI11Session session, byte[] ckaIdValue, long type, boolean onlyCache) {
             try {
                 List<Long> pubkeyRefs = null;
                 if (onlyCache) {
                     Optional<List<Long>> cacheret = cryptoki.findObjectsInCache(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, type), new CKA(CKA.ID, ckaIdValue));
                     if (cacheret.isPresent()) {
                         pubkeyRefs = cacheret.get(); 
                     }
                 } else {
                     pubkeyRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, type), new CKA(CKA.ID, ckaIdValue));                     
                 }
                 return (pubkeyRefs == null ? Collections.emptyList() : pubkeyRefs);
             } catch (CKRException ex) {
                 throw new EJBException("Failed to find key objects of type (2=pub, 3=priv) " + type, ex);
             }
         }

        private List<Long> findKeyObjectsByLabelInternal(NJI11Session session, String alias, long type, boolean onlyCache) {
            try {
                List<Long> pubkeyRefs = null;
                if (onlyCache) {
                    //Optional<List<Long>> cacheret  = cryptoki.findObjectsInCache(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                    Optional<List<Long>> cacheret = cryptoki.findObjectsInCache(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, type), new CKA(CKA.LABEL, alias));
                    if (cacheret.isPresent()) {
                        pubkeyRefs = cacheret.get(); 
                    }
                } else {
                    pubkeyRefs = cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, type), new CKA(CKA.LABEL, alias));                     
                }
                return (pubkeyRefs == null ? Collections.emptyList() : pubkeyRefs);
            } catch (CKRException ex) {
                throw new EJBException("Failed to find key objects of type (2=pub, 3=priv) " + type, ex);
            }
        }

        /**
         * Fetches private key objects with given ID, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
         * You can prevent falling back to looking in the HSM without cache by setting onlyCache=true.
         * if the Slot global setting 'usecache' is false, the method will always go out to the HSM with a c.FindObjects.
         *
         * @param session session in HSM slot used to fetch objects 
         * @param ckaIdValue CKA_ID of a private key
         * @return found private key object references, which can be an empty array if no objects are found
         */
        public List<Long> findPrivateKeyObjectsByID(NJI11Session session, byte[] ckaIdValue) {
            return findKeyObjectsByIDInternal(session, ckaIdValue, CKO.PRIVATE_KEY, false);
        }

        /**
         * Fetches private key objects with given ID, only returning cached object if cache is enabled and object is present in the cache, not returning anything otherwise.
         * 
         * @param session session in HSM slot used to fetch objects 
         * @param ckaIdValue CKA_ID of public key
         * @return found private key object references, which can be an empty list ((Collections.emptyList)) if no objects are found
         */
        List<Long> findPrivateKeyObjectsByIDInCache(NJI11Session session, byte[] ckaIdValue) {
            return findKeyObjectsByIDInternal(session, ckaIdValue, CKO.PRIVATE_KEY, true);
        }

        public List<Long> findPrivateKeyObjectsByLabel(NJI11Session session, String label) {
            return findKeyObjectsByLabelInternal(session, label, CKO.PRIVATE_KEY, false);
        }

        List<Long> findPrivateKeyObjectsByLabelInCache(NJI11Session session, String label) {
            return findKeyObjectsByLabelInternal(session, label, CKO.PRIVATE_KEY, true);
        }

        /**
         * Finds all private key objects (both token and session keys).
         * @return list of private key object handles, which can be an empty array if no objects are found
         */
        long[] findAllPrivateKeyObjects() {
            final long[] results;
            NJI11Session session = null;
            try {
                session = aquireSession();
                results = c.FindObjects(session.getId(), new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
            } catch (CKRException ex) {
                throw new EJBException("Failed to find private key objects.", ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
            return results;
        }

        /**
        * Fetches secret key objects with given label, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param alias label of secret key
        * @return found secret key objects, which can be an empty array if no objects are found
        */
        List<Long> findSecretKeyObjectsByLabel(NJI11Session session, String alias) {
            try {
                return cryptoki.findObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));
            } catch (CKRException ex) {
                throw new EJBException("Failed to find secret key objects.", ex);
            }
        }
        
        /**
         * Fetches the requested attribute of a given object, returning cached object if cache is enabled and object is present in the cache, going out to fetch it otherwise.
         *
         * @param session session in HSM slot used to fetch attribute value 
         * @param object the object reference to fetch attribute for
         * @param paramName the attribute to fetch, for example P11NGStoreConstants.CKA_ID
         * @return attribute value, which can be an empty value (CKA.getValue() == null) if attribute does not exist
         */
        CKA getAttribute(NJI11Session session, Long object, String paramName) {
            CKA ckaVal;
            try {
                ckaVal = cryptoki.getAttributeValue(session.getId(), object, P11NGStoreConstants.nameToID(paramName));
            } catch (CKRException ex) {
                throw new EJBException("Failed to get ID of certificate object.", ex);
            }

            return ckaVal;
        }

        /**
         * <p>Fetches the requested attribute of a private key object with the specified alias.
         *
         * @param alias the <code>CKA_LABEL</code> of certificate or private key. If a certificate is found the private
         *              key is matched from <code>CKA_ID</code> of the certificate.
         * @param cka the ID of the attribute to fetch, for example <code>CKA.ALLOWED_MECHANISMS</code>
         *            or <code>CKA.MODULUS</code> (288/0x120).
         * @return an attribute value, which can be an empty value (<code>CKA.getValue() == null</code>) if the attribute
         * does not exist, or <code>null</code> if no private key exists with the specified alias.
         */
        public CKA getPrivateKeyAttribute(final String alias, final long cka) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                final Long privateKeyRef = getPrivateKeyRefByLabel(session, alias);
                if (privateKeyRef == null ) {
                    LOG.warn("No private key object with label: " + label);
                } else {
                    return cryptoki.getAttributeValue(session.getId(), privateKeyRef, cka);
                }
                return null;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        /**
        * fetches private key object in unwrapped form.
        *
        * @param session session in HSM slot used to fetch attribute value 
        * @param wrappingCipher cipher mechanism to be used for unwrapping the wrappedPrivateKey
        * @param unWrapKey secret key object used to unwrap wrapped private key
        * @param wrappedPrivateKey private key in wrapped form
        * @param unwrappedPrivateKeyTemplate unwrapped private key template
        * @return private key object
        */
        long getUnwrappedPrivateKey(NJI11Session session, long wrappingCipher, long unWrapKey, byte[] wrappedPrivateKey, CKA[] unwrappedPrivateKeyTemplate) {
            long privateKey;

            CKM cipherMechanism = getCKMForWrappingCipher(wrappingCipher);

            if (LOG.isTraceEnabled()) {
                LOG.trace("c.UnwrapKey(" + session + ", " + cipherMechanism + ", " + unWrapKey + ", privLength:" + wrappedPrivateKey.length + ", templLength:" + unwrappedPrivateKeyTemplate.length);
            }
            try {
                privateKey = c.UnwrapKey(session.getId(), cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            } catch (CKRException ex) {
                // As there are sporadic failures with thie method returning 0x00000070: MECHANISM_INVALID, try again after a while:
                LOG.error("First error during c.unwrapKey call: " + ex.getMessage(), ex);
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex1) {
                    LOG.error("Interrupted: " + ex1.getMessage(), ex1);
                }
                privateKey = c.UnwrapKey(session.getId(), cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
                LOG.error("C.UnwrapKey call worked after first error");
            }

            // As there is 0x00000060: KEY_HANDLE_INVALID failure during engineInitSign, check if unwrapped private key 
            // actually exists. Try again if not.
            if (!unwrappedPrivateKeyExists(privateKey)) {
                LOG.error("Unwrapped private key does not exist actually, going to try again");
                privateKey = c.UnwrapKey(session.getId(), cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("All private keys after c.UnwrapKey call: " + Arrays.toString(findAllPrivateKeyObjects()));
            }

            return privateKey;
        }

        void removeObject(NJI11Session session, long keyObject) {
            try {
                cryptoki.destroyObject(session.getId(), keyObject);
            } catch (CKRException ex) {
                throw new EJBException("Failed to remove object.", ex);
            }
        }

        private CKM getCKMForWrappingCipher(long wrappingCipher) {
            CKM cipherMechanism = new CKM(wrappingCipher); // OK with nCipher
            // CKM cipherMechanism = new CKM(0x00001091); // SoftHSM2
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using mechanism: " + cipherMechanism);
            }
            return cipherMechanism;
        }
        
        private boolean unwrappedPrivateKeyExists(long unwrappedPrivateKey) {
            Long[] privateKeyObjectsBoxed = ArrayUtils.toObject(findAllPrivateKeyObjects());
            return Arrays.asList(privateKeyObjectsBoxed).contains(unwrappedPrivateKey);
        }

        private boolean isAliasUsed(final NJI11Session session, final String alias) {
            try {
                // Don't use cache when checking if it's used or not on the HSM
                long[] objs = c.FindObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                if (objs.length != 0) {
                    return true;
                }
                objs = c.FindObjects(session.getId(), new CKA(CKA.TOKEN, true), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)));
                if (objs.length != 0) {
                    return true;
                }
            } catch (CKRException ex) {
                throw new EJBException("Error retrieving objects to determine whether alias is used.", ex);
            }
            return false;
        }

        /**
         * Returns true if the HSM library name or manufacturer ID match with the HSM brand in the method name.
         *
         * @return true if the HSM vendor is Utimaco otherwise false.
         */
        public boolean isUtimacoHsm() {
            String utimacoManufacturerID = "Utimaco IS GmbH";
            if (StringUtils.contains(libName, "cs_pkcs11_R")) {
                return true;
            } else {
                return tokenInfo.manufacturerID != null && utimacoManufacturerID.equalsIgnoreCase(new String(tokenInfo.manufacturerID, StandardCharsets.UTF_8).trim());
            }
        }

        /**
         * Returns true if the HSM library name or manufacturer ID match with the HSM brand in the method name.
         *
         * @return true if the HSM vendor is nCipher otherwise false.
         */
        public boolean isNcipherHsm() {
            String nCipherManufacturerID = "nCipher Corp. Ltd";
            if (StringUtils.contains(libName, "cknfast")) {
                return true;
            } else {
                return tokenInfo.manufacturerID != null && nCipherManufacturerID.equalsIgnoreCase(new String(tokenInfo.manufacturerID, StandardCharsets.UTF_8).trim());
            }
        }

        /**
         * Returns true if the HSM library name or manufacturer ID match with the HSM brand in the method name.
         *
         * @return true if the HSM vendor is Thales Luna otherwise false.
         */
        public boolean isThalesLunaHsm() {
            String thalesLunaManufacturerID = "SafeNet Inc";
            if (StringUtils.contains(libName, "Cryptoki2")) {
                return true;
            } else {
                return tokenInfo.manufacturerID != null && thalesLunaManufacturerID.equalsIgnoreCase(new String(tokenInfo.manufacturerID, StandardCharsets.UTF_8).trim());
            }
        }

        /** Returns true if an alias is used as a label or ID */
        public boolean isAliasUsed(final String alias) {
            NJI11Session session = null;
            try {
                session = aquireSession();
                return isAliasUsed(session, alias);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

    }

    public JackNJI11Provider getProvider() {
        return provider;
    }
    
    public interface CertificateGenerator {
        X509Certificate generateCertificate(KeyPair keyPair, Provider provider) throws OperatorCreationException, CertificateException;
    }
}
