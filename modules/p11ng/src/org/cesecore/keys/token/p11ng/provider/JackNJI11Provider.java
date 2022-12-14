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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.sun.jna.Memory;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi.PSS;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11ng.MechanismNames;
import org.cesecore.util.StringTools;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.LongRef;

/**
 * Provider using JackNJI11.
 */
public class JackNJI11Provider extends Provider {

    private static final long serialVersionUID = 7972160215413860118L;

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JackNJI11Provider.class);

    public static final String NAME = "JackNJI11";
    public static final String SIGNATURE_LENGTH_CACHE_ENABLED = "p11ng.signatureLengthCacheEnabled";

    public JackNJI11Provider() {
        super(NAME, 1.3, "JackNJI11 Provider");
 
        putService(new MySigningService(this, "Signature", "MD5withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA224withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSASSA-PSS", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId(), MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId(), MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId(), MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_ED25519, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_ED448, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithECDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA256", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA384", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA512", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "AlgorithmParameters", "PSS", MyAlgorithmParameters.class.getName()));
        putService(new MySigningService(this, "Cipher", "RSAEncryption", MyCipher.class.getName()));
        putService(new MySigningService(this, "Cipher", PKCSObjectIdentifiers.rsaEncryption.getId(), MyCipher.class.getName()));
        putService(new MySigningService(this, "KeyAgreement", "ECDH", MyKeyAgreement.class.getName()));

    }

    private static class MyService extends Service {

        private static final Class<?>[] paramTypes = {Provider.class, String.class};

        MyService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className, null, null);
        }

        @Override
        public Object newInstance(Object param) throws NoSuchAlgorithmException {
            try {
                // get the Class object for the implementation class
                Class<?> clazz;
                Provider provider = getProvider();
                ClassLoader loader = provider.getClass().getClassLoader();
                if (loader == null) {
                    clazz = Class.forName(getClassName());
                } else {
                    clazz = loader.loadClass(getClassName());
                }
                // fetch the (Provider, String) constructor
                Constructor<?> cons = clazz.getConstructor(paramTypes);
                // invoke constructor and return the SPI object
                return cons.newInstance(provider, getAlgorithm());
            } catch (ReflectiveOperationException |  IllegalArgumentException | SecurityException e) {
                LOG.error("Could not instantiate service", e);
                throw new NoSuchAlgorithmException("Could not instantiate service", e);
            }
        }
    }

    private static class MySigningService extends MyService {
        
        MySigningService(Provider provider, String type, String algorithm,
                String className) {
            super(provider, type, algorithm, className);
        }

        // we override supportsParameter() to let the framework know which
        // keys we can support. We support instances of MySecretKey, if they
        // are stored in our provider backend, plus SecretKeys with a RAW encoding.
        @Override
        public boolean supportsParameter(Object obj) {
            if (!(obj instanceof NJI11StaticSessionPrivateKey)
                    && !(obj instanceof NJI11ReleasebleSessionPrivateKey)) {
                if (LOG.isDebugEnabled()) {
                    final StringBuilder sb = new StringBuilder();
                    sb.append("Not our object:\n")
                            .append(obj)
                            .append(", classloader: ")
                            .append(obj.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    sb.append("We are:\n")
                            .append(this)
                            .append(", classloader: ")
                            .append(this.getClass().getClassLoader())
                            .append(" (").append(this.getClass().getClassLoader().hashCode()).append(")")
                            .append("\n");
                    LOG.debug(sb.toString());
                }
                return false;
            }
            return true;
        }
    }

    private static class MySignature extends SignatureSpi {
        private static final Logger log = Logger.getLogger(MySignature.class);

        private String algorithm;
        private NJI11Object myKey;
        private NJI11Session session;
        private ByteArrayOutputStream buffer;
        private final int type;
        private AlgorithmParameterSpec params;
        private boolean hasActiveSession;
        private Exception debugStacktrace;
        private final boolean signatureLengthCacheEnabled;
        
        /** A static HashMap that is used to cache how large byte buffer we need to allocate 
         * to hold the signature created by a specific key for a specific signature algorithm
         */
        private static final HashMap<Integer, Integer> bufLenCache = new HashMap<>();
        // code snitched from Eclipse's auto-generation of hashCode methods
        public int bufLenCacheKey(long slot, long keyRef, String algorithm) {
            final int prime = 31;
            int result = 1;
            result = prime * result + (int) (slot ^ (slot >>> 32));
            result = prime * result + (int) (keyRef ^ (keyRef >>> 32));
            result = prime * result + algorithm.hashCode();
            return result;
        }
        
        @SuppressWarnings("unused")
        public MySignature(Provider provider, String algorithm) {
            super();
            this.algorithm = algorithm;            
            if (MechanismNames.typeFromSigAlgoName(algorithm).isPresent()) {
                type = MechanismNames.typeFromSigAlgoName(algorithm).get();                
            } else {
                throw new RuntimeException("Algorithm " + algorithm + " is not supported, it has no PKCS#11 signature type defined.");
            }
            if (log.isTraceEnabled()) {
                log.trace("Creating Signature provider for algorithm: " + algorithm + ", and provider " + provider + ", type=" + type);
            }

            // Possibility to disable the cache until DSSINTER-846 has been figured out
            signatureLengthCacheEnabled = Boolean.parseBoolean(System.getProperty(SIGNATURE_LENGTH_CACHE_ENABLED, "true"));
        }

        @Override
        protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
            if (!(pk instanceof NJI11Object)) {
                throw new InvalidKeyException("Not a NJI11Object: " + (pk == null ? "null" : pk.getClass().getName()));
            }
            myKey = (NJI11Object) pk;
            
            if (pk instanceof NJI11StaticSessionPrivateKey) {
                session = ((NJI11StaticSessionPrivateKey) pk).getSession();
            } else {
                session = myKey.getSlot().aquireSession();
                hasActiveSession = true;
            }
            try {
                if (!MechanismNames.longFromSigAlgoName(this.algorithm).isPresent()) {
                    final String message = "The signature algorithm " + algorithm + " is not supported by P11NG.";
                    log.error(message);
                    throw new InvalidKeyException("The signature algorithm " + algorithm + " is not supported by P11NG.");
                }
                long mechanism = MechanismNames.longFromSigAlgoName(this.algorithm).get();
                if (mechanism == CKM.EDDSA) {
                    if (myKey.getSlot().isThalesLunaHsm()) {
                        // Workaround, like ED key generation in CryptokiDevice, for EdDSA where HSMs are not up to P11v3 yet
                        // In a future where PKCS#11v3 is ubiquitous, this need to be removed.
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Cryptoki2 detected, using CKM_VENDOR_DEFINED + 0xC03 instead of P11v3 for CKM_EDDSA");
                        }
                        // From cryptoki_v2.h in the lunaclient sample package
                        final long LUNA_CKM_EDDSA = (0x80000000L + 0xC03L);
                        mechanism = LUNA_CKM_EDDSA;
                    } else if (myKey.getSlot().isUtimacoHsm()) { // utimaco SecurityServer / CryptoServer Se52 Series "P11R3"
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("cs_pkcs11_R* / utimaco detected. CKM.EDDSA=>CKM.ECDSA");
                        }
                        mechanism = CKM.ECDSA;
                    }
                }
                final byte[] param;
                if (params == null) {
                    param = MechanismNames.CKM_PARAMS.get(this.algorithm);
                } else if (params instanceof PSSParameterSpec) {
                    param = MechanismNames.encodePssParameters((PSSParameterSpec) params);
                } else {
                    throw new InvalidKeyException("Unsupported algorithm parameter: " + params);
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("engineInitSign: session: " + session + ", object: " +
                            myKey.getObject() + ", sigAlgoValue: 0x" + Long.toHexString(mechanism) + ", param: " + StringTools.hex(param));
                    debugStacktrace = new Exception();
                }
                session.markOperationSignStarted();
                myKey.getSlot().getCryptoki().SignInit(session.getId(), new CKM(mechanism, param),
                        myKey.getObject());
                log.debug("C_SignInit with mechanism 0x" + Long.toHexString(mechanism) + " successful.");
            } catch (Exception e) {
                // An Exception can mean that something has happened causing the session to be broken
                // two threads sharing the same session or something weird, close this session so it can be recovered.
                // We don't want to return this session to the Idle pool if C_SignInit had been called because that will result in a 
                // CKR_OPERATION_ACTIVE if the session is re-used by another signing operation
                log.error("An exception occurred when calling C_SignInit, closing session: " + e.getMessage());
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().closeSession(session);
                    hasActiveSession = false;
                }
                throw new InvalidKeyException(e);
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            engineUpdate(new byte[]{b}, 0, 1);
        }

        @Override
        protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
            switch (type) {
            case MechanismNames.T_UPDATE:
                if (offset != 0 || length != bytes.length) {
                    byte[] newArray = Arrays.copyOfRange(bytes, offset, (offset + length));
                    myKey.getSlot().getCryptoki().SignUpdate(session.getId(), newArray);
                } else {
                    myKey.getSlot().getCryptoki().SignUpdate(session.getId(), bytes);
                }
                break;
            case MechanismNames.T_RAW: // No need to call SignUpdate as hash is supplied already
            case MechanismNames.T_DIGEST: // Will hash the buffer in engineSign
                if (buffer == null) {
                    buffer = new ByteArrayOutputStream();
                }
                buffer.write(bytes, offset, length);
                break;
            default:
                throw new ProviderException("Internal error, type not recognized: " + type);
            }
        }

        byte[] derEncodeEllipticCurve(final byte[] rawSig) throws IOException {
            final BigInteger[] sig = new BigInteger[2];
            final byte[] first = new byte[rawSig.length / 2];
            final byte[] second = new byte[rawSig.length / 2];

            System.arraycopy(rawSig, 0, first, 0, first.length);
            System.arraycopy(rawSig, first.length, second, 0, second.length);
            sig[0] = new BigInteger(1, first);
            sig[1] = new BigInteger(1, second);

            if (log.isDebugEnabled()) {
                log.debug("Parsed signature: " +  System.lineSeparator() +
                               "   X: " + sig[0].toString() + System.lineSeparator() +
                               "   Y: " + sig[1].toString());
            }

            // DER encode the elliptic curve point as a DER sequence with two integers (X, Y)
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(sig[0]));
            seq.addObject(new ASN1Integer(sig[1]));
            seq.close();
            return baos.toByteArray();
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            if (myKey instanceof NJI11ReleasebleSessionPrivateKey && !hasActiveSession) {
                log.warn("No active PKCS#11 session when attempting to sign. Enable debug logging to see init stack trace", debugStacktrace);
                throw new SignatureException("No active PKCS#11 session when attempting to sign.");
            }
            try {
                if (type == MechanismNames.T_UPDATE) {
                    byte[] result =  myKey.getSlot().getCryptoki().SignFinal(session.getId());
                    session.markOperationSignFinished();
                    return result;
                } else if (type == MechanismNames.T_DIGEST) {
                    // Since it's T_DIGEST, hash the buffer before signing it
                    final MessageDigest md = AlgorithmTools.getDigestFromAlgoName(this.algorithm);
                    final byte[] digest = md.digest(buffer.toByteArray());
                    final byte[] sigInput;
                    if (MechanismNames.longFromSigAlgoName(this.algorithm).get() == CKM.RSA_PKCS) {
                        // RSA PKCS#1 input value to the signature operation is a DER encoded DigestInfo structure
                        // PKCS#1 [RFC3447] requires that the padding used for RSA signatures (EMSA-PKCS1-v1_5) MUST use SHA2 AlgorithmIdentifiers with NULL parameters
                        final DigestInfo di = new DigestInfo(new AlgorithmIdentifier(new DefaultDigestAlgorithmIdentifierFinder().find(md.getAlgorithm()).getAlgorithm(), 
                                DERNull.INSTANCE), digest);
                        sigInput = di.getEncoded(ASN1Encoding.DER);
                    } else {
                        // RSA_PKCS_PSS, ECDSA and EDDSA all take the raw hash as input
                        sigInput = digest;
                    }
                    
                    // Make the signature, see if we have cached the length of the signature for this slot, key and algorithm
                    // so that we can optimize away the call to check for the resulting signature length
                    final int key = bufLenCacheKey(myKey.getSlot().getId(), myKey.getObject(), algorithm);
                    final Integer bufLen = bufLenCache.get(key); 
                    byte[] rawSig;
                    if (bufLen != null) {
                        rawSig = new byte[bufLen];
                        try {
                            myKey.getSlot().getCryptoki().Sign(session.getId(), sigInput, rawSig, new LongRef(bufLen));
                            session.markOperationSignFinished();
                        } catch (CKRException e) {
                            // If you use a GCP KMS, there is a transaction limit on the account, if you sign too fast you will be throttled
                            // and get a CKR_DEVICE_ERROR back. If this happened the signing operation is cancelled and the following will 
                            // return a CKR_OPERATION_NOT_INITIALIZED. The real reason will be visible in the libkmsp11 log file as 
                            // a RESOURCE_EXHAUSTED. There is no way to try again here if this happens, but can only be done by starting over
                            // with InitSign.
                            // If it is a DEVICE_ERROR it doesn't make sense to try again here, we should bail out with that error
                            if (e.getCKR() == CKR.DEVICE_ERROR) {
                                throw e;
                            }
                            // Assuming CKR_BUFFER_TOO_SMALL, fallback to multi-call, where the first call asks the HSM 
                            // for the size of buffer needed, and the second call calls with that size of a buffer 
                            // (handled internally in JackNJI11) 
                            if (log.isDebugEnabled()) {
                                log.debug("CKRException calling Sign with pre-allocated buffer of length " + bufLen + ": " + e.getMessage());
                            }
                            rawSig = myKey.getSlot().getCryptoki().Sign(session.getId(), sigInput);
                            session.markOperationSignFinished();
                            // Add the signature length to the cache
                            if (signatureLengthCacheEnabled) {
                                bufLenCache.put(key, rawSig.length);
                            }
                        }
                    } else {
                        rawSig = myKey.getSlot().getCryptoki().Sign(session.getId(), sigInput);
                        session.markOperationSignFinished();
                        // Add the signature length to the cache
                        if (signatureLengthCacheEnabled) {
                            bufLenCache.put(key, rawSig.length);
                        }
                    }

                    // RSA signing by the HSM returns the padded signature, ready to use
                    if (this.algorithm.contains("RSA")) {
                        return rawSig;
                    }
                    // If not RSA, assume it's EC/Ed and continue here to assemble the signature as ECDSA HSM 
                    // signing returns the raw signature, but what is put in signed objects is an ASN.1 encoded version
                    return derEncodeEllipticCurve(rawSig);
                } else { // T_RAW
                    // Ed25519 and Ed448 uses T_RAW
                    // Make the signature, see if we have cached the length of the signature for this key and algorithm
                    // so that we can optimize away the call to check for the resulting signature length
                    final int key = Long.valueOf(myKey.getObject()).hashCode() ^ this.algorithm.hashCode();
                    final Integer bufLen = bufLenCache.get(key); 
                    byte[] rawSig;
                    if (bufLen != null) {
                        rawSig = new byte[bufLen];
                        try {
                            myKey.getSlot().getCryptoki().Sign(session.getId(), buffer.toByteArray(), rawSig, new LongRef(bufLen));
                            session.markOperationSignFinished();
                        } catch (CKRException e) {
                            // Assuming CKR_BUFFER_TOO_SMALL, fallback to multi-call, where the first call asks the HSM 
                            // for the size of buffer needed, and the second call calls with that size of a buffer 
                            // (handled internally in JackNJI11) 
                            if (log.isDebugEnabled()) {
                                log.debug("CKRException calling C_Sign with pre-allocated buffer of length " + bufLen + ", retrying calling with len=0 to fetch the need length: " + e.getMessage());
                            }
                            rawSig = myKey.getSlot().getCryptoki().Sign(session.getId(), buffer.toByteArray());
                            session.markOperationSignFinished();
                            // Add the signature length to the cache
                            if (signatureLengthCacheEnabled) {
                                bufLenCache.put(key, rawSig.length);
                            }
                        }
                    } else {
                        rawSig = myKey.getSlot().getCryptoki().Sign(session.getId(), buffer.toByteArray());
                        session.markOperationSignFinished();
                        // Add the signature length to the cache
                        if (signatureLengthCacheEnabled) {
                            bufLenCache.put(key, rawSig.length);
                        }
                    }

                    if (MechanismNames.longFromSigAlgoName(this.algorithm).get() == CKM.ECDSA) {
                        // assemble the signature as ECDSA HSM signing returns the raw signature, but what is put in signed objects is an ASN.1 encoded version
                        return derEncodeEllipticCurve(rawSig);
                    } else {
                        return rawSig;
                    }
                }
                // An Exception during signing can result in canceling this signing, while C_SignInit has still been called,
                // re-using this session can then later result in CKR_OPERATION_ACTIVE, so upon failure it's better to close 
                // this session so it can be re-created
            } catch (IOException e) {
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().closeSession(session);
                    hasActiveSession = false; // prevent pushing this closed session to the idle pool
                }
                throw new SignatureException(e);
            } catch (NoSuchAlgorithmException e) {
                log.warn("The signature algorithm " + algorithm + " uses an unknown hashing algorithm.", e);
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().closeSession(session);
                    hasActiveSession = false; // prevent pushing this closed session to the idle pool
                }
                throw new SignatureException(e);
            } catch (NoSuchProviderException e) {
                log.error("The Bouncy Castle provider has not been installed.");
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().closeSession(session);
                    hasActiveSession = false; // prevent pushing this closed session to the idle pool
                }
                throw new SignatureException(e);
            } catch (CKRException e) {
                log.warn("PKCS#11 exception while trying to sign: ", e);
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().closeSession(session);
                    hasActiveSession = false; // prevent pushing this closed session to the idle pool
                }
                throw new SignatureException(e);
            } finally {
                // Signing is done, either successful or failed, release the session if there is an active one
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey && hasActiveSession) {
                    myKey.getSlot().releaseSession(session);
                    hasActiveSession = false;
                }
            }
        }

        @Override
        protected boolean engineVerify(byte[] bytes) throws SignatureException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineSetParameter(String string, Object o) throws InvalidParameterException {
            // Super method is deprecated. Use engineSetParameter(AlgorithmParameterSpec params)
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            this.params = params;
        }
        
        @Override
        protected Object engineGetParameter(String string) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
        @Override
        protected void finalize() throws Throwable {
            // TODO: finalize is deprecated and should not be used, should find another way to release session
            try {
                if (hasActiveSession) {
                    log.warn("Signature object was not de-initialized. Enable debug logging to see init stack trace", debugStacktrace);
                    try {
                        final CryptokiDevice.Slot slot = myKey.getSlot();
                        if (slot != null) {
                            slot.releaseSession(session);
                        }
                    } catch (RuntimeException e) {
                        // Can't do anything
                        log.warn("Failed to release PKCS#11 session in finalizer");
                    }
                }
            } finally {
                super.finalize();
            }
        }
    }
    
    private static class MyAlgorithmParameters extends PSS {
        // Fall back on BC PSS parameter configuration. 
        @SuppressWarnings("unused")
        public MyAlgorithmParameters(Provider provider, String algorithm) {
            super();
        }
    }
    
    private static class MyMessageDigiest extends MessageDigestSpi {
        // While this MessageDigiest "implementation" doesn't do anything currently, it's required
        // in order for MGF1 Algorithms to work since BC performs a sanity check before
        // creating signatures with PSS parameters. See org.bouncycastle.operator.jcajce.OperatorHelper.notDefaultPSSParams(...)
        @SuppressWarnings("unused")
        public MyMessageDigiest(Provider provider, String algorithm) {
            super();
        }
        
        @Override
        protected void engineUpdate(byte input) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected byte[] engineDigest() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineReset() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
    
    /**
     * A Java Cipher provider for decrypting small values (key unwrapping) with JackNJI11 PKCS#11. Only does two types of "engineDoInit and engineDoFinal"
     */
    public static class MyCipher extends CipherSpi {

        private static final Logger log = Logger.getLogger(MyCipher.class);

        private int opmode;
        private String algorithm;
        private NJI11Object myKey;
        private NJI11Session session;
        private boolean hasActiveSession;
        private Exception debugStacktrace;

        public MyCipher(Provider provider, String algorithm) {
            super();
            this.algorithm = algorithm;
            if (log.isTraceEnabled()) {
                log.info("Creating Cipher provider for algorithm: " + algorithm + ", and provider: " + provider);
            }
        }

        @Override
        protected byte[] engineUpdate(byte[] b, int off, int len) {
            if (log.isDebugEnabled()) {
                log.debug("engineUpdate1: " + this.getClass().getName());
            }
            return null;
        }
        
        @Override
        protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
                throws InvalidKeyException, NoSuchAlgorithmException {
            if (log.isDebugEnabled()) {
                log.debug("engineUnwrap: " + this.getClass().getName() + ", " + this.opmode + ", " + myKey.getClass().getName()
                        + ", " + wrappedKeyAlgorithm + ", " + wrappedKeyType);
            }
            try {
                long mechanism = MechanismNames.longFromEncAlgoName(this.algorithm).get();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("engineUnwrap: session: " + session + ", object: " +
                            myKey.getObject() + ", algoValue: 0x" + Long.toHexString(mechanism) + ", param: null");
                    debugStacktrace = new Exception();
                }
                // We do unwrapping using DECRYPT in PKCS#11
                // This is very generic and ignores wrappedeyAlgorithm and wrappedKeyType to this method, but it supports our 
                // goal of CMS message encryption using wrapped AES keys for keyRecovery and SCEP in EJBCA
                // Does not support all other generic cases for key wrapping/unwrapping, specifically when you want to use the secret key inside the HSM 
                myKey.getSlot().getCryptoki().DecryptInit(session.getId(), new CKM(mechanism), myKey.getObject());
                final byte[] seckeybuf = myKey.getSlot().getCryptoki().Decrypt(session.getId(), wrappedKey);                
                // Get AES key from byte array
                SecretKey key = new SecretKeySpec(seckeybuf, wrappedKeyAlgorithm);
                return key;
            } finally {
                // Decryption is done, either successful or failed
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().releaseSession(session);
                    hasActiveSession = false;
                }
            }
        }
        
        @Override
        protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4) throws ShortBufferException {
            if (log.isDebugEnabled()) {
                log.debug("engineUpdate2: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2) throws IllegalBlockSizeException, BadPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineDoFinal1: " + this.getClass().getName() + ", opmode=" + this.opmode);
            }
            return null;
        }

        @Override
        protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4)
                throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineDoFinal2: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected int engineGetBlockSize() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetBlockSize: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected byte[] engineGetIV() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetIV: " + this.getClass().getName());
            }
            return null;
        }

        @Override
        protected int engineGetOutputSize(int arg0) {
            if (log.isDebugEnabled()) {
                log.debug("engineGetOutputSize: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetParameters: " + this.getClass().getName());
            }
            return null;
        }

        @Override
        protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit1: " + this.getClass().getName() + ", " + opmode);
            }
            this.opmode = opmode;
            if (this.opmode != Cipher.UNWRAP_MODE) {
                throw new UnsupportedOperationException("Only UNWRAP_MODE (4) can be used: " + opmode);
            }
            
            if (!(key instanceof NJI11Object)) {
                throw new InvalidKeyException("Not a NJI11Object: " + key.getClass().getName());
            }
            myKey = (NJI11Object) key;
            
            if (key instanceof NJI11StaticSessionPrivateKey) {
                session = ((NJI11StaticSessionPrivateKey) key).getSession();
            } else {
                session = myKey.getSlot().aquireSession();
                hasActiveSession = true;
            }
            try {
                if (!MechanismNames.longFromEncAlgoName(this.algorithm).isPresent()) {
                    final String message = "The cipher algorithm " + algorithm + " is not supported by P11NG.";
                    log.error(message);
                    throw new InvalidKeyException("The cipher algorithm " + algorithm + " is not supported by P11NG.");
                }
                log.debug("C_EncryptInit with algorithm " + this.algorithm + " successful.");
            } catch (Exception e) {
                log.error("An exception occurred when calling C_EncryptInit: " + e.getMessage());
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().releaseSession(session);
                    hasActiveSession = false;
                }
                throw e;
            }
        }

        @Override
        protected void engineInit(int opmode, Key arg1, AlgorithmParameterSpec arg2, SecureRandom arg3)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit2: " + this.getClass().getName());
            }
        }

        @Override
        protected void engineInit(int opmode, Key arg1, AlgorithmParameters arg2, SecureRandom arg3)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit3: " + this.getClass().getName());
            }
        }

        @Override
        protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
            if (log.isDebugEnabled()) {
                log.debug("engineSetMode: " + this.getClass().getName() + ", " + mode);
            }
        }

        @Override
        protected void engineSetPadding(String arg0) throws NoSuchPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineSetPadding: " + this.getClass().getName());
            }
        }

        @Override
        protected void finalize() throws Throwable {
            try {
                if (hasActiveSession) {
                    log.warn("Decryption object was not de-initialized. Enable debug logging to see init stack trace", debugStacktrace);
                    try {
                        final CryptokiDevice.Slot slot = myKey.getSlot();
                        if (slot != null) {
                            slot.releaseSession(session);
                        }
                    } catch (RuntimeException e) {
                        // Can't do anything
                        log.warn("Failed to release PKCS#11 session in finalizer");
                    }
                }
            } finally {
                super.finalize();
            }
        }
    }
    
    private static class MyKeyAgreement extends KeyAgreementSpi {
        private static final Logger log = Logger.getLogger(MyKeyAgreement.class);

        private String algorithm;
        private NJI11Object privateBaseKey;
        private NJI11Session session;
        private boolean hasActiveSession;
        private Exception debugStacktrace;
        private BCECPublicKey pubKey;
        
        public MyKeyAgreement(Provider provider, String algorithm) {
            super();
            this.algorithm = algorithm;
            if (log.isTraceEnabled()) {
                log.trace("Creating KeyAgreement provider for algorithm: " + algorithm + ", and provider: " + provider);
            }
        }

        @Override
        protected Key engineDoPhase(Key publicKey, boolean arg1) throws InvalidKeyException, IllegalStateException {
            log.trace("engineDoPhase: " + this.getClass().getName());
            pubKey = new BCECPublicKey((ECPublicKey)publicKey, null);
            return null;
        }

        @Override
        protected byte[] engineGenerateSecret() throws IllegalStateException {
            log.trace("engineGenerateSecret0: " + this.getClass().getName());
            CKA[] pubTempl;
            pubTempl = new CKA[] {
                    new CKA(CKA.TOKEN, false),
                    new CKA(CKA.CLASS, CKO.SECRET_KEY),
                    new CKA(CKA.SENSITIVE, false),
                    new CKA(CKA.EXTRACTABLE, true),
                    new CKA(CKA.KEY_TYPE, CKK.GENERIC_SECRET),
                    new CKA(CKA.WRAP, true),
                    new CKA(CKA.UNWRAP, true),
                    new CKA(CKA.ENCRYPT, true),
                    new CKA(CKA.DECRYPT, true)
                };
                
            CKM mechanism;            
            Memory pubKeyEncoded = new Memory(65); // assume 256 bit only
            pubKeyEncoded.write(0, pubKey.getQ().getEncoded(false), 0, 65);
            
            MyEcdhParameters ecdhParams = new MyEcdhParameters(pubKeyEncoded);
            ecdhParams.write();

            mechanism = new CKM(CKM.ECDH1_DERIVE);
            mechanism.pParameter = ecdhParams.getPointer();
            mechanism.ulParameterLen = ecdhParams.size();

            long keyRef = 0;
            try {
                keyRef = privateBaseKey.getSlot().getCryptoki().DeriveKey(session.getId(), mechanism,
                            privateBaseKey.getObject(), pubTempl);
            } catch(CKRException e) {
                log.warn("PKCS#11 exception while trying to ecdh: ", e);
                if (privateBaseKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    privateBaseKey.getSlot().closeSession(session);
                    hasActiveSession = false;
                }
                throw new IllegalStateException("PKCS#11 exception while trying to ecdh: ", e);
            }
            
            CKA privKeyAttribute = ((NJI11ReleasebleSessionPrivateKey) privateBaseKey).getSlot().getCryptoki()
                    .GetAttributeValue(session.getId(), keyRef, CKA.VALUE);
            
            if (privateBaseKey instanceof NJI11ReleasebleSessionPrivateKey) {
                privateBaseKey.getSlot().closeSession(session);
                hasActiveSession = false;
            }
            return privKeyAttribute.getValue();
        }

        @Override
        protected SecretKey engineGenerateSecret(String arg0) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
            log.trace("engineGenerateSecret1: " + this.getClass().getName());
            return null;
        }

        @Override
        protected int engineGenerateSecret(byte[] arg0, int arg1) throws IllegalStateException, ShortBufferException {
            log.trace("engineGenerateSecret2: " + this.getClass().getName());
            return 0;
        }

        @Override
        protected void engineInit(Key key, SecureRandom arg1) throws InvalidKeyException {
            log.trace("engineInit1: " + this.getClass().getName());
            
            privateBaseKey = (NJI11Object) key;
            session = ((NJI11ReleasebleSessionPrivateKey) key).getSlot().aquireSession();
            hasActiveSession = true;
            
            CKA caKeySupportsDerive = ((NJI11ReleasebleSessionPrivateKey) key).getSlot().getCryptoki()
                    .GetAttributeValue(session.getId(), 
                            ((NJI11ReleasebleSessionPrivateKey) key).getObject(), 
                            CKA.DERIVE);

            log.debug("EC private key supports derive operation:" + caKeySupportsDerive.toString());

        }

        @Override
        protected void engineInit(Key arg0, AlgorithmParameterSpec arg1, SecureRandom arg2)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            log.info("engineInit2: " + this.getClass().getName());
        }
        
        @Override
        protected void finalize() throws Throwable {
            try {
                if (hasActiveSession) {
                    log.warn("Keyagreement object was not de-initialized. Enable debug logging to see init stack trace", debugStacktrace);
                    try {
                        final CryptokiDevice.Slot slot = privateBaseKey.getSlot();
                        if (slot != null) {
                            slot.releaseSession(session);
                        }
                    } catch (RuntimeException e) {
                        // Can't do anything
                        log.warn("Failed to release PKCS#11 session in finalizer");
                    }
                }
            } finally {
                super.finalize();
            }
        }
        
    }
    
}
