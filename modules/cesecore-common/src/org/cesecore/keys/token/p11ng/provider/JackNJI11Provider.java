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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi.PSS;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11ng.MechanismNames;
import org.cesecore.util.StringTools;
import org.pkcs11.jacknji11.CKM;

/**
 * Provider using JackNJI11.
 *
 * @version $Id$
 */
public class JackNJI11Provider extends Provider {

    private static final long serialVersionUID = 7972160215413860118L;

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JackNJI11Provider.class);

    public static final String NAME = "JackNJI11";

    public JackNJI11Provider() {
        super(NAME, 0.3, "JackNJI11 Provider");
 
        putService(new MySigningService(this, "Signature", "NONEwithRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "MD5withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA224withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "NONEwithDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withDSA", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA1withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA256withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA384withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", "SHA512withRSAandMGF1", MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "Signature", AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA, MySignature.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA256", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA384", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "MessageDigest", "SHA512", MyMessageDigiest.class.getName()));
        putService(new MySigningService(this, "AlgorithmParameters", "PSS", MyAlgorithmParameters.class.getName()));
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

        private final JackNJI11Provider provider;
        private final String algorithm;
        private NJI11Object myKey;
        private long session;
        private ByteArrayOutputStream buffer;
        private final int type;
        private boolean hasActiveSession;
        private Exception debugStacktrace;

        // constant for type digesting, we do the hashing ourselves
        private final static int T_DIGEST = 1;
        // constant for type update, token does everything
        private final static int T_UPDATE = 2;
        // constant for type raw, used with NONEwithRSA only
        private final static int T_RAW = 3;
        
        
        public MySignature(Provider provider, String algorithm) {
            super();
            this.provider = (JackNJI11Provider) provider;
            this.algorithm = algorithm;

            if (algorithm.equals("NONEwithRSA")) {
                type = T_RAW;
            } else if (algorithm.contains("ECDSA")) {
                type = T_DIGEST;
            } else {
                type = T_UPDATE;
            }
        }

        @Override
        protected void engineInitVerify(PublicKey pk) throws InvalidKeyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        protected void engineInitSign(PrivateKey pk) throws InvalidKeyException {
            if (!(pk instanceof NJI11Object)) {
                throw new InvalidKeyException("Not an NJI11Object: " + pk);
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
                final long mechanism = MechanismNames.longFromSigAlgoName(this.algorithm).get();
                byte[] param = MechanismNames.CKM_PARAMS.get(mechanism);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("engineInitSign: session: " + session + ", object: " +
                            myKey.getObject() + ", sigAlgoValue: " + mechanism + ", param: " + StringTools.hex(param));
                    debugStacktrace = new Exception();
                }
                myKey.getSlot().getCryptoki().SignInit(session, new CKM(mechanism, param),
                        myKey.getObject());
                log.debug("C_SignInit with mechanism " + mechanism + " successful.");
            } catch (Exception e) {
                log.error("An exception occurred when calling C_SignInit: " + e.getMessage());
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
                    myKey.getSlot().releaseSession(session);
                    hasActiveSession = false;
                }
                throw e;
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            engineUpdate(new byte[]{b}, 0, 1);
        }

        @Override
        protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
            try {
                switch (type) {
                case T_UPDATE:
                    if (offset != 0 || length != bytes.length) {
                        byte[] newArray = Arrays.copyOfRange(bytes, offset, (offset + length));
                        myKey.getSlot().getCryptoki().SignUpdate(session, newArray);
                    } else {
                        myKey.getSlot().getCryptoki().SignUpdate(session, bytes);
                    }
                    break;
                case T_RAW: // No need to call SignUpdate as hash is supplied already
                    buffer = new ByteArrayOutputStream();
                    buffer.write(bytes, offset, length);
                    break;
                case T_DIGEST:
                    if (offset != 0 || length != bytes.length) {
                        final byte[] digest = AlgorithmTools.getDigestFromAlgoName(this.algorithm)
                                .digest(Arrays.copyOfRange(bytes, offset, (offset + length)));
                        buffer = new ByteArrayOutputStream();
                        buffer.write(digest);
                    } else {
                        final byte[] digest = AlgorithmTools.getDigestFromAlgoName(this.algorithm).digest(bytes);
                        buffer = new ByteArrayOutputStream();
                        buffer.write(digest);
                    }
                    break;
                default:
                    throw new ProviderException("Internal error");
                }
            } catch (NoSuchAlgorithmException e) {
                log.error("The signature algorithm " + algorithm + " uses an unknown hashing algorithm.");
                throw new SignatureException(e);
            } catch (IOException e) {
                log.error("I/O exception occurred when writing byte array to output stream (offset = " + offset + "), length = (" + length + ").");
                throw new SignatureException(e);
            } catch (NoSuchProviderException e) {
                log.error("The Bouncy Castle provider has not been installed.");
                throw new SignatureException(e);
            }
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            log.debug("engineSign with " + type);
            try {
                if (type == T_UPDATE) {
                    return myKey.getSlot().getCryptoki().SignFinal(session);
                } else if (type == T_DIGEST) {
                    final byte[] rawSig = myKey.getSlot().getCryptoki().Sign(session, buffer.toByteArray());

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
                } else {
                    return myKey.getSlot().getCryptoki().Sign(session, buffer.toByteArray());
                }
            } catch (IOException e) {
                throw new SignatureException(e);
            } finally {
                // Signing is done, either successful or failed
                if (myKey instanceof NJI11ReleasebleSessionPrivateKey) {
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
        }
        
        @Override
        protected Object engineGetParameter(String string) throws InvalidParameterException {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
        @Override
        protected void finalize() throws Throwable {
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
        public MyAlgorithmParameters(Provider provider, String algorithm) {
            super();
        }
    }
    
    private static class MyMessageDigiest extends MessageDigestSpi {
        // While this MessageDigiest "implementation" doesn't do anything currently, it's required
        // in order for MGF1 Algorithms to work since BC performs a sanity check before
        // creating signatures with PSS parameters. See org.bouncycastle.operator.jcajce.notDefaultPSSParams(...)
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
}
