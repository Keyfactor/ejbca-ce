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
package org.cesecore.keys.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.cvc.PublicKeyEC;

/**
 * Tools to handle common key and keystore operations.
 * 
 * @version $Id$
 */
public final class KeyTools {
    private static final Logger log = Logger.getLogger(KeyTools.class);
    private static final InternalResources intres = InternalResources.getInstance();

    private static final byte[] BAG_ATTRIBUTES = "Bag Attributes\n".getBytes();
    private static final byte[] FRIENDLY_NAME = "    friendlyName: ".getBytes();
    private static final byte[] SUBJECT_ATTRIBUTE = "subject=/".getBytes();
    private static final byte[] ISSUER_ATTRIBUTE = "issuer=/".getBytes();
    private static final byte[] BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----".getBytes();
    private static final byte[] END_CERTIFICATE = "-----END CERTIFICATE-----".getBytes();
    private static final byte[] BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----".getBytes();
    private static final byte[] END_PRIVATE_KEY = "-----END PRIVATE KEY-----".getBytes();
    private static final byte[] NL = "\n".getBytes();

    /**
     * Prevent from creating new KeyTools object
     */
    private KeyTools() {
        // should never be called
    }

    /**
     * Generates a keypair
     * 
     * @param keySpec
     *            string specification of keys to generate, typical value is 2048 for RSA keys,
     *            1024 for DSA keys, secp256r1 for ECDSA keys, or null if algspec is to be used.
     * @param algSpec
     *            AlgorithmParameterSpec of keys to generate, typically an EXParameterSpec for EC keys, or null if keySpec is to be used.
     * @param keyAlg
     *            algorithm of keys to generate, typical value is RSA, DSA or ECDSA, see AlgorithmConstants.KEYALGORITHM_XX
     * 
     * @see org.cesecore.certificates.util.core.model.AlgorithmConstants
     * @see org.bouncycastle.asn1.x9.X962NamedCurves
     * @see org.bouncycastle.asn1.nist.NISTNamedCurves
     * @see org.bouncycastle.asn1.sec.SECNamedCurves
     * 
     * @return KeyPair the generated keypair
     * @throws InvalidAlgorithmParameterException
     * @see org.cesecore.certificates.util.AlgorithmConstants#KEYALGORITHM_RSA
     */
    public static KeyPair genKeys(final String keySpec, final AlgorithmParameterSpec algSpec, final String keyAlg) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">genKeys(" + keySpec + ", " + keyAlg + ")");
        }

        final KeyPairGenerator keygen;
        try {
            keygen = KeyPairGenerator.getInstance(keyAlg, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + keyAlg + " was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            if ((keySpec != null) && !StringUtils.equals(keySpec, "implicitlyCA")) {
                log.debug("Generating named curve ECDSA key pair: " + keySpec);
                // We have EC keys
                ECGenParameterSpec bcSpec = new ECGenParameterSpec(keySpec);
                keygen.initialize(bcSpec, new SecureRandom());
                // The old code should work in BC v1.50b6 and later, but in vesions prior to that the below produces a key with explicit parameter encoding instead of named curves.
                // There is a test for this in KeyToolsTest.testGenKeysECDSAx9
                //                ecSpec = ECNamedCurveTable.getParameterSpec(keySpec);
                //                if (ecSpec == null) {
                //                    throw new InvalidAlgorithmParameterException("keySpec " + keySpec + " is invalid for ECDSA.");
                //                }
                //                keygen.initialize(ecSpec, new SecureRandom());
            } else if (algSpec != null) {
                log.debug("Generating ECDSA key pair from AlgorithmParameterSpec: " + algSpec);
                keygen.initialize(algSpec, new SecureRandom());
            } else if (StringUtils.equals(keySpec, "implicitlyCA")) {
                log.debug("Generating implicitlyCA encoded ECDSA key pair");
                // If the keySpec is null, we have "implicitlyCA" defined EC parameters
                // The parameters were already installed when we installed the provider
                // We just make sure that ecSpec == null here
                keygen.initialize(null, new SecureRandom());
            } else {
                throw new InvalidAlgorithmParameterException("No keySpec no algSpec and no implicitlyCA specified");
            }
        } else if(keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
            final AlgorithmParameterSpec ecSpec;
            if(keySpec != null) {
                log.debug("Generating keys from given key specifications : " + keySpec);
                ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keySpec);
                if(ecSpec == null) throw new InvalidAlgorithmParameterException(
                        "Key specification " + keySpec + " is invalid for ECGOST3410");
            } else if(algSpec != null) {
                log.debug("Generating keys from given algorithm parameters : " + algSpec);
                ecSpec = algSpec;
            } else {
                throw new InvalidAlgorithmParameterException("No key or algorithm specifications");
            }
            keygen.initialize(ecSpec, new SecureRandom());
        } else if(keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
            final AlgorithmParameterSpec ecSpec;
            if(keySpec != null) {
                log.debug("Generating keys from given key specifications : " + keySpec);
                ecSpec = dstuOidToAlgoParams(keySpec);
                if(ecSpec == null) throw new InvalidAlgorithmParameterException(
                        "Key specification " + keySpec + " is invalid for DSTU4145");
            } else if(algSpec != null) {
                log.debug("Generating keys from given algorithm parameters : " + algSpec);
                ecSpec = algSpec;
            } else {
                throw new InvalidAlgorithmParameterException("No key or algorithm specifications");
            }
            keygen.initialize(ecSpec, new SecureRandom());
        } else if (keySpec.startsWith("DSA")) {
            // DSA key with "DSA" in keyspec
            final int keysize = Integer.parseInt(keySpec.substring(3));
            keygen.initialize(keysize);
        } else {
            // RSA or DSA key where keyspec is simply the key length
            final int keysize = Integer.parseInt(keySpec);
            keygen.initialize(keysize);
        }

        final KeyPair keys = keygen.generateKeyPair();

        if (log.isDebugEnabled()) {
            final PublicKey pk = keys.getPublic();
            final int len = getKeyLength(pk);
            log.debug("Generated " + keys.getPublic().getAlgorithm() + " keys with length " + len);
        }
        log.trace("<genKeys()");
        return keys;
    } // genKeys

    /**
     * @see KeyTools#genKeys(String,AlgorithmParameterSpec,String)
     */
    public static KeyPair genKeys(final String keySpec, final String keyAlg) throws InvalidAlgorithmParameterException {
       return genKeys(keySpec, null, keyAlg);
    }

    /**
     * An ECDSA key can be stripped of the curve parameters so it only contains the public point, and this is not enough to use the key for
     * verification. However, if we know the curve name we can fill in the curve parameters and get a usable EC public key
     * 
     * @param pk
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that might miss parameters, if parameters are there we do not touch the public key just return it unchanged
     * @param keySpec
     *            name of curve for example brainpoolp224r1
     * @return PublicKey with parameters from the named curve
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getECPublicKeyWithParams(final PublicKey pk, final String keySpec) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        PublicKey ret = pk;
        if ((pk instanceof PublicKeyEC) && (keySpec != null)) {
            final PublicKeyEC pkec = (PublicKeyEC) pk;
            // The public key of IS and DV certificate do not have any parameters so we have to do some magic to get a complete EC public key
            final ECParameterSpec spec = pkec.getParams();
            if (spec == null) {
                // we did not have the parameter specs, lets create them because we know which curve we are using
                final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(keySpec);
                final java.security.spec.ECPoint p = pkec.getW();
                final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), p, false);
                final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
                final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", "BC");
                ret = keyfact.generatePublic(pubKey);
            }
        }
        return ret;
    }
    /**
     * An ECDSA key can be stripped of the curve parameters so it only contains the public point, and this is not enough to use the key for
     * verification. However, if we know the curve name we can fill in the curve parameters and get a usable EC public key
     * 
     * @param pk
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that might miss parameters, if parameters are there we do not touch the public key just return it unchanged
     * @param pkwithparams
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that contains all parameters.
     * @return PublicKey with parameters from the named curve
     *
     * @throws InvalidKeySpecException if the key specification in pkwithparams was invalid
     */
    public static PublicKey getECPublicKeyWithParams(final PublicKey pk, final PublicKey pkwithparams) throws InvalidKeySpecException {
        if ( !(pk instanceof PublicKeyEC) || !(pkwithparams instanceof PublicKeyEC) ) {
            log.info("Either pk or pkwithparams is not a PublicKeyEC: " + pk.toString() + ", " + pkwithparams.toString());
            return pk;
        }
        final PublicKeyEC pkec = (PublicKeyEC) pk;
        final ECParameterSpec spec = pkec.getParams();
        if (spec != null) {
            return pk;// the key allready has its parameters.
        }
        // The public key of IS and DV certificate do not have any parameters so we have to do some magic to get a complete EC public key
        final PublicKeyEC pkecp = (PublicKeyEC) pkwithparams;
        final ECParameterSpec pkspec = pkecp.getParams();
        if (pkspec == null) {
            log.info("pkwithparams does not have any params.");
            return pk;
        }
        final org.bouncycastle.jce.spec.ECParameterSpec bcspec = EC5Util.convertSpec(pkspec, false);
        final java.security.spec.ECPoint p = pkec.getW();
        final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(pkspec, p, false);
        final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
        final KeyFactory keyfact;
        try {
            keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ECDSA was an unknown algorithm", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        return keyfact.generatePublic(pubKey);
    }

    /**
     * Gets the key length of supported keys
     * 
     * @param pk
     *            PublicKey used to derive the keysize
     * @return -1 if key is unsupported, otherwise a number >= 0. 0 usually means the length can not be calculated, for example if the key is an EC
     *         key and the "implicitlyCA" encoding is used.
     */
    public static int getKeyLength(final PublicKey pk) {
        if (pk instanceof RSAPublicKey) {
            final RSAPublicKey rsapub = (RSAPublicKey) pk;
            return rsapub.getModulus().bitLength();
        }
        if (pk instanceof JCEECPublicKey) {
            final JCEECPublicKey ecpriv = (JCEECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                return spec.getN().bitLength();
            }
            // We support the key, but we don't know the key length
            return 0;
        }
        if (pk instanceof BCECPublicKey) {
            final BCECPublicKey ecpriv = (BCECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                return spec.getN().bitLength();
            }
            // We support the key, but we don't know the key length
            return 0;
        }
        if (pk instanceof ECPublicKey) {
            final ECPublicKey ecpriv = (ECPublicKey) pk;
            final java.security.spec.ECParameterSpec spec = ecpriv.getParams();
            if (spec != null) {
                return spec.getOrder().bitLength(); // does this really return something we expect?
            }
            // We support the key, but we don't know the key length
            return 0;
        }
        if (pk instanceof DSAPublicKey) {
            final DSAPublicKey dsapub = (DSAPublicKey) pk;
            if (dsapub.getParams() != null) {
                return dsapub.getParams().getP().bitLength();
            }
            return dsapub.getY().bitLength();
        }
        // Unknown key type
        return -1;
    }

    /**
     * Gets the key AlgorithmParameterSpec of supported keys. Can be used to initialize a KeyPairGenerator to generate a key of equal type and size.
     * 
     * @param pk
     *            PublicKey used to derive the AlgorithmParameterSpec
     * @return null if key is unsupported or pk is null, otherwise a AlgorithmParameterSpec.
     */
    public static AlgorithmParameterSpec getKeyGenSpec(final PublicKey pk) {
        if (pk == null) {
            return null;
        }
        if (pk instanceof RSAPublicKey) {
            log.debug("getKeyGenSpec: RSA");
            final RSAPublicKey rpk = (RSAPublicKey) pk;
            return new RSAKeyGenParameterSpec(getKeyLength(pk), rpk.getPublicExponent());
        }
        if (pk instanceof DSAPublicKey) {
            log.debug("getKeyGenSpec: DSA");
            final DSAPublicKey dpk = (DSAPublicKey) pk;
            final DSAParams params = dpk.getParams();
            return new DSAParameterSpec(params.getP(), params.getQ(), params.getG());
        }
        if (pk instanceof ECPublicKey) {
            log.debug("getKeyGenSpec: ECPublicKey");
            final ECPublicKey ecpub = (ECPublicKey) pk;
            final java.security.spec.ECParameterSpec sunsp = ecpub.getParams();
            final EllipticCurve ecurve = new EllipticCurve(sunsp.getCurve().getField(), sunsp.getCurve().getA(), sunsp.getCurve().getB());
            // ECParameterSpec par = new ECNamedCurveSpec(null, sunsp.getCurve(), sunsp.getGenerator(), sunsp.getOrder(),
            // BigInteger.valueOf(sunsp.getCofactor()));
            final ECParameterSpec params = new ECParameterSpec(ecurve, sunsp.getGenerator(), sunsp.getOrder(), sunsp.getCofactor());
            if (log.isDebugEnabled()) {
                log.debug("Fieldsize: " + params.getCurve().getField().getFieldSize());
                final EllipticCurve curve = params.getCurve();
                log.debug("CurveA: " + curve.getA().toString(16));
                log.debug("CurveB: " + curve.getB().toString(16));
                log.debug("CurveSeed: " + curve.getSeed());
                final ECFieldFp field = (ECFieldFp) curve.getField();
                log.debug("CurveSfield: " + field.getP().toString(16));
                final ECPoint p = params.getGenerator();
                log.debug("Generator: " + p.getAffineX().toString(16) + ", " + p.getAffineY().toString(16));
                log.debug("Order: " + params.getOrder().toString(16));
                log.debug("CoFactor: " + params.getCofactor());
            }
            return params;
        }
        if (pk instanceof JCEECPublicKey) {
            log.debug("getKeyGenSpec: JCEECPublicKey");
            final JCEECPublicKey ecpub = (JCEECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec bcsp = ecpub.getParameters();
            final ECCurve curve = bcsp.getCurve();
            // TODO: this probably does not work for key generation with the Sun PKCS#11 provider. Maybe seed needs to be set to null as above? Or
            // something else, the BC curve is it the same?
            final ECParameterSpec params = new ECNamedCurveSpec(null, curve, bcsp.getG(), bcsp.getN(), bcsp.getH());
            return params;
            // EllipticCurve ecc = new EllipticCurve(curve.)
            // ECParameterSpec sp = new ECParameterSpec(, bcsp.getG(), bcsp.getN(), bcsp.getH().intValue());
        }
        return null;
    }

    /**
     * Creates PKCS12-file that can be imported in IE or Firefox. The alias for the private key is set to 'privateKey' and the private key password is
     * null.
     * 
     * @param alias
     *            the alias used for the key entry
     * @param privKey
     *            RSA private key
     * @param cert
     *            user certificate
     * @param cacert
     *            CA-certificate or null if only one cert in chain, in that case use 'cert'.
     * 
     * @return KeyStore containing PKCS12-keystore
     * 
     * @exception Exception
     *                if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(final String alias, final PrivateKey privKey, final Certificate cert, final Certificate cacert)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Certificate[] chain;

        if (cacert == null) {
            chain = null;
        } else {
            chain = new Certificate[1];
            chain[0] = cacert;
        }

        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Firefox. The alias for the private key is set to 'privateKey' and the private key password is
     * null.
     * 
     * @param alias
     *            the alias used for the key entry
     * @param privKey
     *            RSA private key
     * @param cert
     *            user certificate
     * @param cacerts
     *            Collection of X509Certificate, or null if only one cert in chain, in that case use 'cert'.
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception
     *                if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(final String alias, final PrivateKey privKey, final Certificate cert, final Collection<Certificate> cacerts)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Certificate[] chain;
        if (cacerts == null) {
            chain = null;
        } else {
            chain = cacerts.toArray(new Certificate[cacerts.size()]);
        }
        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Firefox. The alias for the private key is set to 'privateKey' and the private key password is
     * null.
     * 
     * @param alias
     *            the alias used for the key entry
     * @param privKey
     *            RSA private key
     * @param cert
     *            user certificate
     * @param cachain
     *            CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception
     *                if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(final String alias, final PrivateKey privKey, final Certificate cert, final Certificate[] cachain)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (log.isTraceEnabled()) {
            log.trace(">createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length="
                    + ((cachain == null) ? 0 : cachain.length));
        }
        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        final Certificate[] chain = new Certificate[len];
        // To not get a ClassCastException we need to generate a real new certificate with BC
        final CertificateFactory cf = CertTools.getCertificateFactory();
        chain[0] = cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

        if (cachain != null) {
            for (int i = 0; i < cachain.length; i++) {
                final X509Certificate tmpcert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cachain[i].getEncoded()));
                chain[i + 1] = tmpcert;
            }
        }
        if (chain.length > 1) {
            for (int i = 1; i < chain.length; i++) {
                final X509Certificate cacert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(chain[i].getEncoded()));
                // Set attributes on CA-cert
                try {
                    final PKCS12BagAttributeCarrier caBagAttr = (PKCS12BagAttributeCarrier) chain[i];
                    // We construct a friendly name for the CA, and try with some parts from the DN if they exist.
                    String cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                    // On the ones below we +i to make it unique, O might not be otherwise
                    if (cafriendly == null) {
                        cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "O");
                        if (cafriendly == null) {
                            cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "OU");
                            if (cafriendly == null) {
                                cafriendly = "CA_unknown" + i;
                            } else {
                                cafriendly = cafriendly +i;
                            }
                        } else {
                            cafriendly = cafriendly +i;
                        }
                    }
                    caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(cafriendly));
                } catch (ClassCastException e) {
                    log.error("ClassCastException setting BagAttributes, can not set friendly name: ", e);
                }
            }
        }

        // Set attributes on user-cert
        try {
            final PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier) chain[0];
            certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
            // in this case we just set the local key id to that of the public key
            certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
        } catch (ClassCastException e) {
            log.error("ClassCastException setting BagAttributes, can not set friendly name: ", e);
        }
        try {
        // "Clean" private key, i.e. remove any old attributes
        final KeyFactory keyfact = KeyFactory.getInstance(privKey.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        final PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));
        // Set attributes for private key
            try {
                final PKCS12BagAttributeCarrier keyBagAttr = (PKCS12BagAttributeCarrier) pk;
                // in this case we just set the local key id to that of the public key
                keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
                keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
            } catch (ClassCastException e) {
                log.error("ClassCastException setting BagAttributes, can not set friendly name: ", e);
            }
            // store the key and the certificate chain
            // BC PKCS12 uses 3DES for key protection and 40 bit RC2 for protecting the certificates
            final KeyStore store = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            store.load(null, null);
            store.setKeyEntry(alias, pk, null, chain);
            if (log.isTraceEnabled()) {
                log.trace("<createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length="
                        + ((cachain == null) ? 0 : cachain.length));
            }
            return store;
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not found.", e);
        }
    } // createP12

    /**
     * Creates JKS-file that can be used with JDK. The alias for the private key is set to 'privateKey' and the private key password is null.
     * 
     * @param alias
     *            the alias used for the key entry
     * @param privKey
     *            RSA private key
     * @param password
     *            user's password
     * @param cert
     *            user certificate
     * @param cachain
     *            CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * 
     * @return KeyStore containing JKS-keystore
     * @throws KeyStoreException is storing the certificate failed, perhaps because the alias is already being used?
     * 
     * @exception Exception
     *                if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createJKS(final String alias, final PrivateKey privKey, final String password, final X509Certificate cert,
            final Certificate[] cachain) throws KeyStoreException {
        if (log.isTraceEnabled()) {
            log.trace(">createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length="
                    + ((cachain == null) ? 0 : cachain.length));
        }
        final String caAlias = "cacert";

        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        final Certificate[] chain = new Certificate[len];
        chain[0] = cert;
        if (cachain != null) {
            System.arraycopy(cachain, 0, chain, 1, cachain.length);
        }

        // store the key and the certificate chain
        final KeyStore store;
        try {
            store = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new IllegalStateException("No JKS implementation found in provider", e);
        }
        try {
            store.load(null, null);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        // First load the key entry
        final X509Certificate[] usercert = new X509Certificate[1];
        usercert[0] = cert;
        try {
            store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Keystore apparently hasn't been loaded?", e);
 
        }

        // Add the root cert as trusted
        if (cachain != null) {
            if (!CertTools.isSelfSigned(cachain[cachain.length - 1])) {
                throw new IllegalArgumentException("Root cert is not self-signed.");
            }
            store.setCertificateEntry(caAlias, cachain[cachain.length - 1]);
        }

        // Set the complete chain
        log.debug("Storing cert chain of length " + chain.length);
        store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
        if (log.isTraceEnabled()) {
            log.trace("<createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length="
                    + ((cachain == null) ? 0 : cachain.length));
        }
        return store;
    } // createJKS

    /**
     * Convert a KeyStore to PEM format.
     */
    public static byte[] getSinglePemFromKeyStore(final KeyStore ks, final char[] password) throws KeyStoreException, CertificateEncodingException,
    IOException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        // Find the key private key entry in the keystore
        final Enumeration<String> e = ks.aliases();
        Object o = null;
        String alias = "";
        PrivateKey serverPrivKey = null;
        while (e.hasMoreElements()) {
            o = e.nextElement();
            if (o instanceof String) {
                if ((ks.isKeyEntry((String) o)) && ((serverPrivKey = (PrivateKey) ks.getKey((String) o, password)) != null)) {
                    alias = (String) o;
                    break;
                }
            }
        }

        final byte[] privKeyEncoded = serverPrivKey!=null ? serverPrivKey.getEncoded() : "".getBytes();

        final Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
        final X509Certificate userX509Certificate = (X509Certificate) chain[0];
        {
            final byte[] output = userX509Certificate.getEncoded();
            final String sn = CertTools.getSubjectDN(userX509Certificate);

            final String subjectdnpem = sn.replace(',', '/');
            final String issuerdnpem = CertTools.getIssuerDN(userX509Certificate).replace(',', '/');

            buffer.write(BAG_ATTRIBUTES);
            buffer.write(FRIENDLY_NAME);
            buffer.write(alias.getBytes());
            buffer.write(NL);
            buffer.write(BEGIN_PRIVATE_KEY);
            buffer.write(NL);

            final byte[] privKey = Base64.encode(privKeyEncoded);
            buffer.write(privKey);
            buffer.write(NL);
            buffer.write(END_PRIVATE_KEY);
            buffer.write(NL);
            buffer.write(BAG_ATTRIBUTES);
            buffer.write(FRIENDLY_NAME);
            buffer.write(alias.getBytes());
            buffer.write(NL);
            buffer.write(SUBJECT_ATTRIBUTE);
            buffer.write(subjectdnpem.getBytes());
            buffer.write(NL);
            buffer.write(ISSUER_ATTRIBUTE);
            buffer.write(issuerdnpem.getBytes());
            buffer.write(NL);
            buffer.write(BEGIN_CERTIFICATE);
            buffer.write(NL);

            final byte[] userCertB64 = Base64.encode(output);
            buffer.write(userCertB64);
            buffer.write(NL);
            buffer.write(END_CERTIFICATE);
            buffer.write(NL);
        }
        if (!CertTools.isSelfSigned(userX509Certificate)) {
            for (int num = 1; num < chain.length; num++) {
                final X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                final String sn = CertTools.getSubjectDN(tmpX509Cert);

                final String cnTmp = CertTools.getPartFromDN(sn, "CN");
                final String cn = StringUtils.isEmpty(cnTmp) ? cnTmp : "Unknown";

                final String subjectdnpem = sn.replace(',', '/');
                final String issuerdnpem = CertTools.getIssuerDN(tmpX509Cert).replace(',', '/');

                buffer.write(BAG_ATTRIBUTES);
                buffer.write(FRIENDLY_NAME);
                buffer.write(cn.getBytes());
                buffer.write(NL);
                buffer.write(SUBJECT_ATTRIBUTE);
                buffer.write(subjectdnpem.getBytes());
                buffer.write(NL);
                buffer.write(ISSUER_ATTRIBUTE);
                buffer.write(issuerdnpem.getBytes());
                buffer.write(NL);

                final byte[] tmpOutput = tmpX509Cert.getEncoded();
                buffer.write(BEGIN_CERTIFICATE);
                buffer.write(NL);

                final byte[] tmpCACertB64 = Base64.encode(tmpOutput);
                buffer.write(tmpCACertB64);
                buffer.write(NL);
                buffer.write(END_CERTIFICATE);
                buffer.write(NL);
            }
        }
        return buffer.toByteArray();
    }

    /** @return a buffer with the public key in PEM format */
    public static String getAsPem(final PublicKey publicKey) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try ( final JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(baos)) ) {
            pemWriter.writeObject(publicKey);
        }
        return new String(baos.toByteArray(), "UTF8");
    }

    /**
     * Retrieves the certificate chain from a keystore.
     * 
     * @param keyStore
     *            the keystore, which has been loaded and opened.
     * @param privateKeyAlias
     *            the alias of the privatekey for which the certchain belongs.
     * 
     * @return array of Certificate, or null if no certificates are found.
     */
    public static Certificate[] getCertChain(final KeyStore keyStore, final String privateKeyAlias) throws KeyStoreException {
        if (log.isTraceEnabled()) {
            log.trace(">getCertChain: alias='" + privateKeyAlias + "'");
        }
        final Certificate[] certchain = keyStore.getCertificateChain(privateKeyAlias);
        if (certchain == null) {
            return null;
        }
        log.debug("Certchain retrieved from alias '" + privateKeyAlias + "' has length " + certchain.length);

        if (certchain.length < 1) {
            log.error("Cannot load certificate chain with alias '" + privateKeyAlias + "' from keystore.");
            if (log.isTraceEnabled()) {
                log.trace("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + certchain.length);
            }
            return certchain;
        } else if (certchain.length > 0) {
            if (CertTools.isSelfSigned(certchain[certchain.length - 1])) {
                if (log.isDebugEnabled()) {
                    log.debug("Issuer='" + CertTools.getIssuerDN(certchain[certchain.length - 1]) + "'.");
                    log.debug("Subject='" + CertTools.getSubjectDN(certchain[certchain.length - 1]) + "'.");
                }
                if (log.isTraceEnabled()) {
                    log.trace("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + certchain.length);
                }
                return certchain;
            }
        }

        // If we came here, we have a cert which is not root cert in 'cert'
        final ArrayList<Certificate> array = new ArrayList<>();

        for (int i = 0; i < certchain.length; i++) {
            array.add(certchain[i]);
        }

        while ( true ) {
            final X509Certificate cert = (X509Certificate) array.get(array.size() - 1);
            final String ialias = CertTools.getPartFromDN(CertTools.getIssuerDN(cert), "CN");
            final Certificate[] chain1 = keyStore.getCertificateChain(ialias);

            if (chain1 == null) {
                break;
            }
            if (log.isDebugEnabled()) {
                log.debug("Loaded certificate chain with length " + chain1.length + " with alias '" + ialias + "'.");
            }

            if (chain1.length == 0) {
                log.error("No RootCA certificate found!");
                break;
            }
            boolean isSelfSigned = false;
            for (int j = 0; j < chain1.length && !isSelfSigned; j++) {
                array.add(chain1[j]);

                // If one cert is slefsigned, we have found a root certificate, we don't need to go on anymore
                if (CertTools.isSelfSigned(chain1[j])) {
                    isSelfSigned = true;
                }
            }
            if ( isSelfSigned ) {
                break;
            }
        }

        final Certificate[] ret = new Certificate[array.size()];

        for (int i = 0; i < ret.length; i++) {
            ret[i] = array.get(i);
            if (log.isDebugEnabled()) {
                log.debug("Issuer='" + CertTools.getIssuerDN(ret[i]) + "'.");
                log.debug("Subject='" + CertTools.getSubjectDN(ret[i]) + "'.");
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + ret.length);
        }
        return ret;
    } // getCertChain

    /**
     * create the subject key identifier.
     * 
     * @param pubKey
     *            the public key
     * 
     * @return SubjectKeyIdentifer asn.1 structure
     */
    public static SubjectKeyIdentifier createSubjectKeyId(final PublicKey pubKey) {
        try {
            final ASN1Sequence keyASN1Sequence;
            try( final ASN1InputStream pubKeyAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(pubKey.getEncoded())); ) {
                final Object keyObject = pubKeyAsn1InputStream.readObject();
                if (keyObject instanceof ASN1Sequence) {
                    keyASN1Sequence = (ASN1Sequence) keyObject;
                } else {
                    // PublicKey key that doesn't encode to a ASN1Sequence. Fix this by creating a BC object instead.
                    final PublicKey altKey = (PublicKey) KeyFactory.getInstance(pubKey.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME).translateKey(pubKey);
                    try ( final ASN1InputStream altKeyAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(altKey.getEncoded())) ) {
                        keyASN1Sequence = (ASN1Sequence) altKeyAsn1InputStream.readObject();
                    }
                }
                X509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
                return x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyASN1Sequence));
            }
        } catch (Exception e) {
            final RuntimeException e2 = new RuntimeException("error creating key"); // NOPMD
            e2.initCause(e);
            throw e2;
        }
    } 

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public static boolean isUsingExportableCryptography() {
        return CryptoProviderTools.isUsingExportableCryptography();
    }

    /**
     * Sign provided data with specified private key and algortihm
     * 
     * @param privateKey
     *            the private key
     * @param signatureAlgorithm a valid signature algorithm
     * @param data
     *            the data to sign
     * @return the signature
     */
    public static byte[] signData(final PrivateKey privateKey, final String signatureAlgorithm, final byte[] data) throws SignatureException,
            NoSuchAlgorithmException, InvalidKeyException {
        final Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(privateKey);
        signer.update(data);
        return (signer.sign());
    }

    /**
     * Verify signed data with specified public key, algorith and signature
     * 
     * @param publicKey
     *            the public key
     * @param signatureAlgorithm a valid signature algorithm
     * @param data
     *            the data to verify
     * @param signature
     *            the signature
     * @return true if the signature is ok
     */
    public static boolean verifyData(final PublicKey publicKey, final String signatureAlgorithm, final byte[] data, final byte[] signature)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        final Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initVerify(publicKey);
        signer.update(data);
        return (signer.verify(signature));

    }

    private static class SignDataOperation implements ISignOperation {

        public SignDataOperation( final PrivateKey _key, final byte _dataToBeSigned[] ) {
            this.key = _key;
            this.dataToBeSigned = _dataToBeSigned;
        }
        final private PrivateKey key;
        final private byte dataToBeSigned[];
        private byte[] signatureBV;
        private String signatureAlgorithm;
        @Override
        public void taskWithSigning(String signAlgorithm, Provider provider) throws TaskWithSigningException {
            final Signature signature;
            try {
                signature = Signature.getInstance(signAlgorithm, provider);
                signature.initSign(this.key);
                signature.update(this.dataToBeSigned);
                this.signatureBV = signature.sign();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new TaskWithSigningException(String.format("Signing of data failed: %s", e.getMessage()), e);
            }
            this.signatureAlgorithm = signAlgorithm;
        }
        public byte[] getSignature() {
            return this.signatureBV;
        }
        public String getSignatureAlgorithm() {
            return this.signatureAlgorithm;
        }
    }
    private static Provider getProvider(final String sProvider) {
        if ( sProvider==null ) {
            return Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        final Provider provider = Security.getProvider(sProvider);
        if ( provider!=null ) {
            return provider;
        }
        return Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
    /**
     * Testing a key pair to verify that it is possible to first sign and then verify with it.
     * 
     * @param priv
     *            private key to sign a string with
     * @param pub
     *            public key to verify the signature with
     * @param sProvider
     *            A provider used for signing with the private key, or null if "BC" should be used.
     * 
     * @throws InvalidKeyException
     *             if the public key can not be used to verify a string signed by the private key, because the key is wrong or the signature operation
     *             fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws TaskWithSigningException 
     * @throws NoSuchProviderException
     *             if the provider is not installed.
     */
    public static void testKey(final PrivateKey priv, final PublicKey pub, final String sProvider) throws InvalidKeyException { // NOPMD:this is not a junit test
        final byte input[] = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        final byte signBV[];
        final String testSigAlg;
        try {
            if (log.isDebugEnabled()) {
                final StringWriter sw = new StringWriter();
                try( final PrintWriter pw = new PrintWriter(sw) ) {
                    pw.println("Testing a key:");
                    pw.println(String.format("\tTesting keys with algorithm: %s", pub.getAlgorithm()));
                    pw.println(String.format("\tprovider: %s", sProvider));
                    pw.println(String.format("\tprivateKey: %s", priv));
                    pw.println(String.format("\tprivateKey class: %s", priv.getClass().getName()));
                    pw.println(String.format("\tpublicKey: %s", pub));
                    pw.println(String.format("\tpublicKey class: %s", pub.getClass().getName()));
                    pw.flush();
                }
                log.debug(sw.toString());
            }
            {
                final SignDataOperation operation = new SignDataOperation(priv, input);
                // Candidate algorithms. The first working one will be selected by SignWithWorkingAlgorithm
                final List<String> availableSignAlgorithms = AlgorithmTools.getSignatureAlgorithms(pub);
                SignWithWorkingAlgorithm.doSignTask(availableSignAlgorithms, getProvider(sProvider), operation);
                signBV = operation.getSignature();
                testSigAlg = operation.getSignatureAlgorithm();
                if (signBV == null) {
                    throw new InvalidKeyException("Result from signing is null.");
                }
                if (log.isDebugEnabled()) {
                    log.trace("Created signature of size: " + signBV.length);
                    log.trace("Created signature: " + new String(Hex.encode(signBV)));
                }
            }
            {
                final Signature signature;
                try {
                    signature = Signature.getInstance(testSigAlg, "BC");
                } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
                    throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
                }
                signature.initVerify(pub);
                signature.update(input);
                if (!signature.verify(signBV)) {
                    throw new InvalidKeyException("Signature was not correctly verified.");
                }
            }
        } catch ( InvalidKeyException e ) {
            throw e;
        } catch (  TaskWithSigningException | SignatureException e ) {
            throw new InvalidKeyException(String.format("Exception testing key: %s", e.getMessage()), e);
        }
    }

    /**
     * Print parameters of public part of a key.
     * 
     * @param publK
     *            the key
     * @param ps
     *            stream to print to.
     */
    public static void printPublicKeyInfo(final PublicKey publK, final PrintStream ps) {
        if (publK instanceof RSAPublicKey) {
            ps.println("RSA key:");
            final RSAPublicKey rsa = (RSAPublicKey) publK;
            ps.println("  modulus: " + rsa.getModulus().toString(16));
            ps.println("  public exponent: " + rsa.getPublicExponent().toString(16));
            return;
        }
        if (publK instanceof ECPublicKey) {
            ps.println("Elliptic curve key:");
            final ECPublicKey ec = (ECPublicKey) publK;
            ps.println("  Named curve: "+AlgorithmTools.getKeySpecification(ec));
            ps.println("  the affine x-coordinate: " + ec.getW().getAffineX().toString(16));
            ps.println("  the affine y-coordinate: " + ec.getW().getAffineY().toString(16));
            return;
        }
        if (publK instanceof DHPublicKey) {
            ps.println("DH key:");
            final DHPublicKey dh = (DHPublicKey) publK;
            ps.println("  the public value y: " + dh.getY().toString(16));
            return;
        }
        if (publK instanceof DSAPublicKey) {
            ps.println("DSA key:");
            final DSAPublicKey dsa = (DSAPublicKey) publK;
            ps.println("  the public value y: " + dsa.getY().toString(16));
            return;
        }
    }

    /**
     * Test if a private key is extractable (could be stored).
     * 
     * @param privK
     *            key to test.
     * @return true if the key is extractable.
     */
    public static boolean isPrivateKeyExtractable(final PrivateKey privK) {
        if (privK instanceof RSAPrivateKey) {
            final RSAPrivateKey rsa = (RSAPrivateKey) privK;
            final BigInteger result = rsa.getPrivateExponent();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof ECPrivateKey) {
            final ECPrivateKey ec = (ECPrivateKey) privK;
            final BigInteger result = ec.getS();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof DHPrivateKey) {
            final DHPrivateKey dh = (DHPrivateKey) privK;
            final BigInteger result = dh.getX();
            return result != null && result.bitLength() > 0;
        }
        if (privK instanceof DSAPrivateKey) {
            final DSAPrivateKey dsa = (DSAPrivateKey) privK;
            final BigInteger result = dsa.getX();
            return result != null && result.bitLength() > 0;
        }
        return false;
    }

    public static void checkValidKeyLength(String keyspec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        final String keyAlg = keyspecToKeyalg(keyspec);
        final int len;
        if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
            len = Integer.parseInt(keyspec); 
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
            len = Integer.parseInt(keyspec.substring(3));
        } else {
            // Assume it's elliptic curve
            final KeyPair kp = KeyTools.genKeys(keyspec, keyAlg);
            len = KeyTools.getKeyLength(kp.getPublic());
        }
        checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(final PublicKey pk) throws InvalidKeyException {
        final String keyAlg = AlgorithmTools.getKeyAlgorithm(pk);
        final int len = KeyTools.getKeyLength(pk);
        checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(final String keyAlg, final int len) throws InvalidKeyException {
        final boolean isEcdsa = AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlg);
        final boolean isGost3410 = AlgorithmTools.isGost3410Enabled() && AlgorithmConstants.KEYALGORITHM_ECGOST3410.equals(keyAlg);
        final boolean isDstu4145 = AlgorithmTools.isDstu4145Enabled() && keyAlg.startsWith(CesecoreConfiguration.getOidDstu4145()+".");
        if (isEcdsa || isGost3410 || isDstu4145) {
            // We allow key lengths of 0, because that means that implicitlyCA is used. 
            // for ImplicitlyCA we have no idea what the key length is, on the other hand only real professionals
            // will ever use that to we will allow it.
            if ((len > 0) && (len < 224)) {
                final String msg = intres.getLocalizedMessage("catoken.invalidkeylength", "ECDSA", "224", Integer.valueOf(len));
                throw new InvalidKeyException(msg);
            }                            
        } else if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlg) || AlgorithmConstants.KEYALGORITHM_DSA.equals(keyAlg)) {
            if (len < 1024) {
                final String msg = intres.getLocalizedMessage("catoken.invalidkeylength", "RSA/DSA", "1024", Integer.valueOf(len));
                throw new InvalidKeyException(msg);
            }
        }
    }
    
    /**
     * Gets the parameter spec from a given OID of a DSTU curve (they don't have names) 
     */
    public static AlgorithmParameterSpec dstuOidToAlgoParams(String dstuOid) {
        return new ECGenParameterSpec(dstuOid);
    }
    
    public static String keyspecToKeyalg(String keyspec) {
        if (StringUtils.isNumeric(keyspec)) {
            return AlgorithmConstants.KEYALGORITHM_RSA;
        }
        if (keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_RSA)) {
            return AlgorithmConstants.KEYALGORITHM_RSA;
        }
        if (keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_DSA)) {
            return AlgorithmConstants.KEYALGORITHM_DSA;
        }
        if (AlgorithmTools.isGost3410Enabled() && keyspec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
            return AlgorithmConstants.KEYALGORITHM_ECGOST3410;
        }
        if (AlgorithmTools.isDstu4145Enabled() && keyspec.startsWith(CesecoreConfiguration.getOidDstu4145()+".")) {
            return AlgorithmConstants.KEYALGORITHM_DSTU4145;
        }
        return AlgorithmConstants.KEYALGORITHM_ECDSA;
    }
    
    /**
     * Converts a standalone specspec that starts with the keyalg to a short keyspec which
     * is to be used together with a separate "keyalg" value.
     */
    public static String shortenKeySpec(String keyspec) {
        if (keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_DSA) || keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_RSA) ) {
            return keyspec.substring(3);
        }
        return keyspec;
    }
    
    /**
     * Converts a keyalg/keyspec pair into a standalone specspec.
     */
    public static String keyalgspecToKeyspec(String keyalg, String keyspec) {
        if ("DSA".equals(keyalg)) {
            return "DSA" + keyspec;
        }
        return keyspec;
    }

    /** 
     * Get the ASN.1 encoded PublicKey as a Java PublicKey Object.
     * @param the ASN.1 encoded PublicKey
     * @return the ASN.1 encoded PublicKey as a Java Object
     */
    public static PublicKey getPublicKeyFromBytes(byte[] asn1EncodedPublicKey) {
        try {
            final SubjectPublicKeyInfo keyInfo;
            keyInfo = SubjectPublicKeyInfo.getInstance(asn1EncodedPublicKey);
            final AlgorithmIdentifier keyAlg = keyInfo.getAlgorithm();
            final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(keyInfo).getBytes());
            final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            return keyFact.generatePublic(xKeySpec);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            log.debug("Unable to decode PublicKey.", e);
        }
        return null;
    }
    
    /**
     * Extracts the binary data from a PEM of a specified kind, e.g. public key.
     *  
     * @param pem PEM data to extract from. May contain other types of data as well.
     * @param beginMarker E.g. CertTools.BEGIN_PUBLIC_KEY
     * @param endMarker E.g. CertTools.END_PUBLIC_KEY
     * @return The first entry of the matching type, or null if it couldn't be parsed.
     */
    public static byte[] getBytesFromPEM(String pem, String beginMarker, String endMarker) {
        final int start = pem.indexOf(beginMarker);
        final int end = pem.indexOf(endMarker, start);
        if (start == -1 || end == -1) {
            log.debug("Could not find "+beginMarker+" and "+endMarker+" lines in PEM");
            return null;
        }
        
        final String base64 = pem.substring(start + beginMarker.length(), end);
        try {
            return Base64.decode(base64.getBytes("ASCII"));
        } catch (UnsupportedEncodingException e) {
            log.debug(String.format("Invalid byte in PEM data: %s", e.getMessage()));
            return null;
        }
    }
    
    /**
     * Extracts the binary DER data from a public key file. The file may be either in PEM format
     * or in DER format. In the latter case, the file contents is returned as-is.
     *  
     * @param file Data of a PEM or DER file.
     * @return DER encoded public key.
     * @throws CertificateParsingException If the data isn't a public key in either PEM or DER format.
     */
    public static byte[] getBytesFromPublicKeyFile(final byte[] file) throws CertificateParsingException {
        final String fileText = Charset.forName("ASCII").decode(java.nio.ByteBuffer.wrap(file)).toString();
        final byte[] asn1bytes;
        {
            final byte[] tmpBytes = getBytesFromPEM(fileText, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
            asn1bytes = tmpBytes!=null ? tmpBytes : file; // Assume it's in ASN1 format already if null
        }
        try {
            PublicKeyFactory.createKey(asn1bytes); // Check that it's a valid public key
            return asn1bytes;
        } catch (IOException e) {
            throw new CertificateParsingException(e);
        }
    }
}
