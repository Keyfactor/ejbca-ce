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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
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
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.cvc.PublicKeyEC;

/**
 * Tools to handle common key and keystore operations.
 * 
 * @version $Id$
 */
public final class KeyTools {
    private static final Logger log = Logger.getLogger(KeyTools.class);
    private static final InternalResources intres = InternalResources.getInstance();

    /** The name of Suns pkcs11 implementation */
    public static final String SUNPKCS11CLASS = "sun.security.pkcs11.SunPKCS11";
    public static final String IAIKPKCS11CLASS = "iaik.pkcs.pkcs11.provider.IAIKPkcs11";
    public static final String IAIKJCEPROVIDERCLASS = "iaik.security.provider.IAIK";

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
     *            string specification of keys to generate, typical value is 1024 for RSA or DSA keys, or secp256r1 for ECDSA keys or null of algspec
     *            is to be used.
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
     * @see org.cesecore.certificates.util.core.model.AlgorithmConstants#KEYALGORITHM_RSA
     */
    public static KeyPair genKeys(final String keySpec, final AlgorithmParameterSpec algSpec, final String keyAlg) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">genKeys(" + keySpec + ", " + keyAlg + ")");
        }

        final KeyPairGenerator keygen = KeyPairGenerator.getInstance(keyAlg, "BC");
        if (StringUtils.equals(keyAlg, AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            AlgorithmParameterSpec ecSpec = null;
            if ((keySpec != null) && !StringUtils.equals(keySpec, "implicitlyCA")) {
                log.debug("Generating named curve ECDSA key pair: " + keySpec);
                // We have EC keys
                ecSpec = ECNamedCurveTable.getParameterSpec(keySpec);
                if (ecSpec == null) {
                    throw new InvalidAlgorithmParameterException("keySpec " + keySpec + " is invalid for ECDSA.");
                }
            } else if (algSpec != null) {
                log.debug("Generating ECDSA key pair from AlgorithmParameterSpec: " + algSpec);
                ecSpec = algSpec;
            } else if (StringUtils.equals(keySpec, "implicitlyCA")) {
                log.debug("Generating implicitlyCA encoded ECDSA key pair");
                // If the keySpec is null, we have "implicitlyCA" defined EC parameters
                // The parameters were already installed when we installed the provider
                // We just make sure that ecSpec == null here
            } else {
                throw new InvalidAlgorithmParameterException("No keySpec no algSpec and no implicitlyCA specified");
            }
            keygen.initialize(ecSpec, new SecureRandom());
        } else {
            // RSA or DSA keys
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
    public static KeyPair genKeys(final String keySpec, final String keyAlg) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
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
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getECPublicKeyWithParams(final PublicKey pk, final PublicKey pkwithparams) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        PublicKey ret = pk;
        if ((pk instanceof PublicKeyEC) && (pkwithparams instanceof PublicKeyEC)) {
            final PublicKeyEC pkec = (PublicKeyEC) pk;
            // The public key of IS and DV certificate do not have any parameters so we have to do some magic to get a complete EC public key
            final ECParameterSpec spec = pkec.getParams();
            if (spec == null) {
                final PublicKeyEC pkecp = (PublicKeyEC) pkwithparams;
                final ECParameterSpec pkspec = pkecp.getParams();
                if (pkspec != null) {
                    final org.bouncycastle.jce.spec.ECParameterSpec bcspec = EC5Util.convertSpec(pkspec, false);
                    final java.security.spec.ECPoint p = pkec.getW();
                    final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(pkspec, p, false);
                    final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
                    final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", "BC");
                    ret = keyfact.generatePublic(pubKey);
                } else {
                    log.info("pkwithparams does not have any params.");
                }
            }
        } else {
            log.info("Either pk or pkwithparams is not a PublicKeyEC: " + pk.toString() + ", " + pkwithparams.toString());
        }
        return ret;
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
        int len = -1;
        if (pk instanceof RSAPublicKey) {
            final RSAPublicKey rsapub = (RSAPublicKey) pk;
            len = rsapub.getModulus().bitLength();
        } else if (pk instanceof JCEECPublicKey) {
            final JCEECPublicKey ecpriv = (JCEECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                len = spec.getN().bitLength();
            } else {
                // We support the key, but we don't know the key length
                len = 0;
            }
        } else if (pk instanceof BCECPublicKey) {
            final BCECPublicKey ecpriv = (BCECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
            if (spec != null) {
                len = spec.getN().bitLength();
            } else {
                // We support the key, but we don't know the key length
                len = 0;
            }
        } else if (pk instanceof ECPublicKey) {
            final ECPublicKey ecpriv = (ECPublicKey) pk;
            final java.security.spec.ECParameterSpec spec = ecpriv.getParams();
            if (spec != null) {
                len = spec.getOrder().bitLength(); // does this really return something we expect?
            } else {
                // We support the key, but we don't know the key length
                len = 0;
            }
        } else if (pk instanceof DSAPublicKey) {
            final DSAPublicKey dsapub = (DSAPublicKey) pk;
            if (dsapub.getParams() != null) {
                len = dsapub.getParams().getP().bitLength();
            } else {
                len = dsapub.getY().bitLength();
            }
        }
        return len;
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
        AlgorithmParameterSpec ret = null;
        if (pk instanceof RSAPublicKey) {
            log.debug("getKeyGenSpec: RSA");
            final RSAPublicKey rpk = (RSAPublicKey) pk;
            ret = new RSAKeyGenParameterSpec(getKeyLength(pk), rpk.getPublicExponent());
        } else if (pk instanceof DSAPublicKey) {
            log.debug("getKeyGenSpec: DSA");
            final DSAPublicKey dpk = (DSAPublicKey) pk;
            final DSAParams params = dpk.getParams();
            ret = new DSAParameterSpec(params.getP(), params.getQ(), params.getG());
        } else if (pk instanceof ECPublicKey) {
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
            ret = params;
        } else if (pk instanceof JCEECPublicKey) {
            log.debug("getKeyGenSpec: JCEECPublicKey");
            final JCEECPublicKey ecpub = (JCEECPublicKey) pk;
            final org.bouncycastle.jce.spec.ECParameterSpec bcsp = ecpub.getParameters();
            final ECCurve curve = bcsp.getCurve();
            // TODO: this probably does not work for key generation with the Sun PKCS#11 provider. Maybe seed needs to be set to null as above? Or
            // something else, the BC curve is it the same?
            final ECParameterSpec params = new ECNamedCurveSpec(null, curve, bcsp.getG(), bcsp.getN(), bcsp.getH());
            ret = params;
            // EllipticCurve ecc = new EllipticCurve(curve.)
            // ECParameterSpec sp = new ECParameterSpec(, bcsp.getG(), bcsp.getN(), bcsp.getH().intValue());
        }
        return ret;
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
            throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;

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
            throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;
        if (cacerts == null) {
            chain = null;
        } else {
            chain = new Certificate[cacerts.size()];
            chain = (Certificate[]) cacerts.toArray(chain);
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
            throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
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
        // "Clean" private key, i.e. remove any old attributes
        final KeyFactory keyfact = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
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
        final KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry(alias, pk, null, chain);
        if (log.isTraceEnabled()) {
            log.trace("<createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length="
                    + ((cachain == null) ? 0 : cachain.length));
        }
        return store;
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
     * 
     * @exception Exception
     *                if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createJKS(final String alias, final PrivateKey privKey, final String password, final X509Certificate cert,
            final Certificate[] cachain) throws Exception {
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
        final KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);

        // First load the key entry
        final X509Certificate[] usercert = new X509Certificate[1];
        usercert[0] = cert;
        store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);

        // Add the root cert as trusted
        if (cachain != null) {
            if (!CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
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

        byte[] privKeyEncoded = "".getBytes();

        if (serverPrivKey != null) {
            privKeyEncoded = serverPrivKey.getEncoded();
        }

        final Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
        final X509Certificate userX509Certificate = (X509Certificate) chain[0];

        final byte[] output = userX509Certificate.getEncoded();
        String sn = CertTools.getSubjectDN(userX509Certificate);

        String subjectdnpem = sn.replace(',', '/');
        String issuerdnpem = CertTools.getIssuerDN(userX509Certificate).replace(',', '/');

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

        if (!CertTools.isSelfSigned(userX509Certificate)) {
            for (int num = 1; num < chain.length; num++) {
                final X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                sn = CertTools.getSubjectDN(tmpX509Cert);

                String cn = CertTools.getPartFromDN(sn, "CN");
                if (StringUtils.isEmpty(cn)) {
                    cn = "Unknown";
                }

                subjectdnpem = sn.replace(',', '/');
                issuerdnpem = CertTools.getIssuerDN(tmpX509Cert).replace(',', '/');

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
        final PEMWriter pemWriter = new PEMWriter(new OutputStreamWriter(baos));
        pemWriter.writeObject(publicKey);
        pemWriter.close();
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
            if (CertTools.isSelfSigned((X509Certificate) certchain[certchain.length - 1])) {
                if (log.isDebugEnabled()) {
                    log.debug("Issuer='" + CertTools.getIssuerDN((X509Certificate) certchain[certchain.length - 1]) + "'.");
                    log.debug("Subject='" + CertTools.getSubjectDN((X509Certificate) certchain[certchain.length - 1]) + "'.");
                }
                if (log.isTraceEnabled()) {
                    log.trace("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + certchain.length);
                }
                return certchain;
            }
        }

        // If we came here, we have a cert which is not root cert in 'cert'
        final ArrayList<Certificate> array = new ArrayList<Certificate>();

        for (int i = 0; i < certchain.length; i++) {
            array.add(certchain[i]);
        }

        boolean stop = false;

        while (!stop) {
            final X509Certificate cert = (X509Certificate) array.get(array.size() - 1);
            final String ialias = CertTools.getPartFromDN(CertTools.getIssuerDN(cert), "CN");
            final Certificate[] chain1 = keyStore.getCertificateChain(ialias);

            if (chain1 == null) {
                stop = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Loaded certificate chain with length " + chain1.length + " with alias '" + ialias + "'.");
                }

                if (chain1.length == 0) {
                    log.error("No RootCA certificate found!");
                    stop = true;
                }

                for (int j = 0; j < chain1.length; j++) {
                    array.add(chain1[j]);

                    // If one cert is slefsigned, we have found a root certificate, we don't need to go on anymore
                    if (CertTools.isSelfSigned((X509Certificate) chain1[j])) {
                        stop = true;
                    }
                }
            }
        }

        final Certificate[] ret = new Certificate[array.size()];

        for (int i = 0; i < ret.length; i++) {
            ret[i] = (X509Certificate) array.get(i);
            if (log.isDebugEnabled()) {
                log.debug("Issuer='" + CertTools.getIssuerDN((X509Certificate) ret[i]) + "'.");
                log.debug("Subject='" + CertTools.getSubjectDN((X509Certificate) ret[i]) + "'.");
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
            final Object keyObject = new ASN1InputStream(new ByteArrayInputStream(pubKey.getEncoded())).readObject();
            if (keyObject instanceof ASN1Sequence) {
                keyASN1Sequence = (ASN1Sequence) keyObject;
            } else {
                // PublicKey key that don't encode to a ASN1Sequence. Fix this by creating a BC object instead.
                final PublicKey altKey = (PublicKey) KeyFactory.getInstance(pubKey.getAlgorithm(), "BC").translateKey(pubKey);
                keyASN1Sequence = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(altKey.getEncoded())).readObject();
            }
            return new SubjectKeyIdentifier(new SubjectPublicKeyInfo(keyASN1Sequence));
        } catch (Exception e) {
            final RuntimeException e2 = new RuntimeException("error creating key"); // NOPMD
            e2.initCause(e);
            throw e2;
        }
    } // createSubjectKeyId

    /**
     * Creates a SUN or IAIK PKCS#11 provider using the passed in pkcs11 library. First we try to see if the IAIK provider is available, because it
     * supports more algorithms. If the IAIK provider is not available in the classpath, we try the SUN provider.
     * 
     * @param slot
     *            pkcs11 slot number or null if a config file name is provided as fileName
     * @param fileName
     *            the manufacturers provided pkcs11 library (.dll or .so) or config file name if slot is null
     * @param isIndex
     *            specifies if the slot is a slot number or a slotIndex
     * @param attributesFile
     *            a file specifying PKCS#11 attributes (used mainly for key generation) in the format specified in the
     *            "JavaTM PKCS#11 Reference Guide", http://java.sun.com/javase/6/docs/technotes/guides/security/p11guide.html
     * 
     *            Example contents of attributes file:
     * 
     *            attributes(generate,CKO_PRIVATE_KEY,*) = { CKA_PRIVATE = true CKA_SIGN = true CKA_DECRYPT = true CKA_TOKEN = true }
     * 
     *            See also html documentation for PKCS#11 HSMs in EJBCA.
     * 
     * @return AuthProvider of type "sun.security.pkcs11.SunPKCS11" or
     * @throws IOException
     *             if the pkcs11 library can not be found, or the PKCS11 provider can not be created.
     */
    public static Provider getP11Provider(final String slot, final String fileName, final boolean isIndex, final String attributesFile)
            throws IOException {
        if (StringUtils.isEmpty(fileName)) {
            throw new IOException("A file name must be supplied.");
        }
        final File libFile = new File(fileName);
        if (!libFile.isFile() || !libFile.canRead()) {
            throw new IOException("The file " + fileName + " can't be read.");
        }
        if (slot == null) {
            return getP11Provider(new FileInputStream(fileName), null);
        }
        // Properties for the SUN PKCS#11 provider
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final PrintWriter pw = new PrintWriter(baos);
        pw.println("name = " + libFile.getName() + "-slot" + slot);
        pw.println("library = " + libFile.getCanonicalPath());

        final int slotNr;
        try {
            if (slot.length() > 0) {
                slotNr = Integer.parseInt(slot);
            } else {
                slotNr = -1;
            }
        } catch (NumberFormatException e) {
            throw new IOException("Slot nr " + slot + " not an integer.");
        }
        if (slotNr >= 0) {
            pw.println("slot" + (isIndex ? "ListIndex" : "") + " = " + slot);
        }
        if (attributesFile != null) {
            byte[] attrs = FileTools.readFiletoBuffer(attributesFile);
            pw.println(new String(attrs));
        } else {
            // setting the attributes like this should work for most HSMs.
            pw.println("attributes(*, *, *) = {");
            pw.println("  CKA_TOKEN = true"); // all created objects should be permanent. They should not only exiswt during the session.
            pw.println("}");
            pw.println("attributes(*, CKO_PUBLIC_KEY, *) = {");
            pw.println("  CKA_ENCRYPT = true");
            pw.println("  CKA_VERIFY = true");
            pw.println("  CKA_WRAP = true");// no harm allowing wrapping of keys. created private keys can not be wrapped anyway since CKA_EXTRACTABLE
                                            // is false.
            pw.println("}");
            pw.println("attributes(*, CKO_PRIVATE_KEY, *) = {");
            pw.println("  CKA_PRIVATE = true"); // always require logon with password to use the key
            pw.println("  CKA_SENSITIVE = true"); // not possible to read the key
            pw.println("  CKA_EXTRACTABLE = false"); // not possible to wrap the key with another key
            pw.println("  CKA_DECRYPT = true");
            pw.println("  CKA_SIGN = true");
            pw.println("  CKA_UNWRAP = true");// for unwrapping of session keys,
            pw.println("}");
            pw.println("attributes(*, CKO_SECRET_KEY, *) = {");
            pw.println("  CKA_SENSITIVE = true"); // not possible to read the key
            pw.println("  CKA_EXTRACTABLE = false"); // not possible to wrap the key with another key
            pw.println("  CKA_ENCRYPT = true");
            pw.println("  CKA_DECRYPT = true");
            pw.println("  CKA_SIGN = true");
            pw.println("  CKA_VERIFY = true");
            pw.println("  CKA_WRAP = true");// for unwrapping of session keys,
            pw.println("  CKA_UNWRAP = true");// for unwrapping of session keys,
            pw.println("}");
        }
        pw.flush();
        pw.close();
        if (log.isDebugEnabled()) {
            log.debug(baos.toString());
        }

        // Properties for the IAIK PKCS#11 provider
        final Properties prop = new Properties();
        prop.setProperty("PKCS11_NATIVE_MODULE", libFile.getCanonicalPath());
        // If using Slot Index it is denoted by brackets in iaik
        prop.setProperty("SLOT_ID", isIndex ? ("[" + slot + "]") : slot);
        if (log.isDebugEnabled()) {
            log.debug(prop.toString());
        }
        return getP11Provider(new ByteArrayInputStream(baos.toByteArray()), prop);
    }

    /**
     * 
     * @param is
     *            for the SUN PKCS#11 provider
     * @param prop
     *            for the IAIK PKCS#11 provider
     * @return Java security Provider for a PCKS#11 token
     * @throws IOException
     *             if neither the IAIK or the SUN provider can be created
     */

    private static Provider getP11Provider(final InputStream is, final Properties prop) throws IOException {

        // We will construct the PKCS11 provider (sun.security..., or iaik...) using reflection, because
        // the sun class does not exist on all platforms in jdk5, and we want to be able to compile everything.
        // The below code replaces the single line (for the SUN provider):
        // return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));

        // We will first try to construct the more competent IAIK provider, if it exists in the classpath
        // if that does not exist, we will revert back to use the SUN provider
        Provider ret = null;
        if (prop != null) {
            try {
                @SuppressWarnings("unchecked")
                final Class<? extends Provider> implClass = (Class<? extends Provider>) Class.forName(IAIKPKCS11CLASS);
                log.info("Using IAIK PKCS11 provider: " + IAIKPKCS11CLASS);
                // iaik PKCS11 has Properties as constructor argument
                ret = implClass.getConstructor(Properties.class).newInstance(new Object[] { prop });
                // It's not enough just to add the p11 provider. Depending on algorithms we may have to install the IAIK JCE provider as well in order
                // to support algorithm delegation
                @SuppressWarnings("unchecked")
                final Class<? extends Provider> jceImplClass = (Class<? extends Provider>) Class.forName(KeyTools.IAIKJCEPROVIDERCLASS);
                Provider iaikProvider = jceImplClass.getConstructor().newInstance();
                if (Security.getProvider(iaikProvider.getName()) == null) {
                    log.info("Adding IAIK JCE provider for Delegation: " + KeyTools.IAIKJCEPROVIDERCLASS);
                    Security.addProvider(iaikProvider);
                }
            } catch (Exception e) {
                // do nothing here. Sun provider is tested below.
            }
        }
        if (ret == null) {
            try {
                // Sun PKCS11 has InputStream as constructor argument
                @SuppressWarnings("unchecked")
                final Class<? extends Provider> implClass = (Class<? extends Provider>) Class.forName(SUNPKCS11CLASS);
                log.info("Using SUN PKCS11 provider: " + SUNPKCS11CLASS);
                ret = implClass.getConstructor(InputStream.class).newInstance(new Object[] { is });
            } catch (Exception e) {
                log.error("Error constructing pkcs11 provider: " + e.getMessage());
                final IOException ioe = new IOException("Error constructing pkcs11 provider: " + e.getMessage());
                ioe.initCause(e);
                throw ioe;
            }
        }
        return ret;
    }

    /**
     * @param is
     *            InputStream for sun configuration file.
     * @return The Sun provider
     * @throws IOException
     */
    public static Provider getSunP11Provider(final InputStream is) throws IOException {
        return getP11Provider(is, null);
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
     * @param signatureAlgorithm
     *            e.g. as returned by caToken.getCATokenInfo().getSignatureAlgorithm()
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
     * @param signatureAlgorithm
     *            e.g. as returned by caToken.getCATokenInfo().getSignatureAlgorithm()
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

    /**
     * Testing a key pair to verify that it is possible to first sign and then verify with it.
     * 
     * @param priv
     *            private key to sign a string with
     * @param pub
     *            public key to verify the signature with
     * @param provider
     *            A provider used for signing with the private key, or null if "BC" should be used.
     * 
     * @throws InvalidKeyException
     *             if the public key can not be used to verify a string signed by the private key, because the key is wrong or the signature operation
     *             fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws NoSuchProviderException
     *             if the provider is not installed.
     */
    public static void testKey(final PrivateKey priv, final PublicKey pub, final String provider) throws InvalidKeyException, NoSuchProviderException { // NOPMD:this is not a junit test
        final byte input[] = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        final byte signBV[];
        final String testSigAlg;
        {
            final Iterator<String> i = AlgorithmTools.getSignatureAlgorithms(pub).iterator();
            final String tmp = i.hasNext() ? i.next() : null;
            testSigAlg = tmp != null ? tmp : "SHA1WithRSA";
        }
        if (log.isDebugEnabled()) {
            log.debug("Testing keys with algorithm: " + pub.getAlgorithm());
            log.debug("testSigAlg: " + testSigAlg);
            log.debug("provider: " + provider);
            log.trace("privateKey: " + priv);
            log.trace("privateKey class: " + priv.getClass().getName());
            log.trace("publicKey: " + pub);
            log.trace("publicKey class: " + pub.getClass().getName());
        }
        try {
            {
                final Provider prov = Security.getProvider(provider != null ? provider : "BC");
                final Signature signature = Signature.getInstance(testSigAlg, prov);
                signature.initSign(priv);
                signature.update(input);
                signBV = signature.sign();
                if (signBV == null) {
                    throw new InvalidKeyException("Result from signing is null.");
                }
                if (log.isDebugEnabled()) {
                    log.trace("Created signature of size: " + signBV.length);
                    log.trace("Created signature: " + new String(Hex.encode(signBV)));
                }
            }
            {
                final Signature signature = Signature.getInstance(testSigAlg, "BC");
                signature.initVerify(pub);
                signature.update(input);
                if (!signature.verify(signBV)) {
                    throw new InvalidKeyException("Not possible to sign and then verify with key pair.");
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Exception testing key: " + e.getMessage(), e);
        } catch (SignatureException e) {
            throw new InvalidKeyException("Exception testing key: " + e.getMessage(), e);
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

    public static void checkValidKeyLength(String keyspec) throws InvalidKeyException, NoSuchAlgorithmException,
    NoSuchProviderException, InvalidAlgorithmParameterException {
        String keyAlg;
        int len;
        if (StringUtils.isNumeric(keyspec)) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
            len = Integer.valueOf(keyspec); 
        } else if (keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_DSA)) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_DSA;
            if (keyspec.startsWith(AlgorithmConstants.KEYALGORITHM_DSA)) {
                keyspec = keyspec.substring(3);
            }
            len = Integer.valueOf(keyspec);
        } else {
            keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
            final KeyPair kp = KeyTools.genKeys(keyspec, keyAlg);
            len = KeyTools.getKeyLength(kp.getPublic());
        }
        checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(final PublicKey pk) throws InvalidKeyException, NoSuchAlgorithmException,
    NoSuchProviderException, InvalidAlgorithmParameterException {
        final String keyAlg = AlgorithmTools.getKeyAlgorithm(pk);
        final int len = KeyTools.getKeyLength(pk);
        checkValidKeyLength(keyAlg, len);
    }

    public static void checkValidKeyLength(final String keyAlg, final int len) throws InvalidKeyException {
        if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlg)) {
            // We allow key lengths of 0, because that means that implicitlyCA is used. 
            // for ImplicitlyCA we have no idea what the key length is, on the other hand only real professionals
            // will ever use that to we will allow it.
            if ((len > 0) && (len < 224)) {
                final String msg = intres.getLocalizedMessage("catoken.invalidkeylength", "ECDSA", "224", len);
                throw new InvalidKeyException(msg);
            }                            
        } else if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlg) || AlgorithmConstants.KEYALGORITHM_DSA.equals(keyAlg)) {
            if (len < 1024) {
                final String msg = intres.getLocalizedMessage("catoken.invalidkeylength", "RSA/DSA", "1024", len);
                throw new InvalidKeyException(msg);
            }
        }
    }
}
