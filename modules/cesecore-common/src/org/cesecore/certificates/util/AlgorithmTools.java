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
package org.cesecore.certificates.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.OIDField;

/**
 * Various helper methods for handling the mappings between different key and
 * signature algorithms.
 *
 * This class has to be updated when new key or signature algorithms are
 * added to EJBCA.
 *
 * @see AlgorithmConstants
 * @see CertTools#getSignatureAlgorithm
 * @see KeyTools#getKeyLength
 *
 * @version $Id$
 */
public abstract class AlgorithmTools {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(AlgorithmTools.class);

    /** String used for an unknown keyspec in CA token properties */
    public static final String KEYSPEC_UNKNOWN = "unknown";

    /** Signature algorithms supported by RSA keys */
    public static final List<String> SIG_ALGS_RSA = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA384_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA512_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA
    ));

    /** Signature algorithms supported by DSA keys */
    public static final List<String> SIG_ALGS_DSA = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_SHA1_WITH_DSA
    ));

    /** Signature algorithms supported by ECDSA keys */
    public static final List<String> SIG_ALGS_ECDSA = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA,
            AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA
    ));

    /** Signature algorithms supported by GOST keys */
    public static final List<String> SIG_ALGS_ECGOST3410 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410
    ));

    /** Signature algorithms supported by DSTU4145 keys */
    public static final List<String> SIG_ALGS_DSTU4145 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145
    ));

    /**
     * Gets the name of matching key algorithm from a public key as defined by
     * <i>AlgorithmConstants</i>.
     * @param publickey Public key to find matching key algorithm for.
     * @return Name of the matching key algorithm or null if no match.
     * @see AlgorithmConstants#KEYALGORITHM_RSA
     * @see AlgorithmConstants#KEYALGORITHM_DSA
     * @see AlgorithmConstants#KEYALGORITHM_ECDSA
     */
    public static String getKeyAlgorithm(final PublicKey publickey) {
        String keyAlg = null;
        if ( publickey instanceof RSAPublicKey ) {
            keyAlg  = AlgorithmConstants.KEYALGORITHM_RSA;
        } else if ( publickey instanceof DSAPublicKey ) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_DSA;
        } else if ( publickey instanceof ECPublicKey ) {
            final String algo = publickey.getAlgorithm();
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
            } else if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSTU4145;
            } else {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
            }
        }
        return keyAlg;
    }

    /** @return a list of all available key algorithms */
    public static List<String> getAvailableKeyAlgorithms() {
        final List<String> ret = new ArrayList<>(Arrays.asList(AlgorithmConstants.KEYALGORITHM_DSA, AlgorithmConstants.KEYALGORITHM_ECDSA,
                AlgorithmConstants.KEYALGORITHM_RSA));
        for (final String algName : CesecoreConfiguration.getExtraAlgs()) {
            ret.add(CesecoreConfiguration.getExtraAlgTitle(algName));
        }
        return ret;
    }

    /**
     * Get unique available named elliptic curves and their aliases.
     *
     * @param hasToBeKnownByDefaultProvider if the curve name needs to be known by the default provider (e.g. so Sun PKCS#11 can use it)
     * @return a Map with elliptic curve names as key and the key+any alias as the value.
     */
    public static Map<String,List<String>> getNamedEcCurvesMap(final boolean hasToBeKnownByDefaultProvider) {
        // Map of curve name and aliases which are the same curve
        final Map<String,List<String>> processedCurveNames = new HashMap<>();
        @SuppressWarnings("unchecked")
        final Enumeration<String> ecNamedCurvesStandard = ECNamedCurveTable.getNames();
        // Process standard curves, removing blacklisted ones and those not supported by the provider
        while (ecNamedCurvesStandard.hasMoreElements()) {
            final String ecNamedCurve = ecNamedCurvesStandard.nextElement();
            processCurveName(hasToBeKnownByDefaultProvider, processedCurveNames, ecNamedCurve);
        }

        // Process additional curves that we specify
        for (String ecNamedCurve : AlgorithmConstants.EXTRA_EC_CURVES) {
            processCurveName(hasToBeKnownByDefaultProvider, processedCurveNames, ecNamedCurve);
        }
        return processedCurveNames;
    }

    /**
     * Get unique available named elliptic curves and their aliases.
     *
     * @param hasToBeKnownByDefaultProvider if the curve name needs to be known by the default provider (e.g. so Sun PKCS#11 can use it)
     * @return a Map with elliptic curve names as key and the list of alias separated by '/' as the value.
     */
    public static TreeMap<String,String> getFlatNamedEcCurvesMap(final boolean hasToBeKnownByDefaultProvider) {
        final TreeMap<String,String> result = new TreeMap<String,String>();
        final Map<String, List<String>> map = getNamedEcCurvesMap(hasToBeKnownByDefaultProvider);
        final String[] keys = map.keySet().toArray(new String[map.size()]);
        Arrays.sort(keys);
        for (final String name : keys) {
            result.put(name, StringTools.getAsStringWithSeparator(" / ", map.get(name)));
        }
        return result;
    }

    /**
     * Gets a list of allowed curves (see {@link http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf}.
     *
     * @return the list of allowed curves.
     */
    public static List<String> getNistCurves() {
        // Only apply most important conditions (sequence is Root-CA, Sub-CA, User-Certificate)!
        // But this is not required at the time, because certificate validity conditions are before
        // 2014 (now 2017). Allowed curves by NIST are NIST P 256, P 384, P 521
        // See http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf chapter 1.2
        final List<String> list = new ArrayList<String>();
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-256"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-384"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-521"));
        return list;
    }

    private static void processCurveName(final boolean hasToBeKnownByDefaultProvider, final Map<String, List<String>> processedCurveNames,
            final String ecNamedCurve) {
        if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(ecNamedCurve)) {
            return;
        }
        // Only add it if the key-length is sufficient
        try {
            final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(ecNamedCurve);
            final int bitLength = parameterSpec.getN().bitLength();
            KeyTools.checkValidKeyLength(AlgorithmConstants.KEYALGORITHM_ECDSA, bitLength);
            // Check if this exists under another alias
            boolean added = false;
            for (final String name : processedCurveNames.keySet()) {
                final ECNamedCurveParameterSpec parameterSpec2 = ECNamedCurveTable.getParameterSpec(name);
                if (parameterSpec.equals(parameterSpec2)) {
                    // We have already listed this curve under another name
                    added = true;
                    break;
                }
            }
            if (!added) {
                if (hasToBeKnownByDefaultProvider) {
                    if (AlgorithmTools.isNamedECKnownInDefaultProvider(ecNamedCurve)) {
                        processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
                    }
                } else {
                    processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
                }
            }
        } catch (InvalidKeyException e) {
            // Ignore very silently
            if (log.isTraceEnabled()) {
                log.trace("Not adding keys that are not allowed to key list: "+e.getMessage());
            }
        } catch (RuntimeException e) {
            // Ignore
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
    }

    /** @return the number of bits a named elliptic curve has or 0 if the curve name is unknown. */
    public static int getNamedEcCurveBitLength(final String ecNamedCurve) {
        ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECGOST3410NamedCurveTable.getParameterSpec(ecNamedCurve);
        if (ecNamedCurveParameterSpec!=null) {
            // This always returns 0, so try to use the field size as an estimate of the bit strength
            //return ECGOST3410NamedCurveTable.getParameterSpec(ecNamedCurve).getN().bitLength()
            return ecNamedCurveParameterSpec.getCurve().getFieldSize();
        }
        ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(ecNamedCurve);
        if (ecNamedCurveParameterSpec==null) {
            return 0;
        }
        return ecNamedCurveParameterSpec.getN().bitLength();
    }

    /**
     * Gets a collection of signature algorithm names supported by the given
     * key.
     * @param publickey key to find supported algorithms for.
     * @return Collection of zero or more signature algorithm names
     * @see AlgorithmConstants
     */
    public static List<String> getSignatureAlgorithms(final PublicKey publickey) {
        if ( publickey instanceof RSAPublicKey ) {
            return SIG_ALGS_RSA;
        }
        if ( publickey instanceof DSAPublicKey ) {
            return SIG_ALGS_DSA;
        }
        if ( publickey instanceof ECPublicKey ) {
            final String algo = publickey.getAlgorithm();
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                return SIG_ALGS_ECGOST3410;
            }
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                return SIG_ALGS_DSTU4145;
            }
            return SIG_ALGS_ECDSA;
        }
        return Collections.emptyList();
    }

    /**
     * Gets the key algorithm matching a specific signature algorithm.
     * @param signatureAlgorithm to get matching key algorithm for
     * @return The key algorithm matching the signature or algorithm or
     * the default if no matching was found.
     * @see AlgorithmConstants
     */
    public static String getKeyAlgorithmFromSigAlg(final String signatureAlgorithm) {
        final String ret;
        if ( signatureAlgorithm.contains("ECDSA") ) {
            ret = AlgorithmConstants.KEYALGORITHM_ECDSA;
        } else if ( signatureAlgorithm.contains("GOST3410")) {
            ret = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
        } else if ( signatureAlgorithm.contains("DSTU4145")) {
            ret = AlgorithmConstants.KEYALGORITHM_DSTU4145;
        } else if ( signatureAlgorithm.contains("DSA") ) {
            ret = AlgorithmConstants.KEYALGORITHM_DSA;
        } else {
            ret = AlgorithmConstants.KEYALGORITHM_RSA;
        }
        return ret;
    }

    /**
     * Gets the key specification from a public key. Example: "2048" for a RSA
     * or DSA key or "secp256r1" for EC key. The EC curve is only detected
     * if <i>publickey</i> is an object known by the bouncy castle provider.
     * @param publicKey The public key to get the key specification from
     * @return The key specification, "unknown" if it could not be determined and
     * null if the key algorithm is not supported
     */
    public static String getKeySpecification(final PublicKey publicKey) {
        if (log.isTraceEnabled()) {
            log.trace(">getKeySpecification");
        }
        String keyspec = null;
        if ( publicKey instanceof RSAPublicKey ) {
            keyspec = Integer.toString( ((RSAPublicKey) publicKey).getModulus().bitLength() );
        } else if ( publicKey instanceof DSAPublicKey ) {
            keyspec = Integer.toString( ((DSAPublicKey) publicKey).getParams().getP().bitLength() );
        } else if ( publicKey instanceof ECPublicKey) {
            final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            if ( ecPublicKey.getParams() instanceof ECNamedCurveSpec ) {
                keyspec = ((ECNamedCurveSpec) ecPublicKey.getParams()).getName();
                // Prefer to return a curve name alias that also works with the default and BC provider
                for (String keySpecAlias : getEcKeySpecAliases(keyspec)) {
                    if (isNamedECKnownInDefaultProvider(keySpecAlias)) {
                        keyspec = keySpecAlias;
                        break;
                    }
                }
            } else {
                keyspec = KEYSPEC_UNKNOWN;
                // Try to detect if it is a curve name known by BC even though the public key isn't a BC key
                final ECParameterSpec namedCurve = ecPublicKey.getParams();
                if (namedCurve!=null) {
                    final int c1 = namedCurve.getCofactor();
                    final EllipticCurve ec1 = namedCurve.getCurve();
                    final BigInteger a1 = ec1.getA();
                    final BigInteger b1 = ec1.getB();
                    final int fs1 = ec1.getField().getFieldSize();
                    //final byte[] s1 = ec1.getSeed();
                    final ECPoint g1 = namedCurve.getGenerator();
                    final BigInteger ax1 = g1.getAffineX();
                    final BigInteger ay1 = g1.getAffineY();
                    final BigInteger o1 = namedCurve.getOrder();
                    if (log.isDebugEnabled()) {
                        log.debug("a1=" + a1 + " b1=" + b1 + " fs1=" + fs1 + " ax1=" + ax1 + " ay1=" + ay1 + " o1=" + o1 + " c1="+c1);
                    }
                    @SuppressWarnings("unchecked")
                    final Enumeration<String> ecNamedCurves = ECNamedCurveTable.getNames();
                    while (ecNamedCurves.hasMoreElements()) {
                        final String ecNamedCurveBc = ecNamedCurves.nextElement();
                        final ECNamedCurveParameterSpec parameterSpec2 = ECNamedCurveTable.getParameterSpec(ecNamedCurveBc);
                        final ECCurve ec2 = parameterSpec2.getCurve();
                        final BigInteger a2 = ec2.getA().toBigInteger();
                        final BigInteger b2 = ec2.getB().toBigInteger();
                        final int fs2 = ec2.getFieldSize();
                        final org.bouncycastle.math.ec.ECPoint g2 = parameterSpec2.getG();
                        final BigInteger ax2 = g2.getAffineXCoord().toBigInteger();
                        final BigInteger ay2 = g2.getAffineYCoord().toBigInteger();
                        final BigInteger h2 = parameterSpec2.getH();
                        final BigInteger n2 = parameterSpec2.getN();
                        if (a1.equals(a2) && ax1.equals(ax2) && b1.equals(b2) && ay1.equals(ay2) && fs1==fs2 && o1.equals(n2) && c1==h2.intValue()) {
                            // We have a matching curve here!
                            if (log.isDebugEnabled()) {
                                log.debug("a2=" + a2 + " b2=" + b2 + " fs2=" + fs2 + " ax2=" + ax2 + " ay2=" + ay2 + " h2=" + h2 + " n2=" + n2 + " " + ecNamedCurveBc);
                            }
                            // Since this public key is a SUN PKCS#11 pub key if we get here, we only return an alias if it is recognized by the provider
                            if (isNamedECKnownInDefaultProvider(ecNamedCurveBc)) {
                                keyspec = ecNamedCurveBc;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getKeySpecification: "+keyspec);
        }
        return keyspec;
    }

    /** Check if the curve name is known by the first found PKCS#11 provider or default (BC) (if no EC capable PKCS#11 provider were found)*/
    public static boolean isNamedECKnownInDefaultProvider(String ecNamedCurveBc) {
        final Provider[] providers = Security.getProviders("KeyPairGenerator.EC");
        String providerName = providers[0].getName();
        try {
            for (Provider ecProvider : providers) {
                //This will list something like: SunPKCS11-NSS, BC, SunPKCS11-<library>-slot<slotnumber>
                if (log.isDebugEnabled()) {
                    log.debug("Found EC capable provider named: " + ecProvider.getName());
                }
                if (ecProvider.getName().startsWith("SunPKCS11-") && !ecProvider.getName().startsWith("SunPKCS11-NSS") ) {
                    // Sometimes the P11 provider will not even know about EC, skip these providers. As an example the SunP11
                    // provider in some version/installations will throw a:
                    // java.lang.RuntimeException: Cannot load SunEC provider
                    //   at sun.security.pkcs11.P11ECKeyFactory.getSunECProvider(P11ECKeyFactory.java:55)
                    // This was a bug of non upgraded NSS in RHEL at some point in time.
                    try {
                        KeyPairGenerator.getInstance("EC", ecProvider.getName());
                        providerName = ecProvider.getName();
                        break;
                    } catch (RuntimeException e) {
                        log.info("Provider "+ecProvider.getName()+" bailed out on EC, ignored.", e);
                    }
                }
            }
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", providerName);
            kpg.initialize(new ECGenParameterSpec(getEcKeySpecOidFromBcName(ecNamedCurveBc)));
            return true;
        } catch (InvalidAlgorithmParameterException e) {
            if (log.isDebugEnabled()) {
                log.debug(ecNamedCurveBc + " is not available in provider " + providerName);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("EC capable provider " + providerName + " could no longer handle elliptic curve algorithm.." ,e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("EC capable provider " + providerName + " disappeard unexpectedly." ,e);
        }
        return false;
    }

    /**
     * Convert from BC ECC curve names to the OID.
     *
     * @param ecNamedCurveBc the name as BC reports it
     * @return the OID of the curve or the input curve name if it is unknown by BC
     */
    public static String getEcKeySpecOidFromBcName(final String ecNamedCurveBc) {
        // Although the below class is in x9 package, it handles all different curves, including TeleTrust (brainpool)
        final ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID(ecNamedCurveBc);
        if (oid==null) {
            return ecNamedCurveBc;
        }
        return oid.getId();
    }

    /** @return a list of aliases for the provided curve name (including the provided name) */
    public static List<String> getEcKeySpecAliases(final String namedEllipticCurve) {
        final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(namedEllipticCurve);
        final List<String> ret = new ArrayList<>();
        ret.add(namedEllipticCurve);

        if (parameterSpec != null) { // GOST and DSTU aren't present in ECNamedCurveTable (and don't have aliases)
            @SuppressWarnings("unchecked")
            final Enumeration<String> ecNamedCurves = ECNamedCurveTable.getNames();
            while (ecNamedCurves.hasMoreElements()) {
                final String currentCurve = ecNamedCurves.nextElement();
                if (!namedEllipticCurve.equals(currentCurve)) {
                    final ECNamedCurveParameterSpec parameterSpec2 = ECNamedCurveTable.getParameterSpec(currentCurve);
                    if (parameterSpec.equals(parameterSpec2)) {
                        ret.add(currentCurve);
                    }
                }
            }
        }
        return ret;
    }

    /**
     * Gets the algorithm to use for encryption given a specific signature algorithm.
     * Some signature algorithms (i.e. DSA and ECDSA) can not be used for
     * encryption so they are instead substituted with RSA with equivalent hash
     * algorithm.
     * @param signatureAlgorithm to find a encryption algorithm for
     * @return an other encryption algorithm or same as signature algorithm if it
     * can be used for encryption
     */
    public static String getEncSigAlgFromSigAlg(final String signatureAlgorithm) {
        String encSigAlg = signatureAlgorithm;
        if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA)) {
            // Even though SHA384 is used for ECDSA, play it safe and use SHA256 for RSA since we do not trust all PKCS#11 implementations
            // to be so new to support SHA384WithRSA
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_SHA1_WITH_DSA)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
        } else if (signatureAlgorithm.equals(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
        }
        return encSigAlg;
    }

    /**
     * Answers if the key can be used together with the given signature algorithm.
     * @param publicKey public key to use
     * @param signatureAlgorithm algorithm to test
     * @return true if signature algorithm can be used with the public key algorithm
     */
    public static boolean isCompatibleSigAlg(final PublicKey publicKey, final String signatureAlgorithm) {
        String algname = publicKey.getAlgorithm();
        if (algname == null) {
            algname = "";
        }
        boolean isGost3410 = algname.contains("GOST3410");
        boolean isDstu4145 = algname.contains("DSTU4145");
        boolean isSpecialECC = isGost3410 || isDstu4145;

        boolean ret = false;
        if (StringUtils.contains(signatureAlgorithm, AlgorithmConstants.KEYALGORITHM_RSA)) {
            if (publicKey instanceof RSAPublicKey) {
                ret = true;
            }
        } else if (StringUtils.contains(signatureAlgorithm, AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            if (publicKey instanceof ECPublicKey && !isSpecialECC) {
                ret = true;
            }
        } else if (StringUtils.contains(signatureAlgorithm, AlgorithmConstants.KEYALGORITHM_DSA)) {
            if (publicKey instanceof DSAPublicKey) {
                ret = true;
            }
        } else if (StringUtils.contains(signatureAlgorithm, AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
             if (publicKey instanceof ECPublicKey && isGost3410) {
                 ret = true;
             }
         } else if (StringUtils.contains(signatureAlgorithm, AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
            if (publicKey instanceof ECPublicKey && isDstu4145) {
                ret = true;
            }
         }
        return ret;
    }

    /**
     * Simple methods that returns the signature algorithm value from the certificate. Not usable for setting signature algorithms names in EJBCA,
     * only for human presentation.
     *
     * @return Signature algorithm name from the certificate as a human readable string, for example SHA1WithRSA.
     */
    public static String getCertSignatureAlgorithmNameAsString(Certificate cert) {
        final String certSignatureAlgorithm;
        {
            final String certSignatureAlgorithmTmp;
            if (cert instanceof X509Certificate) {
                final X509Certificate x509cert = (X509Certificate) cert;
                certSignatureAlgorithmTmp = x509cert.getSigAlgName();
                if (log.isDebugEnabled()) {
                    log.debug("certSignatureAlgorithm is: " + certSignatureAlgorithmTmp);
                }
            } else if (StringUtils.equals(cert.getType(), "CVC")) {
                final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
                final CVCPublicKey cvcpk;
                try {
                    cvcpk = cvccert.getCVCertificate().getCertificateBody().getPublicKey();
                    final OIDField oid = cvcpk.getObjectIdentifier();
                    certSignatureAlgorithmTmp = AlgorithmUtil.getAlgorithmName(oid);
                } catch (NoSuchFieldException e) {
                    throw new AlgorithmsToolRuntimeException("Not a valid CVC certificate", e);
                }
            } else {
                throw new AlgorithmsToolRuntimeException("Certificate type neither X509 nor CVS.");
            }
            // Try to make it easier to display some signature algorithms that cert.getSigAlgName() does not have a good string for.
            // We typically don't get here, since the x509cert.getSigAlgName handles id_RSASSA_PSS nowadays, this is old legacy code,
            // only triggered if the resulting signature algorithm returned above is an OID in stead of a sign alg name
            // (i.e. 1.2.840.113549.1.1.10 instead of SHA256WithRSAAndMGF1
            if (certSignatureAlgorithmTmp.equalsIgnoreCase(PKCSObjectIdentifiers.id_RSASSA_PSS.getId()) && cert instanceof X509Certificate) {
                // Figure out the hash algorithm, it's hidden in the Signature Algorithm Parameters when using RSA PSS
                // If we got this value we should have a x509 cert
                final X509Certificate x509cert = (X509Certificate) cert;
                final byte[] params = x509cert.getSigAlgParams();
                // Below code snipped from BC, it's hidden as private/protected methods so we can't use BC directly.
                final RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
                String digestName = MessageDigestUtils.getDigestName(rsaParams.getHashAlgorithm().getAlgorithm());
                // This is just to convert SHA-256 into SHA256, while SHA3-256 should remain as it is
                if (digestName.contains("-") && !digestName.startsWith("SHA3")) {
                    digestName = StringUtils.remove(digestName, '-');
                }
                certSignatureAlgorithm = digestName + "withRSAandMGF1";
            } else {
                certSignatureAlgorithm = certSignatureAlgorithmTmp;
            }
        }
        // SHA256WithECDSA does not work to be translated in JDK5.
        if (certSignatureAlgorithm.equalsIgnoreCase("1.2.840.10045.4.3.2")) {
            return AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        }
        // GOST3410
        if(isGost3410Enabled() && certSignatureAlgorithm.equalsIgnoreCase(CesecoreConfiguration.getOidGost3410())) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
        }
        // DSTU4145
        if(isDstu4145Enabled() && certSignatureAlgorithm.startsWith(CesecoreConfiguration.getOidDstu4145()+".")) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
        }
        return certSignatureAlgorithm;
    }

    /**
     * Simple method that looks at the certificate and determines, from EJBCA's standpoint, which signature algorithm it is
     *
     * @param cert the cert to examine
     * @return Signature algorithm name from AlgorithmConstants.SIGALG_SHA1_WITH_RSA etc.
     */
    public static String getSignatureAlgorithm(Certificate cert) {
        String signatureAlgorithm = null;
        String certSignatureAlgorithm = getCertSignatureAlgorithmNameAsString(cert);

        // The signature string returned from the certificate is often not usable as the signature algorithm we must
        // specify for a CA in EJBCA, for example SHA1WithECDSA is returned as only ECDSA, so we need some magic to fix it up.
        PublicKey publickey = cert.getPublicKey();
        if (publickey instanceof RSAPublicKey) {
            if (certSignatureAlgorithm.contains("SHA3-")) {
                if (certSignatureAlgorithm.contains("256")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA;
                } else if (certSignatureAlgorithm.contains("384")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA;
                } else if (certSignatureAlgorithm.contains("512")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA;
                }
            } else if (certSignatureAlgorithm.indexOf("MGF1") == -1) {
                if (certSignatureAlgorithm.indexOf("MD5") != -1) {
                    signatureAlgorithm = "MD5WithRSA";
                } else if (certSignatureAlgorithm.indexOf("SHA1") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
                } else if (certSignatureAlgorithm.indexOf("256") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
                } else if (certSignatureAlgorithm.indexOf("384") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_RSA;
                } else if (certSignatureAlgorithm.indexOf("512") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_RSA;
                }
            } else {
                if (certSignatureAlgorithm.indexOf("SHA1") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.indexOf("256") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.indexOf("384") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.indexOf("512") != -1) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1;
                }
            }
        } else if (publickey instanceof DSAPublicKey) {
            signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
        } else {
            if (certSignatureAlgorithm.contains("SHA3-")) {
                if (certSignatureAlgorithm.contains("256")) {
                    return AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA;
                } else if (certSignatureAlgorithm.contains("384")) {
                    return AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA;
                } else if (certSignatureAlgorithm.contains("512")) {
                    return AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA;
                }
            } else if (certSignatureAlgorithm.indexOf("256") != -1) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            } else if (certSignatureAlgorithm.indexOf("224") != -1) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA;
            } else if (certSignatureAlgorithm.indexOf("384") != -1) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA;
            } else if (certSignatureAlgorithm.indexOf("512") != -1) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA;
            } else if (certSignatureAlgorithm.indexOf("ECDSA") != -1) {
                // From x509cert.getSigAlgName(), SHA1withECDSA only returns name ECDSA
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA;
            } else if (isGost3410Enabled() && certSignatureAlgorithm.equalsIgnoreCase(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
            } else if (isDstu4145Enabled() && certSignatureAlgorithm.equalsIgnoreCase(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("getSignatureAlgorithm: " + signatureAlgorithm);
        }
        return signatureAlgorithm;
    } // getSignatureAlgorithm

    /**
     * Returns the OID of the digest algorithm corresponding to the signature algorithm. Does not handle RSA-SSA (MGF1) since the Hash algo in MGF1
     * if hidden in the parameters, which is not visible in the sigAlg
     * @param OID of a signatureAlgorithm, for example PKCSObjectIdentifiers.sha256WithRSAEncryption.getId() (1.2.840.113549.1.1.11)
     * @return Digest OID, CMSSignedGenerator.DIGEST_SHA256, CMSSignedGenerator.DIGEST_GOST3411, etc, default to SHA256 if nothing else fits
     */
    public static String getDigestFromSigAlg(String sigAlgOid) {
        if (sigAlgOid.startsWith(CryptoProObjectIdentifiers.GOST_id.getId()) || sigAlgOid.startsWith(UAObjectIdentifiers.UaOid.getId())) {
            return CMSSignedGenerator.DIGEST_GOST3411;
        }
        
        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA1.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA1;
        }
        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA224.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA224;
        }
        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA256.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA256;
        }
        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA384.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA384;
        }
        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA512.getId()) || sigAlgOid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_SHA512;
        }
        
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256.getId())) {
            return NISTObjectIdentifiers.id_sha3_256.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384.getId())) {
            return NISTObjectIdentifiers.id_sha3_384.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512.getId())) {
            return NISTObjectIdentifiers.id_sha3_512.getId();
        }
        
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId())) {
            return NISTObjectIdentifiers.id_sha3_256.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId())) {
            return NISTObjectIdentifiers.id_sha3_384.getId();
        }
        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId())) {
            return NISTObjectIdentifiers.id_sha3_512.getId();
        }
        
        if(sigAlgOid.equals(PKCSObjectIdentifiers.md5WithRSAEncryption.getId())) {
            return CMSSignedGenerator.DIGEST_MD5;
        }
        
        if(sigAlgOid.equals(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001.getId()) ) {
            return CMSSignedGenerator.DIGEST_GOST3411;
        }
        return CMSSignedGenerator.DIGEST_SHA256;
    }

    /**
     * Calculates which signature algorithm to use given a key type and a digest algorithm
     *
     * @param digestAlg objectId of a digest algorithm, CMSSignedGenerator.DIGEST_SHA256 etc
     * @param keyAlg RSA, EC, DSA
     * @return ASN1ObjectIdentifier with the id of PKCSObjectIdentifiers.sha1WithRSAEncryption, X9ObjectIdentifiers.ecdsa_with_SHA1, X9ObjectIdentifiers.id_dsa_with_sha1, etc
     */
    public static ASN1ObjectIdentifier getSignAlgOidFromDigestAndKey(final String digestAlg, final String keyAlg) {
        if (log.isTraceEnabled()) {
            log.trace(">getSignAlg("+digestAlg+","+keyAlg+")");
        }
        // Default to SHA256WithRSA if everything else fails
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
        if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
            oid = X9ObjectIdentifiers.ecdsa_with_SHA256;
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
            oid = NISTObjectIdentifiers.dsa_with_sha256;
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
            oid = CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001;
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
            oid = new ASN1ObjectIdentifier(CesecoreConfiguration.getOidDstu4145());
        }
        if (digestAlg != null) {
            if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA1) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA384) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                    oid = PKCSObjectIdentifiers.sha384WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA512) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = PKCSObjectIdentifiers.sha512WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_MD5) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = PKCSObjectIdentifiers.md5WithRSAEncryption;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA1) && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC)) ) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA1;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256) && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC)) ) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA256;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA224) && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC)) ) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA224;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA384) && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC)) ) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA384;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA512) && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC)) ) {
                oid = X9ObjectIdentifiers.ecdsa_with_SHA512;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA1) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
                oid = X9ObjectIdentifiers.id_dsa_with_sha1;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
                oid = NISTObjectIdentifiers.dsa_with_sha256;
            } else if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA512) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_DSA)) {
                oid = NISTObjectIdentifiers.dsa_with_sha512;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_256.toString()) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_384.toString()) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_512.toString()) && keyAlg.equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                oid = NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_256.toString())
                    && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_256;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_384.toString())
                    && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_384;
            } else if (digestAlg.equals(NISTObjectIdentifiers.id_sha3_512.toString())
                    && (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ECDSA) || keyAlg.equals(AlgorithmConstants.KEYALGORITHM_EC))) {
                oid = NISTObjectIdentifiers.id_ecdsa_with_sha3_512;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("getSignAlgOidFromDigestAndKey: " + oid.getId());
        }
        return oid;
    }

    public static String getAlgorithmNameFromDigestAndKey(final String digestAlg, final String keyAlg) {
        return getAlgorithmNameFromOID(getSignAlgOidFromDigestAndKey(digestAlg, keyAlg));
    }

    public static boolean isGost3410Enabled() {
        return CesecoreConfiguration.getOidGost3410() != null;
    }

    public static boolean isDstu4145Enabled() {
        return CesecoreConfiguration.getOidDstu4145() != null;
    }

    public static boolean isSigAlgEnabled(String sigAlg) {
        if (AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410.equals(sigAlg)) {
            return isGost3410Enabled();
        } else if (AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145.equals(sigAlg)) {
            return isDstu4145Enabled();
        } else {
            return true;
        }
    }

    /**
     * Determine whether the curve alias given as argument is a known elliptic curve.
     * @param alias an alias of the elliptic curve to look for
     * @return true if the elliptic curve is known by this alias, false otherwise
     */
    public static boolean isKnownAlias(final String alias) {
        return !getAllCurveAliasesFromAlias(alias).isEmpty();
    }

    /**
     * <p>Perform a case-insensitive lookup of all known aliases for an elliptic curve given one known alias.</p>
     * <p>To determine whether an alias is known, see {@link #isKnownCurveAlias}.</p>
     * @return a sorted list of aliases for the elliptic curve specified, never null
     */
    public static List<String> getAllCurveAliasesFromAlias(final String alias) {
        final String lowerCaseAlias = alias.toLowerCase();
        for (final Entry<String, List<String>> name : getNamedEcCurvesMap(false).entrySet()) {
            final String lowerCaseCanonicalName = name.getKey().toLowerCase();
            final List<String> lowerCaseAliases = StringTools.toLowerCase(name.getValue());
            if (StringUtils.equals(lowerCaseAlias, lowerCaseCanonicalName) || lowerCaseAliases.contains(lowerCaseAlias)) {
                final List<String> aliases = new ArrayList<String>(name.getValue());
                aliases.add(name.getKey());
                Collections.sort(aliases);
                return aliases;
            }
        }
        return new ArrayList<>();
    }

    /**
     * Returns the name of the algorithm corresponding to the specified OID
     * @param sigAlgOid
     * @return The name of the algorithm corresponding sigAlgOid or null if the algorithm is not recognized.
     */
    public static String getAlgorithmNameFromOID(ASN1ObjectIdentifier sigAlgOid) {

        if(sigAlgOid.equals(PKCSObjectIdentifiers.md5WithRSAEncryption)) {
            return AlgorithmConstants.SIGALG_MD5_WITH_RSA;
        }

        if(sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption)) {
            return AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
        }

        if(sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
            return AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
        }

        if(sigAlgOid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)) {
            return AlgorithmConstants.SIGALG_SHA384_WITH_RSA;
        }

        if(sigAlgOid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
            return AlgorithmConstants.SIGALG_SHA512_WITH_RSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256)) {
            return AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384)) {
            return AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512)) {
            return AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA;
        }

        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA1)) {
            return AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA;
        }

        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA224)) {
            return AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA;
        }

        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
            return AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        }

        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA384)) {
            return AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA;
        }

        if(sigAlgOid.equals(X9ObjectIdentifiers.ecdsa_with_SHA512)) {
            return AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_256)) {
            return AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_384)) {
            return AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA;
        }

        if (sigAlgOid.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_512)) {
            return AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA;
        }
        // GOST3410
        if(isGost3410Enabled() && sigAlgOid.getId().equalsIgnoreCase(CesecoreConfiguration.getOidGost3410())) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
        }
        // DSTU4145
        if(isDstu4145Enabled() && sigAlgOid.getId().startsWith(CesecoreConfiguration.getOidDstu4145()+".")) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
        }

        return null;
    }

    /**
     * Determine if the certificate profile supports Elliptic Curve Cryptography (ECC).
     *
     * @param certificateProfile the certificate profile to check.
     * @return true if the certificate profile supports a key algorithm which utilises ECC, false otherwise.
     */
    public static boolean isEccCapable(final CertificateProfile certificateProfile) {
        return certificateProfile.getAvailableKeyAlgorithmsAsList().contains("ECDSA")
                || certificateProfile.getAvailableKeyAlgorithmsAsList().contains("ECGOST3410")
                || certificateProfile.getAvailableKeyAlgorithmsAsList().contains("DSTU4145");
    }
}
