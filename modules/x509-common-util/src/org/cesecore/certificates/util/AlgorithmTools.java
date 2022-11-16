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
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSINamedCurves;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
/**
 * Various helper methods for handling the mappings between different key and
 * signature algorithms.
 *
 * This class has to be updated when new key or signature algorithms are
 * added to EJBCA.
 *
 * @see AlgorithmConstants
 * @see KeyTools#getKeyLength
 *
 */
public abstract class AlgorithmTools {

    /** Log4j instance */
    public static final Logger log = Logger.getLogger(AlgorithmTools.class);

    /** String used for an unknown keyspec in CA token properties */
    public static final String KEYSPEC_UNKNOWN = "unknown";

    /** Signature algorithms supported by RSA keys */
    private static final List<String> SIG_ALGS_RSA_NOSHA1_INTERNAL = Arrays.asList(
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA384_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA512_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA
    );
    public static final List<String> SIG_ALGS_RSA_NOSHA1 = Collections.unmodifiableList(SIG_ALGS_RSA_NOSHA1_INTERNAL);

    private static final List<String> SIG_ALGS_RSA_SHA1_INTERNAL = Arrays.asList(
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1
    );

    public static final List<String> SIG_ALGS_RSA = Collections.unmodifiableList(ListUtils.union(SIG_ALGS_RSA_SHA1_INTERNAL, SIG_ALGS_RSA_NOSHA1_INTERNAL));

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
    
    /** Constants holding the default available bit lengths for various algorithms */
    public static final List<Integer> DEFAULTBITLENGTHS_RSA = Arrays.asList( 1024, 1536, 2048, 3072, 4096, 6144, 8192 );
    public static final List<Integer> DEFAULTBITLENGTHS_DSA = Arrays.asList( 1024 );
    public static final List<Integer> DEFAULTBITLENGTHS_EC = getAllNamedEcCurveBitLengths();    
    public static final List<Integer> DEFAULTBITLENGTHS_DSTU = Arrays.asList( 167, 173, 179, 191, 233, 237, 307, 367, 431 );
    
    public static List<Integer> getAllBitLengths() {
        Set<Integer> allBitLengths = new TreeSet<>();
        allBitLengths.addAll(DEFAULTBITLENGTHS_RSA);
        allBitLengths.addAll(DEFAULTBITLENGTHS_DSTU);
        allBitLengths.addAll(DEFAULTBITLENGTHS_EC);
        allBitLengths.addAll(DEFAULTBITLENGTHS_DSA);
        return new ArrayList<>(allBitLengths);
    }

    /** Signature algorithms supported by EDDSA keys */
    public static final List<String> SIG_ALGS_ED25519 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_ED25519
    ));
    /** Signature algorithms supported by EDDSA keys */
    public static final List<String> SIG_ALGS_ED448 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_ED448
    ));

    /** Signature algorithms supported by GOST keys */
    public static final List<String> SIG_ALGS_ECGOST3410 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410
    ));

    /** Signature algorithms supported by DSTU4145 keys */
    public static final List<String> SIG_ALGS_DSTU4145 = Collections.unmodifiableList(Arrays.asList(
            AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145
    ));
    
    private static Map<String, List<String>> allEcCurveNames = preProcessCurveNames(false);
    private static Map<String, List<String>> allEcCurveNamesKnownByProvider = preProcessCurveNames(true);
    private static Map<String, List<String>> allGostCurveNames = preProcessGostCurveNames(false);
    private static Map<String, List<String>> allGostCurveNamesKnownByProvider = preProcessGostCurveNames(true);

    /**
     * Gets the name of matching key algorithm from a public key as defined by
     * <i>AlgorithmConstants</i>.
     * @param publickey Public key to find matching key algorithm for.
     * @return Name of the matching key algorithm or null if no match.
     * @see AlgorithmConstants#KEYALGORITHM_RSA
     * @see AlgorithmConstants#KEYALGORITHM_DSA
     * @see AlgorithmConstants#KEYALGORITHM_ECDSA
     * @see AlgorithmConstants#KEYALGORITHM_ED25519
     * @see AlgorithmConstants#KEYALGORITHM_ED448
     */
    public static String getKeyAlgorithm(final PublicKey publickey) {
        String keyAlg = null;

        if (publickey instanceof RSAPublicKey) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
        } else if (publickey instanceof DSAPublicKey) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_DSA;
        } else if (publickey instanceof ECPublicKey) {
            final String algo = publickey.getAlgorithm();
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
            } else if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                keyAlg = AlgorithmConstants.KEYALGORITHM_DSTU4145;
            } else {
                keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
            }
        } else if (publickey instanceof BCEdDSAPublicKey) {
            final String algo = publickey.getAlgorithm();
            keyAlg = algo;
            // Work around for making testMakeP12ForSingleUserEdDSA* pass, for some reason on jdk > 15 public key 
            // comes from SUN and not BC, most probably due to the multi release jdk used by BC
        } else if (publickey.getClass().getCanonicalName().equals("sun.security.ec.ed.EdDSAPublicKeyImpl")) {
            keyAlg = AlgorithmConstants.KEYALGORITHM_ED25519;
        }
        return keyAlg;
    }

    /** @return a list of all available key algorithms */
    public static List<String> getAvailableKeyAlgorithms() {
        final List<String> ret = new ArrayList<>(Arrays.asList(AlgorithmConstants.KEYALGORITHM_DSA, AlgorithmConstants.KEYALGORITHM_ECDSA,
                AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_ED25519, AlgorithmConstants.KEYALGORITHM_ED448));
        for (final String algName : AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithms()) {
            ret.add(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName));
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
        if(hasToBeKnownByDefaultProvider) {
            return allEcCurveNamesKnownByProvider;
        } else {
            return allEcCurveNames;
        }
    }
    
    public static Map<String,List<String>> getNamedGostCurvesMap(final boolean hasToBeKnownByDefaultProvider) {
        if(hasToBeKnownByDefaultProvider) {
            return allGostCurveNamesKnownByProvider;
        } else {
            return allGostCurveNames;
        }
    }
    
    /**
     * 
     * @param hasToBeKnownByDefaultProvider if the curve name needs to be known by the default provider (e.g. so Sun PKCS#11 can use it)
     * @return a Map with elliptic curve names as key and the key+any alias as the value, restricted to pure EC curves
     */
    public static Map<String,List<String>> getOnlyNamedEcCurvesMap(final boolean hasToBeKnownByDefaultProvider) {
        final Map<String,List<String>> processedCurveNames = getNamedEcCurvesMap(hasToBeKnownByDefaultProvider);
        //Clean out GOST curves
        final Enumeration<?> gostAlgorithms =  ECGOST3410NamedCurves.getNames();
        while (gostAlgorithms.hasMoreElements()) {
            processedCurveNames.remove((String) gostAlgorithms.nextElement());         
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
        final TreeMap<String,String> result = new TreeMap<>();
        final Map<String, List<String>> map = getNamedEcCurvesMap(hasToBeKnownByDefaultProvider);
        final String[] keys = map.keySet().toArray(new String[map.size()]);
        Arrays.sort(keys);
        for (final String name : keys) {
            result.put(name, StringTools.getAsStringWithSeparator(" / ", map.get(name)));
        }
        return result;
    }

    /**
     * Gets a list of allowed curves (see <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf">http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf</a>).
     *
     * @return the list of allowed curves.
     */
    public static List<String> getNistCurves() {
        // Only apply most important conditions (sequence is Root-CA, Sub-CA, User-Certificate)!
        // But this is not required at the time, because certificate validity conditions are before
        // 2014 (now 2017). Allowed curves by NIST are NIST P 256, P 384, P 521
        // See http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf chapter 1.2
        final List<String> list = new ArrayList<>();
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-256"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-384"));
        list.addAll(AlgorithmTools.getEcKeySpecAliases("P-521"));
        return list;
    }
    
    private static Map<String, List<String>> preProcessCurveNames(final boolean hasToBeKnownByDefaultProvider) {
        final Map<String,List<String>> processedCurveNames = new HashMap<>();
        Set<ECNamedCurveParameterSpec> addedCurves = new HashSet<>();
        final Enumeration<?> ecNamedCurvesStandard = ECNamedCurveTable.getNames();
        // Process standard curves, removing blacklisted ones and those not supported by the provider
        while (ecNamedCurvesStandard.hasMoreElements()) {
            final String ecNamedCurve = (String) ecNamedCurvesStandard.nextElement();
            final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(ecNamedCurve);
            if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(ecNamedCurve)) {
                continue;
            }
            if(addedCurves.contains(parameterSpec)) {
                // Check if this param spec exists under another alias
                continue;
            }
            
            if (hasToBeKnownByDefaultProvider) {
                if (AlgorithmTools.isNamedECKnownInDefaultProvider(ecNamedCurve)) {
                    processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
                }
            } else {
                processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
            }
        }
        
        // Process additional curves that we specify
        for (String ecNamedCurve : AlgorithmConstants.EXTRA_EC_CURVES) {
            final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(ecNamedCurve);
            if (AlgorithmConstants.BLACKLISTED_EC_CURVES.contains(ecNamedCurve)) {
                continue;
            }
            if(addedCurves.contains(parameterSpec)) {
                // Check if this param spec exists under another alias
                continue;
            }
            
            if (hasToBeKnownByDefaultProvider) {
                if (AlgorithmTools.isNamedECKnownInDefaultProvider(ecNamedCurve)) {
                    processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
                }
            } else {
                processedCurveNames.put(ecNamedCurve, getEcKeySpecAliases(ecNamedCurve));
            }
        }
        
        return processedCurveNames;
        
    }
    
    private static Map<String, List<String>> preProcessGostCurveNames(final boolean hasToBeKnownByDefaultProvider) {
        final Map<String,List<String>> processedCurveNames = new HashMap<>();
        Set<ECNamedCurveParameterSpec> addedCurves = new HashSet<>();
        final Enumeration<?> gostNamedCurvesStandard = ECGOST3410NamedCurves.getNames();
        // Process standard curves, removing blacklisted ones and those not supported by the provider
        while (gostNamedCurvesStandard.hasMoreElements()) {
            final String gostNamedCurve = (String) gostNamedCurvesStandard.nextElement();
            final ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(gostNamedCurve);

            if(addedCurves.contains(parameterSpec)) {
                // Check if this param spec exists under another alias
                continue;
            }
            
            if (hasToBeKnownByDefaultProvider) {
                if (AlgorithmTools.isNamedECKnownInDefaultProvider(gostNamedCurve)) {
                    processedCurveNames.put(gostNamedCurve, getEcKeySpecAliases(gostNamedCurve));
                }
            } else {
                processedCurveNames.put(gostNamedCurve, getEcKeySpecAliases(gostNamedCurve));
            }
        }
        
        return processedCurveNames;
        
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
     * 
     * @return a list of all possible EC bit lengths known to the current provider
     */
    public static List<Integer> getAllNamedEcCurveBitLengths() {
        Set<Integer> result = new TreeSet<>();
        Enumeration<?> ecCurveNames = ECNamedCurveTable.getNames();
        result.add(0);
        while (ecCurveNames.hasMoreElements()) {
            final String ecNamedCurve = (String) ecCurveNames.nextElement();
            result.add(getNamedEcCurveBitLength(ecNamedCurve));
        }
        return new ArrayList<>(result);
    }
    
    /**
     * 
     * @return a list of all possible DSTU bit lengths known to the current provider
     */
    public static List<Integer> getAllNamedDstuCurveBitLengths() {
        return new ArrayList<>();
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
        if ( publickey instanceof ECPublicKey ) {
            final String algo = publickey.getAlgorithm();
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                return SIG_ALGS_ECGOST3410;
            }
            if (StringUtils.equals(algo, AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                return SIG_ALGS_DSTU4145;
            }
            // Make things work faster by making the "best suitable" signature algorithm be first in the list
            // This is a must for example for Azure Key Vault where a P-384 key can not be used together with SHA256WithECDSA.
            List<String> ecSigAlgs = new ArrayList<>(SIG_ALGS_ECDSA);
            switch (AlgorithmTools.getNamedEcCurveBitLength(getKeySpecification(publickey))) {
            case 256:
                ecSigAlgs.remove(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
                ecSigAlgs.add(0, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
                break;
            case 384:
                ecSigAlgs.remove(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
                ecSigAlgs.add(0, AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
                break;
            case 521:
                // This is really 521 and not 512, the corresponding EC curve is for example secp521r1
                ecSigAlgs.remove(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
                ecSigAlgs.add(0, AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
                break;
            default:
                break;
            }
            if (log.isDebugEnabled()) {
                log.debug("Returning ecAlgs: " + ecSigAlgs);
            }
            return ecSigAlgs;
        }
        if ( publickey instanceof BCEdDSAPublicKey ) {
            final String algo = publickey.getAlgorithm();
            switch (algo) {
            case AlgorithmConstants.KEYALGORITHM_ED25519:            
                return SIG_ALGS_ED25519;
            case AlgorithmConstants.KEYALGORITHM_ED448:            
                return SIG_ALGS_ED448;
            }
        }
        if ( publickey instanceof DSAPublicKey ) {
            return SIG_ALGS_DSA;
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
        } else if ( signatureAlgorithm.equals(AlgorithmConstants.SIGALG_ED25519) ) {
            ret = AlgorithmConstants.KEYALGORITHM_ED25519;
        } else if ( signatureAlgorithm.equals(AlgorithmConstants.SIGALG_ED448) ) {
            ret = AlgorithmConstants.KEYALGORITHM_ED448;
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
                    final Enumeration<?> ecNamedCurves = ECNamedCurveTable.getNames();
                    while (ecNamedCurves.hasMoreElements()) {
                        final String ecNamedCurveBc = (String) ecNamedCurves.nextElement();
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
                            keyspec = ecNamedCurveBc;
                        }
                    }
                }
            }
        } else if ( publicKey instanceof BCEdDSAPublicKey ) {
            return publicKey.getAlgorithm();
        } else if ( publicKey instanceof DSAPublicKey ) {
            keyspec = Integer.toString( ((DSAPublicKey) publicKey).getParams().getP().bitLength() );
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
                if (log.isTraceEnabled()) {
                    log.trace("Found EC capable provider named: " + ecProvider.getName());
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
            if (log.isTraceEnabled()) {
                log.trace(ecNamedCurveBc + " is not available in provider " + providerName);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC capable provider " + providerName + " could no longer handle elliptic curve algorithm.." ,e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("EC capable provider " + providerName + " disappeard unexpectedly." ,e);
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
            final Enumeration<?> ecNamedCurves = ECNamedCurveTable.getNames();
            while (ecNamedCurves.hasMoreElements()) {
                final String currentCurve = (String) ecNamedCurves.nextElement();
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
     * Assumes input in the state of the signature algorithms declared in {@link AlgorithmConstants}, and extracts the basic hash algorithms from there within. 
     * 
     * @param signatureAlgorithm a signature algorithm 
     * @return a basic hash algorithm
     */
    public static String getHashAlgorithm(final String signatureAlgorithm) {
        final String result;
        if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA1)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA1;
        }  else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA224)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA224;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA256)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA256;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA384)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA384;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA512)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA512;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA3_256)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA3_256;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA3_384)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA3_384;
        } else if(signatureAlgorithm.contains(AlgorithmConstants.HASHALGORITHM_SHA3_512)) {
            result = AlgorithmConstants.HASHALGORITHM_SHA3_512;
        }       
        else {
            result = signatureAlgorithm;
        }
        
        return result;
    }
    
    
    /**
     * Gets the algorithm to use for encryption given a specific signature algorithm, adapted to the cipher type used by the encryption keys. 
     * Some cipher algorithms (i.e. DSA) can not be used for encryption so they are instead substituted with RSA with equivalent hash algorithm.
     * 
     * 
     * @param signatureAlgorithm to extract the encryption algorithm for
     * @param publicKey a public key to derive the cipher from
     * @return an other encryption algorithm or same as signature algorithm if it can be used for encryption
     */
    public static String getEncSigAlgFromSigAlg(final String signatureAlgorithm, final PublicKey publicKey ) {
       
        String encSigAlg = signatureAlgorithm;
       

        //The below rather sad construction is needed on the legacy assumption that only RSA keys would ever be used for encryption. 
        switch (signatureAlgorithm) {
        case AlgorithmConstants.SIGALG_SHA1_WITH_DSA:
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
            break;
        case AlgorithmConstants.SIGALG_SHA256_WITH_DSA:
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            break;
        case AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410:
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
            break;
        case AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145:
            encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
            break;
        case AlgorithmConstants.SIGALG_ED25519:
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            break;
        case AlgorithmConstants.SIGALG_ED448:
            encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            break;
        default:
            //Find the hash algoritihm 
            final String hashAlgo = getHashAlgorithm(signatureAlgorithm);
            if(publicKey instanceof RSAPublicKey) {
                if(signatureAlgorithm.contains("MGF1")) {
                    encSigAlg = signatureAlgorithm;
                } else {
                    switch (hashAlgo) {
                    case AlgorithmConstants.HASHALGORITHM_SHA1:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA224:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA256:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA384:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA384_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA512:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA512_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA3_256:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA3_256_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA3_384:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA3_384_WITH_RSA;
                        break;
                    case AlgorithmConstants.HASHALGORITHM_SHA3_512:
                        encSigAlg = AlgorithmConstants.SIGALG_SHA3_512_WITH_RSA;
                        break;
                    default:
                        encSigAlg = signatureAlgorithm;
                        break;
                    }
                }
            } else if(publicKey instanceof ECPublicKey) {
                switch(hashAlgo) {
                case AlgorithmConstants.HASHALGORITHM_SHA1:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA224:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA256:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA384:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA512:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA3_256:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA3_384:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA;
                    break;
                case AlgorithmConstants.HASHALGORITHM_SHA3_512:
                    encSigAlg = AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA;
                    break;
                default:
                    encSigAlg = signatureAlgorithm;
                    break;
                }
            } else {
                encSigAlg = signatureAlgorithm;
            }       
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
         } else if (StringUtils.equals(signatureAlgorithm, AlgorithmConstants.SIGALG_ED25519)) {
             if (StringUtils.equals(AlgorithmConstants.KEYALGORITHM_ED25519, publicKey.getAlgorithm())) {
                 ret = true;
             }
         } else if (StringUtils.equals(signatureAlgorithm, AlgorithmConstants.SIGALG_ED448)) {
             if (StringUtils.equals(AlgorithmConstants.KEYALGORITHM_ED448, publicKey.getAlgorithm())) {
                 ret = true;
             }
          }
        return ret;
    }

    /**
     * Simple method that looks at the certificate and determines, from EJBCA's standpoint, which signature algorithm it is
     *
     * @param cert the cert to examine
     * @return Signature algorithm name from AlgorithmConstants.SIGALG_SHA1_WITH_RSA etc.
     */
    public static String getSignatureAlgorithm(Certificate cert) {
        String signatureAlgorithm = null;
        String certSignatureAlgorithm = CertTools.getCertSignatureAlgorithmNameAsString(cert);

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
            } else if (!certSignatureAlgorithm.contains("MGF1")) {
                if (certSignatureAlgorithm.contains("MD5")) {
                    signatureAlgorithm = "MD5WithRSA";
                } else if (certSignatureAlgorithm.contains("SHA1")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
                } else if (certSignatureAlgorithm.contains("256")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
                } else if (certSignatureAlgorithm.contains("384")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_RSA;
                } else if (certSignatureAlgorithm.contains("512")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_RSA;
                }
            } else {
                if (certSignatureAlgorithm.contains("SHA1")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.contains("256")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.contains("384")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_RSA_AND_MGF1;
                } else if (certSignatureAlgorithm.contains("512")) {
                    signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_RSA_AND_MGF1;
                }
            }
        } else if (publickey instanceof DSAPublicKey) {
            if (certSignatureAlgorithm.contains("SHA1")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            } else if (certSignatureAlgorithm.contains("256")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_DSA;
            }
        } else if ( publickey instanceof BCEdDSAPublicKey ) {
            // EdDSA algorithms are named the same as the key algo, i.e. Ed25519 or Ed488
            signatureAlgorithm = publickey.getAlgorithm();
        } else {
            if (certSignatureAlgorithm.contains("SHA3-")) {
                if (certSignatureAlgorithm.contains("256")) {
                    return AlgorithmConstants.SIGALG_SHA3_256_WITH_ECDSA;
                } else if (certSignatureAlgorithm.contains("384")) {
                    return AlgorithmConstants.SIGALG_SHA3_384_WITH_ECDSA;
                } else if (certSignatureAlgorithm.contains("512")) {
                    return AlgorithmConstants.SIGALG_SHA3_512_WITH_ECDSA;
                }
            } else if (certSignatureAlgorithm.contains("256")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            } else if (certSignatureAlgorithm.contains("224")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA;
            } else if (certSignatureAlgorithm.contains("384")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA;
            } else if (certSignatureAlgorithm.contains("512")) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA;
            } else if (certSignatureAlgorithm.contains("ECDSA")) {
                // From x509cert.getSigAlgName(), SHA1withECDSA only returns name ECDSA
                signatureAlgorithm = AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA;
            } else if (AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled() && certSignatureAlgorithm.equalsIgnoreCase(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410)) {
                signatureAlgorithm = AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
            } else if (AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled() && certSignatureAlgorithm.equalsIgnoreCase(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145)) {
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
     * @param sigAlgOid OID of a signatureAlgorithm, for example PKCSObjectIdentifiers.sha256WithRSAEncryption.getId() (1.2.840.113549.1.1.11)
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

        if (sigAlgOid.equals(EdECObjectIdentifiers.id_Ed25519.getId()) || sigAlgOid.equals(EdECObjectIdentifiers.id_Ed448.getId())) {
            return CMSSignedGenerator.DIGEST_SHA256;
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
            oid = new ASN1ObjectIdentifier(AlgorithmConstants.DSTU4145_OID);
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ED25519)) {
            oid = EdECObjectIdentifiers.id_Ed25519;
        } else if (keyAlg.equals(AlgorithmConstants.KEYALGORITHM_ED448)) {
            oid = EdECObjectIdentifiers.id_Ed448;
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

    public static boolean isSigAlgEnabled(String sigAlg) {
        if (AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410.equals(sigAlg)) {
            return AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled();
        } else if (AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145.equals(sigAlg)) {
            return AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled();
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
     * @return a sorted list of aliases for the elliptic curve specified, never null
     */
    public static List<String> getAllCurveAliasesFromAlias(final String alias) {
        final String lowerCaseAlias = alias.toLowerCase(Locale.ROOT);
        for (final Entry<String, List<String>> name : getNamedEcCurvesMap(false).entrySet()) {
            final String lowerCaseCanonicalName = name.getKey().toLowerCase(Locale.ROOT);
            final List<String> lowerCaseAliases = StringTools.toLowerCase(name.getValue());
            if (StringUtils.equals(lowerCaseAlias, lowerCaseCanonicalName) || lowerCaseAliases.contains(lowerCaseAlias)) {
                final List<String> aliases = new ArrayList<>(name.getValue());
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

        if(sigAlgOid.equals(X9ObjectIdentifiers.id_dsa_with_sha1)) {
            return AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
        }
        
        if(sigAlgOid.equals(NISTObjectIdentifiers.dsa_with_sha256)) {
            return AlgorithmConstants.SIGALG_SHA256_WITH_DSA;
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
        if (sigAlgOid.equals(EdECObjectIdentifiers.id_Ed25519)) {
            return AlgorithmConstants.SIGALG_ED25519;
        }
        if (sigAlgOid.equals(EdECObjectIdentifiers.id_Ed448)) {
            return AlgorithmConstants.SIGALG_ED448;
        }
        // GOST3410
        if(AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled() && sigAlgOid.getId().equalsIgnoreCase(AlgorithmConstants.GOST3410_OID)) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
        }
        // DSTU4145
        if(AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled() && sigAlgOid.getId().startsWith(AlgorithmConstants.DSTU4145_OID + ".")) {
            return AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
        }

        return null;
    }

    /**
     * Get a Bouncy Castle elliptic curve parameter specification by OID.
     * 
     * <p>If you only have the name of the curve, use {@link #getEcKeySpecOidFromBcName} 
     * to lookup the OID first.
     * 
     * @param oid the OID of the curve.
     * @return the elliptic curve parameter specification for the curve, or null if the OID is unknown.
     */
    public static org.bouncycastle.jce.spec.ECParameterSpec getEcParameterSpecFromOid(final ASN1ObjectIdentifier oid) {
        if (NISTNamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = NISTNamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (SECNamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = SECNamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (X962NamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = X962NamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (ECGOST3410NamedCurves.getByOIDLazy(oid) != null) {
            final X9ECParameters ecDomainParameters = ECGOST3410NamedCurves.getByOIDLazy(oid).getParameters();
            return new org.bouncycastle.jce.spec.ECParameterSpec(ecDomainParameters.getCurve(), ecDomainParameters.getG(),
                    ecDomainParameters.getN());
        }
        if (TeleTrusTNamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = TeleTrusTNamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (ANSSINamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = ANSSINamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        if (GMNamedCurves.getByOID(oid) != null) {
            final X9ECParameters x9ecParameters = GMNamedCurves.getByOID(oid);
            return new org.bouncycastle.jce.spec.ECParameterSpec(x9ecParameters.getCurve(), x9ecParameters.getG(), x9ecParameters.getN());
        }
        return null;
    }

    /**
     * Returns a {@link java.security.MessageDigest} object given the name of a signature algorithm, e.g. "SHA256withECDSA".
     * 
     * <p>Signature algorithm names are defined in {@link AlgorithmConstants}.
     * 
     * @param signatureAlgorithm the name of the signature algorithm, e.g. "SHA256withECDSA".
     * @return a message digest object able to compute digests with the hash algorithm specified.
     * @throws NoSuchAlgorithmException if the signature algorithm uses an unsupported digest algorithm.
     * @throws NoSuchProviderException if the Bouncy Castle provider is not installed.
     */
    public static MessageDigest getDigestFromAlgoName(final String signatureAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (signatureAlgorithm.startsWith("SHA1")) {
            return MessageDigest.getInstance("SHA1", "BC");
        } else if (signatureAlgorithm.startsWith("SHA224")) {
            return MessageDigest.getInstance("SHA-224", "BC");
        } else if (signatureAlgorithm.startsWith("SHA256")) {
            return MessageDigest.getInstance("SHA-256", "BC");
        } else if (signatureAlgorithm.startsWith("SHA384")) {
            return MessageDigest.getInstance("SHA-384", "BC");
        } else if (signatureAlgorithm.startsWith("SHA512")) {
            return MessageDigest.getInstance("SHA-512", "BC");
        } else if (signatureAlgorithm.startsWith("SHA3-256")) {
            return MessageDigest.getInstance("SHA3-256", "BC");
        } else if (signatureAlgorithm.startsWith("SHA3-384")) {
            return MessageDigest.getInstance("SHA3-384", "BC");
        } else if (signatureAlgorithm.startsWith("SHA3-512")) {
            return MessageDigest.getInstance("SHA3-512", "BC");
        } else if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_256.getId())) {
            return MessageDigest.getInstance("SHA3-256", "BC");
        } else if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_384.getId())) {
            return MessageDigest.getInstance("SHA3-384", "BC");
        } else if (signatureAlgorithm.equals(NISTObjectIdentifiers.id_ecdsa_with_sha3_512.getId())) {
            return MessageDigest.getInstance("SHA3-512", "BC");
        }
        throw new NoSuchAlgorithmException("The signature algorithm " + signatureAlgorithm + " uses an unsupported digest algorithm.");
    }
}
