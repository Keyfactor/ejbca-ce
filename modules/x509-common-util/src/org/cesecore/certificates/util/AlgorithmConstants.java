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

import java.util.Arrays;
import java.util.List;

/** Constants for digital signature algorithms.
 */
public final class AlgorithmConstants {

    public static final String SIGALG_MD5_WITH_RSA             = "MD5WithRSA";
    public static final String SIGALG_SHA1_WITH_RSA            = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA          = "SHA256WithRSA";
    public static final String SIGALG_SHA384_WITH_RSA          = "SHA384WithRSA";
    public static final String SIGALG_SHA512_WITH_RSA          = "SHA512WithRSA";
    public static final String SIGALG_SHA3_256_WITH_RSA        = "SHA3-256withRSA";
    public static final String SIGALG_SHA3_384_WITH_RSA        = "SHA3-384withRSA";
    public static final String SIGALG_SHA3_512_WITH_RSA        = "SHA3-512withRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA          = "SHA1withECDSA";
    public static final String SIGALG_SHA224_WITH_ECDSA        = "SHA224withECDSA";
    public static final String SIGALG_SHA256_WITH_ECDSA        = "SHA256withECDSA";
    public static final String SIGALG_SHA384_WITH_ECDSA        = "SHA384withECDSA";
    public static final String SIGALG_SHA512_WITH_ECDSA        = "SHA512withECDSA";
    public static final String SIGALG_SHA3_256_WITH_ECDSA      = "SHA3-256withECDSA";
    public static final String SIGALG_SHA3_384_WITH_ECDSA      = "SHA3-384withECDSA";
    public static final String SIGALG_SHA3_512_WITH_ECDSA      = "SHA3-512withECDSA";
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256withRSAandMGF1";
    public static final String SIGALG_SHA384_WITH_RSA_AND_MGF1 = "SHA384withRSAandMGF1";
    public static final String SIGALG_SHA512_WITH_RSA_AND_MGF1 = "SHA512withRSAandMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1   = "SHA1withRSAandMGF1"; // Not possible to select in Admin-GUI
    public static final String SIGALG_SHA1_WITH_DSA            = "SHA1WithDSA";
    public static final String SIGALG_SHA256_WITH_DSA          = "SHA256WithDSA";
    public static final String SIGALG_GOST3411_WITH_ECGOST3410 = "GOST3411withECGOST3410";
    public static final String SIGALG_GOST3411_WITH_DSTU4145   = "GOST3411withDSTU4145";
    public static final String SIGALG_ED25519                  = "Ed25519";
    public static final String SIGALG_ED448                    = "Ed448";
    public static final String SIGALG_FALCON512                = "FALCON-512";
    public static final String SIGALG_FALCON1024               = "FALCON-1024";
    public static final String SIGALG_DILITHIUM2               = "DILITHIUM2";
    public static final String SIGALG_DILITHIUM3               = "DILITHIUM3";
    public static final String SIGALG_DILITHIUM5               = "DILITHIUM5";

    /**
     * Signature algorithms available to choose from.
     * Call AlgorithmTools.isSigAlgEnabled() to determine if a given sigalg is enabled and should be shown in the UI.
     */
    public static final String[] AVAILABLE_SIGALGS = {
        SIGALG_SHA1_WITH_RSA,
        SIGALG_SHA256_WITH_RSA,
        SIGALG_SHA384_WITH_RSA,
        SIGALG_SHA512_WITH_RSA,
        SIGALG_SHA3_256_WITH_RSA,
        SIGALG_SHA3_384_WITH_RSA,
        SIGALG_SHA3_512_WITH_RSA,
        SIGALG_SHA256_WITH_RSA_AND_MGF1,
        SIGALG_SHA384_WITH_RSA_AND_MGF1,
        SIGALG_SHA512_WITH_RSA_AND_MGF1,
        SIGALG_SHA1_WITH_ECDSA,
        SIGALG_SHA224_WITH_ECDSA,
        SIGALG_SHA256_WITH_ECDSA,
        SIGALG_SHA384_WITH_ECDSA,
        SIGALG_SHA512_WITH_ECDSA,
        SIGALG_SHA3_256_WITH_ECDSA,
        SIGALG_SHA3_384_WITH_ECDSA,
        SIGALG_SHA3_512_WITH_ECDSA,
        SIGALG_SHA1_WITH_DSA,
        SIGALG_SHA256_WITH_DSA,
        SIGALG_GOST3411_WITH_ECGOST3410,
        SIGALG_GOST3411_WITH_DSTU4145,
        SIGALG_ED25519,
        SIGALG_ED448,
        SIGALG_FALCON512,
        SIGALG_FALCON1024,
        SIGALG_DILITHIUM2,
        SIGALG_DILITHIUM3,
        SIGALG_DILITHIUM5
    };

    public static final String KEYALGORITHM_RSA         = "RSA";
    public static final String KEYALGORITHM_EC          = "EC";
    public static final String KEYALGORITHM_ECDSA       = "ECDSA"; //The same as "EC", just named differently sometimes. "EC" and "ECDSA" should be handled in the same way
    public static final String KEYALGORITHM_DSA         = "DSA";
    public static final String KEYALGORITHM_ED25519     = "Ed25519";
    public static final String KEYALGORITHM_ED448       = "Ed448";
    public static final String KEYALGORITHM_FALCON512   = "FALCON-512";
    public static final String KEYALGORITHM_FALCON1024  = "FALCON-1024";
    public static final String KEYALGORITHM_DILITHIUM2  = "DILITHIUM2";
    public static final String KEYALGORITHM_DILITHIUM3  = "DILITHIUM3";
    public static final String KEYALGORITHM_DILITHIUM5  = "DILITHIUM5";
    public static final String KEYALGORITHM_NTRU        = "NTRU";
    public static final String KEYALGORITHM_ECGOST3410  = "ECGOST3410";
    public static final String KEYALGORITHM_DSTU4145    = "DSTU4145";
    
    public static final String HASHALGORITHM_SHA1 = "SHA1";
    public static final String HASHALGORITHM_SHA224 = "SHA224";
    public static final String HASHALGORITHM_SHA256 = "SHA256";
    public static final String HASHALGORITHM_SHA384 = "SHA384";
    public static final String HASHALGORITHM_SHA512 = "SHA512";
    public static final String HASHALGORITHM_SHA3_256 = "SHA3-256";
    public static final String HASHALGORITHM_SHA3_384 = "SHA3-384";
    public static final String HASHALGORITHM_SHA3_512 = "SHA3-512";

    public static final String KEYSPECPREFIX_ECGOST3410 = "GostR3410-";
    
    public static final String GOST3410_OID = "1.2.643.2.2.3";
    public static final String DSTU4145_OID = "1.2.804.2.1.1.1.1.3.1.1";
    
    //The following curves may be used for ECCDH: P-224, P-256, P-384, P-521, K-233, K-283, K-409, K-571, B-233, B-283, B-409, B-571
    //See https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-ecc-sp800-56ar3.html#name-ecc-cdh-component-test
    public static final List<String> ECCDH_PERMITTED_CURVES = Arrays.asList("secp224r1", "P-224", "prime256v1", "secp256r1", "P-256", "prime384v1", "secp384r1",
            "P-384", "prime521v1", "secp521r1", "P-521", "sect233k1", "K-233", "sect283k1", "K-283", "sect409k1", "K-409", "sect571k1", "K-571",
            "sect233r1", "B-233", "sect283r1", "B-283", "sect309r1", "B-409", "sect571r1", "B-571"

    );
    
    

    public static final List<String> BLACKLISTED_EC_CURVES = Arrays.asList(
            // No blacklisted EC curves at the moment
    );

    // Extra EC curves that we want to include that are not part of the "standard" curves in BC (ECNamedCurveTable.getNames)
    public static final List<String> EXTRA_EC_CURVES = Arrays.asList(
            // Part of CustomNamedCurves in BouncyCastle 1.54
            // Commented out due to experimental nature 2017-04 as the signatures using this currently probably is not correct
            // Should probably wait for edDSA, See ECA-5796 and linked issues.
            //"curve25519",
    );

    private AlgorithmConstants () {} // Not for instantiation
}
