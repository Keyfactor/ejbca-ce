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
 * 
 * @version $Id$
 */
public final class AlgorithmConstants {

    public static final String SIGALG_MD5_WITH_RSA             = "MD5WithRSA";
    public static final String SIGALG_SHA1_WITH_RSA            = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA          = "SHA256WithRSA";
    public static final String SIGALG_SHA384_WITH_RSA          = "SHA384WithRSA";
    public static final String SIGALG_SHA512_WITH_RSA          = "SHA512WithRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA          = "SHA1withECDSA";
    public static final String SIGALG_SHA224_WITH_ECDSA        = "SHA224withECDSA";
    public static final String SIGALG_SHA256_WITH_ECDSA        = "SHA256withECDSA";
    public static final String SIGALG_SHA384_WITH_ECDSA        = "SHA384withECDSA";
    public static final String SIGALG_SHA512_WITH_ECDSA        = "SHA512withECDSA";
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256WithRSAandMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1   = "SHA1WithRSAandMGF1"; // Not possible to select in Admin-GUI
    public static final String SIGALG_SHA1_WITH_DSA            = "SHA1WithDSA";
    public static final String SIGALG_GOST3411_WITH_ECGOST3410 = "GOST3411withECGOST3410";
    public static final String SIGALG_GOST3411_WITH_DSTU4145   = "GOST3411withDSTU4145";

    /**
     * Signature algorithms available to choose from.
     * Call AlgorithmTools.isSigAlgEnabled() to determine if a given sigalg is enabled and should be shown in the UI.
     */
    public static final String[] AVAILABLE_SIGALGS = { SIGALG_SHA1_WITH_RSA, SIGALG_SHA256_WITH_RSA, SIGALG_SHA384_WITH_RSA, SIGALG_SHA512_WITH_RSA,
            SIGALG_SHA256_WITH_RSA_AND_MGF1, SIGALG_SHA1_WITH_ECDSA, SIGALG_SHA224_WITH_ECDSA, SIGALG_SHA256_WITH_ECDSA, SIGALG_SHA384_WITH_ECDSA,
            SIGALG_SHA512_WITH_ECDSA, SIGALG_SHA1_WITH_DSA, SIGALG_GOST3411_WITH_ECGOST3410, SIGALG_GOST3411_WITH_DSTU4145 };
  
    public static final String KEYALGORITHM_RSA         = "RSA";
    public static final String KEYALGORITHM_EC          = "EC";
    public static final String KEYALGORITHM_ECDSA       = "ECDSA"; //The same as "EC", just named differently sometimes. "EC" and "ECDSA" should be handled in the same way
    public static final String KEYALGORITHM_DSA         = "DSA";
    public static final String KEYALGORITHM_ECGOST3410  = "ECGOST3410";
    public static final String KEYALGORITHM_DSTU4145    = "DSTU4145";
    
    public static final String KEYSPECPREFIX_ECGOST3410 = "GostR3410-";
    
    public static final List<String> BLACKLISTED_EC_CURVES = Arrays.asList(new String[]{
            // Can't be generated with BouncyCastle 1.5.4
            "FRP256v1",
    });

    private AlgorithmConstants () {} // Not for instantiation
}
