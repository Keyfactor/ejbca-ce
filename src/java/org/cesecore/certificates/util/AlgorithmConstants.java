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

/** Constants for digital signature algorithms.
 * 
 * @version $Id$
 */
public final class AlgorithmConstants {

    public static final String SIGALG_SHA1_WITH_RSA            = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA          = "SHA256WithRSA";
    public static final String SIGALG_SHA384_WITH_RSA          = "SHA384WithRSA";
    public static final String SIGALG_SHA512_WITH_RSA          = "SHA512WithRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA          = "SHA1withECDSA";   
    public static final String SIGALG_SHA224_WITH_ECDSA        = "SHA224withECDSA";   
    public static final String SIGALG_SHA256_WITH_ECDSA        = "SHA256withECDSA";   
    public static final String SIGALG_SHA384_WITH_ECDSA        = "SHA384withECDSA";   
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256WithRSAAndMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1   = "SHA1WithRSAAndMGF1"; // Not possible to select in Admin-GUI    
    public static final String SIGALG_SHA1_WITH_DSA            = "SHA1WithDSA";

    /** Signature algorithms available to choose from */    
    public static final String[] AVAILABLE_SIGALGS = {SIGALG_SHA1_WITH_RSA, SIGALG_SHA256_WITH_RSA, SIGALG_SHA384_WITH_RSA, SIGALG_SHA512_WITH_RSA, SIGALG_SHA256_WITH_RSA_AND_MGF1, SIGALG_SHA1_WITH_ECDSA, SIGALG_SHA224_WITH_ECDSA, SIGALG_SHA256_WITH_ECDSA, SIGALG_SHA384_WITH_ECDSA, SIGALG_SHA1_WITH_DSA};
    
    public static final String KEYALGORITHM_RSA   = "RSA";
    public static final String KEYALGORITHM_ECDSA = "ECDSA";
    public static final String KEYALGORITHM_DSA   = "DSA";
    
    private AlgorithmConstants () {} // Not for instantiation
}
