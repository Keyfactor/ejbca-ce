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
package org.cesecore.keys.token;

/**
 * @version $Id$
 */
public final class CryptoTokenConstants {
    public static final String SIGNKEYALGORITHM  = "SIGNKEYALGORITHM";
    public static final String ENCKEYALGORITHM   = "ENCKEYALGORITHM";
    public static final String KEYSTORE          = "KEYSTORE";
    
    /** Property for storing the AWS KMS region name in the crypto token properties.
     * KMS specific, this is a string that will be part of the REST call URI 
     * https://kms." + region + ".amazonaws.com, i.e. https://kms.us-east-1.amazonaws.com 
     */
    public static final String AWSKMS_REGION = "kmsRegion";
    
    /** Property for storing the accessKeyID used to access the AWS KMS, in the crypto token properties.
     */ 
    public static final String AWSKMS_ACCESSKEYID = "kmsSignInAccessKeyID";
    
    /**
     * Property for storing the base URL for the Fortanix DRM REST API ("https://apps.smartkey.io" is the default)
     */
    public static final String FORTANIX_BASE_ADDRESS = "fortanixBaseAddress";
    public static final String FORTANIX_BASE_ADDRESS_DEFAULT = "https://apps.smartkey.io";

}
