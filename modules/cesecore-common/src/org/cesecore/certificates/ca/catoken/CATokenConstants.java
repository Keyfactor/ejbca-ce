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
package org.cesecore.certificates.ca.catoken;

import java.util.HashMap;
import java.util.Map;

/**
 * Purpose mapping constants to for CryptoToken aliases and related.
 * 
 * @version $Id$
 */
public final class CATokenConstants {

    /** default key used when there is no specific setting for a purpose */
    public static final int CAKEYPURPOSE_DEFAULT             = 0;
    /** signs certificates issued by the CA */
	public static final int CAKEYPURPOSE_CERTSIGN            = 1;
	/** igns CRLs issues by the CA */
	public static final int CAKEYPURPOSE_CRLSIGN             = 2;
	/** encrypts entity keys stored in the database for key recovery */
	public static final int CAKEYPURPOSE_KEYENCRYPT          = 3;
	/** used for testing if the CA token is functioning and on-line */
	public static final int CAKEYPURPOSE_KEYTEST             = 4;
	
	/** Hard Tokens were removed since release 7.1.0. Can't remove this constant though, it might be refecenced in existing customers' CA's */
	@Deprecated
	public static final int CAKEYPURPOSE_HARDTOKENENCRYPT    = 5;
	
	/** The CAs previous signing key, if any exists */
	public static final int CAKEYPURPOSE_CERTSIGN_PREVIOUS   = 6;
	/** The CAs next signing key, if any exists */
	public static final int CAKEYPURPOSE_CERTSIGN_NEXT       = 7;
	
	/** The CAs previous/next default key, if any exists - relevant only for ITS */
	public static final int CAKEYPURPOSE_DEFAULT_PREVIOUS   = 8;
    public static final int CAKEYPURPOSE_DEFAULT_NEXT       = 9;

    public final static int[] ALL_KEY_PURPOSES = new int[] {
        CATokenConstants.CAKEYPURPOSE_CERTSIGN,
        CATokenConstants.CAKEYPURPOSE_CRLSIGN,
        CATokenConstants.CAKEYPURPOSE_KEYENCRYPT,
        CATokenConstants.CAKEYPURPOSE_KEYTEST,
        CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT,
        CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS,
        CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT,
        CATokenConstants.CAKEYPURPOSE_DEFAULT_NEXT
    };

	/** Key strings for token properties matching the above constants, i.e. when doing getPrivateKey(1)
	 * on a CAToken it will try to use the key configured with label certSignKey in the CryptoToken properties. */
	final static public String CAKEYPURPOSE_CERTSIGN_STRING = "certSignKey";
	final static public String CAKEYPURPOSE_CRLSIGN_STRING = "crlSignKey";
	final static public String CAKEYPURPOSE_KEYENCRYPT_STRING = "keyEncryptKey";
	final static public String CAKEYPURPOSE_TESTKEY_STRING = "testKey";
	final static public String CAKEYPURPOSE_DEFAULT_STRING = "defaultKey";
	
	private static final Map<Integer,String> purposeConstantToString = new HashMap<>();
	static {
	    purposeConstantToString.put(CAKEYPURPOSE_CERTSIGN, CAKEYPURPOSE_CERTSIGN_STRING);
	    purposeConstantToString.put(CAKEYPURPOSE_CRLSIGN, CAKEYPURPOSE_CRLSIGN_STRING);
	    purposeConstantToString.put(CAKEYPURPOSE_KEYENCRYPT, CAKEYPURPOSE_KEYENCRYPT_STRING);
	    purposeConstantToString.put(CAKEYPURPOSE_KEYTEST, CAKEYPURPOSE_TESTKEY_STRING);
	    purposeConstantToString.put(CAKEYPURPOSE_DEFAULT, CAKEYPURPOSE_DEFAULT_STRING);
	}
	
	@Deprecated
	final static public String CAKEYPURPOSE_HARDTOKENENCRYPT_STRING = "hardTokenEncrypt";
	
	final static public String CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS = "previousCertSignKey";
	final static public String CAKEYPURPOSE_CERTSIGN_STRING_NEXT = "nextCertSignKey";
	
	// relevant only for ITS
	final static public String CAKEYPURPOSE_DEFAULT_STRING_PREVIOUS = "previousDefaultKey";
	final static public String CAKEYPURPOSE_DEFAULT_STRING_NEXT = "nextDefaultKey";

    /** Previous sequence (matching CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS key) that can be set in CA token properties */
    public static final String PREVIOUS_SEQUENCE_PROPERTY = "previousSequence";
    /** Next sequence (matching CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT key) that can be set in CA token properties */
    public static final String NEXT_SEQUENCE_PROPERTY = "nextSequence";
    
    /**
     * Converts from CAKEYPURPOSE_* integer constants to CAKEYPURPOSE_*_STRING constants.
     * @param purposeConstant CAKEYPURPOSE_* integer constant
     * @return String constant, or null on invalid function argument.
     */
    public static String getPurposeStringFromInteger(final int purposeConstant) {
        return purposeConstantToString.get(purposeConstant);
    }
}
