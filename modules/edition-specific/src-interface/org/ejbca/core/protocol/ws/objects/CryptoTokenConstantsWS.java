/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ws.objects;

public class CryptoTokenConstantsWS {

    // -----------------
    // Soft Crypto Token
    //------------------
    /** If set, no default password allowed for this soft cryptotoken */
    public static final String NODEFAULTPWD = org.cesecore.keys.token.SoftCryptoToken.NODEFAULTPWD;
    /** Boolean indicating if it should be allowed to extract private keys */
    public static final String ALLOW_EXTRACTABLE_PRIVATE_KEY = org.cesecore.keys.token.CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY;
    //public static final String ALLOW_NONEXISTING_SLOT_PROPERTY = org.cesecore.keys.token.CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY;
    
    // -------------------
    // PKCS11 Crypto Token
    // -------------------
    /** Specific to PKCS#11. The slot label value */
    public static final String SLOT_LABEL_VALUE = org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_VALUE;
    /** Specific to PKCS#11. The slot label type */
    public static final String SLOT_LABEL_TYPE = org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_TYPE;
    /** Specific to PKCS#11. The path to the shared PKCS11 library */
    public static final String SHLIB_LABEL_KEY = org.cesecore.keys.token.PKCS11CryptoToken.SHLIB_LABEL_KEY;
    /** Specific to PKCS#11. The attributes label */
    public static final String ATTRIB_LABEL_KEY = org.cesecore.keys.token.PKCS11CryptoToken.ATTRIB_LABEL_KEY;
    /** A user defined name of the slot provider. Used in order to be able to have two different providers
     * (with different PKCS#11 attributes) for the same slot. If this is not set (null), the default
     * java provider name is used (SunPKCS11-pkcs11LibName-slotNr for example SunPKCS11-libcryptoki.so-slot1).
     */
    public final static String TOKEN_FRIENDLY_NAME = org.cesecore.keys.token.PKCS11CryptoToken.TOKEN_FRIENDLY_NAME;
    
}
