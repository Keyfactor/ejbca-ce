/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.jacknji11;

/**
 * Constants for Utimaco CP5.
 * 
 * Some of this could be contributed to upstreams CKM and CKU classes.
 */
public interface CP5Constants {

    // TODO: The CKM_ constants could be contributed to JackNJ11 class CKM if prefix properly with VENDOR_ etc.
    // Utimaco CP5, eIDAS HSM
    public static final long CKM_CP5_INITIALIZE          = 0x8000C951L; // CP5 initialize key
    public static final long CKM_CP5_AUTHORIZE           = 0x8000C952L; // CP5 authorize key
    public static final long CKM_CP5_CHANGEAUTHDATA      = 0x8000C952L; // CP5 change authorization data

    // TODO: The CKU_ constants could be contributed to JackNJ11 class CKU if prefixed properly with VENDOR_ etc.
    public static final long CKU_CS_GENERIC = 0x83;// login type for CryptoServer user (generic login of all CryptoServer user)

    public static final long CP5_KEY_AUTH_PROT_RSA_PSS_SHA256 = (0x01);
    public static final long CP5_KEY_AUTH_PROT_RSA_PKCS1_5_SHA256 = (0x02);

}
