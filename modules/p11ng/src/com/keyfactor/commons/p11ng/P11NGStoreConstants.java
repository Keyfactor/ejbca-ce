/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng;

import org.pkcs11.jacknji11.CKA;

/**
 * Class containing constants common for caching implementation of P11NG provider.
 */
public class P11NGStoreConstants {

    public static final String CKA_LABEL = "LABEL";
    public static final String CKA_ID = "ID";
    public static final String CKA_SUBJECT = "SUBJECT";
    public static final String CKA_VALUE = "VALUE";
    public static final String CKA_MODULUS = "MODULUS";
    public static final String CKA_EC_POINT = "EC_POINT";
    public static final String CKA_EC_PARAMS = "EC_PARAMS";
    public static final String CKA_PUBLIC_EXPONENT = "PUBLIC_EXPONENT";
    
    public static final String CKO_PUBLIC_KEY = "PUBLIC_KEY";
    public static final String CKO_PRIVATE_KEY = "PRIVATE_KEY";
    public static final String CKO_SECRET_KEY = "SECRET_KEY";
    public static final String CKO_CERTIFICATE = "CERTIFICATE";

    /**
     * Method that takes a P11 constant name and translates it into the corresponding PKCS#11 ID. 
     * Note that not all possible PKCS#11 values are defined here, only the ones we happen to use.
     * 
     * @param name For example "LABEL", or "MODULUS", supported names are constants in this class, i.e. P11NGStoreConstants.CKA_LABEL
     * @return the corresponding long ID value CKA.LABEL (3/0x3) or CKA.MODULUS (288/0x120)
     * @throws IllegalArgumentException if the passed in name does not have a defined ID, it can simply be that it has not been added here yet
     */
    public static final long nameToID(String name) {
        switch (name) {
        case CKA_LABEL:
            return CKA.LABEL;
        case CKA_ID:
            return CKA.ID;
        case CKA_SUBJECT:
            return CKA.SUBJECT;
        case CKA_MODULUS:
            return CKA.MODULUS;
        case CKA_EC_POINT:
            return CKA.EC_POINT;
        case CKA_EC_PARAMS:
            return CKA.EC_PARAMS;
        case CKA_PUBLIC_EXPONENT:
            return CKA.PUBLIC_EXPONENT;
        case CKA_VALUE:
            return CKA.VALUE;
        }
        throw new IllegalArgumentException("Name " + name + " does not have a defined ID");
    }
}
