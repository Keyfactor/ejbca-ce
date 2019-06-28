/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

/**
 * Class containing constants common for caching implementation of P11NG provider.
 * 
 * @author Vinay Singh
 * @version $Id$
 */
public class P11NGStoreConstants {

    public static final String CKA_LABEL = "LABEL";
    public static final String CKA_ID = "ID";
    public static final String CKA_SUBJECT = "SUBJECT";
    public static final String CKA_VALUE = "VALUE";

    public static final String CKO_PRIVATE_KEY = "PRIVATE_KEY";
    public static final String CKO_SECRET_KEY = "SECRET_KEY";
    public static final String CKO_CERTIFICATE = "CERTIFICATE";

}
