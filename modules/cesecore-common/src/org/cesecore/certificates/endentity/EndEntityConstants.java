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
package org.cesecore.certificates.endentity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/** Constants for End Entity types 
 * 
 * @version $Id$
 */
public final class EndEntityConstants {
	
    //
    // User status codes
    //
    public static final int STATUS_NEW = 10;        // New user
    public static final int STATUS_FAILED = 11;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20;// User has been initialized
    public static final int STATUS_INPROCESS = 30;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived
    public static final int STATUS_KEYRECOVERY  = 70; // The user is should use key recovery functions in next certificate generation.
    public static final int STATUS_WAITINGFORAPPROVAL = 80; // the operation is waiting to be approved before execution. This status 
                                                            // is never stored in the database, but is used transiently when a request 
                                                            // is not stored because it's waiting for approval. This status is primarily 
                                                            // used to send the right notification note when a request is waiting for approval.

    //
    // Token types.
    //
    /** Indicates that a user generated token should be used, i.e not token generated but we expect a request and will create a certificate */
    public static final int TOKEN_USERGEN = 1;
    /** Indicates that a p12 token should be generated. */
    public static final int TOKEN_SOFT_P12 = 2;
    /** Indicates that a jks token should be generated. */
    public static final int TOKEN_SOFT_JKS = 3;
    /** Indicates that a pem token should be generated. */
    public static final int TOKEN_SOFT_PEM = 4;
    /** All values equal or below this constant should be treated as a soft token. */
    public static final int TOKEN_SOFT = 100;
    
    //
    // Names and language strings of statuses
    //
    /** These string values maps a status code to a language string in the admin GUI language property files */
    private static final HashMap<Integer, String> STATUS_TEXT_TRANS = new HashMap<Integer, String>();
    static {
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_NEW),"STATUSNEW");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_FAILED),"STATUSFAILED"); 
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_INITIALIZED),"STATUSINITIALIZED"); 
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_INPROCESS),"STATUSINPROCESS");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_GENERATED),"STATUSGENERATED");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_REVOKED),"STATUSREVOKED");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_HISTORICAL),"STATUSHISTORICAL");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_KEYRECOVERY),"STATUSKEYRECOVERY");
        STATUS_TEXT_TRANS.put(Integer.valueOf(STATUS_WAITINGFORAPPROVAL),"STATUSWAITINGFORAPPROVAL");
    }

    public static String getTranslatableStatusText(int status) {
        String ret = null;
        Object o =  STATUS_TEXT_TRANS.get(Integer.valueOf(status));
        if (o != null) {
            ret = (String)o;
        }
        return ret;
    }

    /** These string values maps a status code to a plain string */
    private static final HashMap<Integer, String> STATUS_TEXT = new HashMap<Integer, String>();
    static {
        STATUS_TEXT.put(Integer.valueOf(STATUS_NEW),"NEW");
        STATUS_TEXT.put(Integer.valueOf(STATUS_FAILED),"FAILED"); 
        STATUS_TEXT.put(Integer.valueOf(STATUS_INITIALIZED),"INITIALIZED"); 
        STATUS_TEXT.put(Integer.valueOf(STATUS_INPROCESS),"INPROCESS");
        STATUS_TEXT.put(Integer.valueOf(STATUS_GENERATED),"GENERATED");
        STATUS_TEXT.put(Integer.valueOf(STATUS_REVOKED),"REVOKED");
        STATUS_TEXT.put(Integer.valueOf(STATUS_HISTORICAL),"HISTORICAL");
        STATUS_TEXT.put(Integer.valueOf(STATUS_KEYRECOVERY),"KEYRECOVERY");
    }

    public static String getStatusText(int status) {
        String ret = null;
        Object o =  STATUS_TEXT.get(Integer.valueOf(status));
        if (o != null) {
            ret = (String)o;
        }
        return ret;
    }
    
    public static Collection<Integer> getAllStatusCodes() {
        List<Integer> statuses = new ArrayList<Integer>(STATUS_TEXT.keySet());
        Collections.sort(statuses);
        return statuses;
    }

}
