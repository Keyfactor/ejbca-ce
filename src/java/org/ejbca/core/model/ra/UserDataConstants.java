/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ra;

import java.util.HashMap;

/**
 * @version $Id$
 */
public class UserDataConstants {
    // Constants for Status of user

    public static final int STATUS_NEW = 10;        // New user
    public static final int STATUS_FAILED = 11;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20;// User has been initialized
    public static final int STATUS_INPROCESS = 30;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived
    public static final int STATUS_KEYRECOVERY  = 70; // The user is should use key recovery functions in next certificate generation.
    
    /** These string values maps a status code to a language string in the admin GUI language property files */
    private static final HashMap STATUS_TEXT_TRANS = new HashMap();
    static {
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_NEW),"STATUSNEW");
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_FAILED),"STATUSFAILED"); 
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_INITIALIZED),"STATUSINITIALIZED"); 
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_INPROCESS),"STATUSINPROCESS");
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_GENERATED),"STATUSGENERATED");
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_REVOKED),"STATUSREVOKED");
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_HISTORICAL),"STATUSHISTORICAL");
    	STATUS_TEXT_TRANS.put(new Integer(STATUS_KEYRECOVERY),"STATUSKEYRECOVERY");
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
    private static final HashMap STATUS_TEXT = new HashMap();
    static {
    	STATUS_TEXT.put(new Integer(STATUS_NEW),"NEW");
    	STATUS_TEXT.put(new Integer(STATUS_FAILED),"FAILED"); 
    	STATUS_TEXT.put(new Integer(STATUS_INITIALIZED),"INITIALIZED"); 
    	STATUS_TEXT.put(new Integer(STATUS_INPROCESS),"INPROCESS");
    	STATUS_TEXT.put(new Integer(STATUS_GENERATED),"GENERATED");
    	STATUS_TEXT.put(new Integer(STATUS_REVOKED),"REVOKED");
    	STATUS_TEXT.put(new Integer(STATUS_HISTORICAL),"HISTORICAL");
    	STATUS_TEXT.put(new Integer(STATUS_KEYRECOVERY),"KEYRECOVERY");
    }

    public static String getStatusText(int status) {
    	String ret = null;
    	Object o =  STATUS_TEXT.get(Integer.valueOf(status));
    	if (o != null) {
    		ret = (String)o;
    	}
    	return ret;
    }

}
