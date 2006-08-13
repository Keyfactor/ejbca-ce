package org.ejbca.core.model.ra;

import java.util.HashMap;

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
    
    public static final HashMap STATUS_TEXT = new HashMap();
    
    static {
    	STATUS_TEXT.put(new Integer(STATUS_NEW),"STATUSNEW");
    	STATUS_TEXT.put(new Integer(STATUS_FAILED),"STATUSFAILED"); 
    	STATUS_TEXT.put(new Integer(STATUS_INITIALIZED),"STATUSINITIALIZED"); 
    	STATUS_TEXT.put(new Integer(STATUS_INPROCESS),"STATUSINPROCESS");
    	STATUS_TEXT.put(new Integer(STATUS_GENERATED),"STATUSGENERATED");
    	STATUS_TEXT.put(new Integer(STATUS_REVOKED),"STATUSREVOKED");
    	STATUS_TEXT.put(new Integer(STATUS_HISTORICAL),"STATUSHISTORICAL");
    	STATUS_TEXT.put(new Integer(STATUS_KEYRECOVERY),"STATUSKEYRECOVERY");
    }
        

}
