package se.anatom.ejbca.ra;

public interface UserDataConstants {
    // Constants for Status of user

    public static final int STATUS_NEW = 10;        // New user
    public static final int STATUS_FAILED = 11;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20;// User has been initialized
    public static final int STATUS_INPROCESS = 30;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived
    public static final int STATUS_KEYRECOVERY  = 70; // The user is should use key recovery functions in next certificate generation.

}
