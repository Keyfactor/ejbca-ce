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

/** Constants for End Entity types 
 * 
 * Based on EJBCA version: SecConst.java 11082 2011-01-07 09:14:46Z anatom
 * 
 * @version $Id$
 */
public final class EndEntityConstants {

	//
    // User types
	//
	
    /** Dummy type. */
    public static final int USER_INVALID = 0x0;
    /** This is an end user certificate (default). */
    public static final int USER_ENDUSER = 0x1;
    /** This user is an administrator. */
    public static final int USER_ADMINISTRATOR = 0x40;
    /** This users keystores are key recoverable. */
    public static final int USER_KEYRECOVERABLE = 0x80;
    /** Notification will be sent to this users emailaddress */
    public static final int USER_SENDNOTIFICATION = 0x100;    
    /** Registration data will be printed for this user */
    public static final int USER_PRINT = 0x200;

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

}
