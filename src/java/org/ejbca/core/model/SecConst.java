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
 
package org.ejbca.core.model;

/**
 * Constants for users and certificates. Constants for Type of user: Type is constructed as a mask
 * since one user can be of several types. To test a user type:
 * <pre>
 * if (((type & USER_ENDUSER) == USER_ENDUSER) && ((type & USER_CAADMIN) == USER_ADMINISTOR) || ...
 *    ...
 * </pre>
 * Bit usage: bits 0-7   (1:st byte):  user types bits 8-15  (2:nd byte):  unused bits 16-23 (3:rd
 * byte):  unused bits 24-30 (4:th byte):  unused Constants for certificates are simple integer
 * types. Constants for Token Types Token type is constructed of integer constants since only one
 * token type can be generated.
 *
 * @version $Id$
 */
public final class SecConst {
    // User types

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


    // Token types.

    /** Indicates that a browser generated token should be used. */
    public static final int TOKEN_SOFT_BROWSERGEN = 1;

    /** Indicates that a p12 token should be generated. */
    public static final int TOKEN_SOFT_P12 = 2;

    /** Indicates that a jks token should be generated. */
    public static final int TOKEN_SOFT_JKS = 3;

    /** Indicates that a pem token should be generated. */
    public static final int TOKEN_SOFT_PEM = 4;

    /** All values equal or below this constant should be treated as a soft token. */
    public static final int TOKEN_SOFT = 100;
    
    public static final String[] TOKENTEXTS = {"TOKENSOFTUSERGENERATED","TOKENSOFTP12","TOKENSOFTJKS","TOKENSOFTPEM"};
    
    public static final int[]    TOKENIDS   = {SecConst.TOKEN_SOFT_BROWSERGEN,SecConst.TOKEN_SOFT_P12,SecConst.TOKEN_SOFT_JKS,SecConst.TOKEN_SOFT_PEM};

    /** Constant indicating a standard hard token, defined in scaper. */
    public static final int TOKEN_HARD_DEFAULT = 101;

    /** Constant indicating a eid hard token.  
     *   OBSERVE This class should only be used for backward compatibility with EJBCA 2.0
     */
    public static final int TOKEN_EID = 102;
    
    /**Constant indicating a swedish eid hard token.  */
    public static final int TOKEN_SWEDISHEID = 103;

    /**Constant indicating a enhanced eid hard token.  */
    public static final int TOKEN_ENHANCEDEID = 104;
    
    /**Constant indicating a enhanced eid hard token.  */
    public static final int TOKEN_TURKISHEID = 105;
    
    // Certificate profiles.

    public static final int NO_HARDTOKENISSUER            = 0;

    /** Used when no certificate profile id value is available */
    // TODO: remove all these CERTPROFILE_ because they are in CertificateProfileConstants in CESeCore
    public static final int CERTPROFILE_NO_PROFILE            = 0; 
    public static final int CERTPROFILE_FIXED_ENDUSER         = 1;
    public static final int CERTPROFILE_FIXED_SUBCA           = 2;
    public static final int CERTPROFILE_FIXED_ROOTCA          = 3;
	public static final int CERTPROFILE_FIXED_OCSPSIGNER      = 4;
	public static final int CERTPROFILE_FIXED_HARDTOKENAUTH   = 5;
	public static final int CERTPROFILE_FIXED_HARDTOKENAUTHENC= 6;
	public static final int CERTPROFILE_FIXED_HARDTOKENENC    = 7;
	public static final int CERTPROFILE_FIXED_HARDTOKENSIGN   = 8;
    public static final int CERTPROFILE_FIXED_SERVER          = 9;

    public static final int EMPTY_ENDENTITYPROFILE = 1;

    /** Used in end entity profiles and service workers */
    public static final int ALLCAS = 1;
        
    /**
     * Constants defining range of id's reserved for fixed end entity profile
     */
    public static final int PROFILE_NO_PROFILE = 0;

    
    /**
     * Constants used in the RSASignSessionBean indicating the userdata defined CA should be used.
     */
    public static final int CAID_USEUSERDEFINED = 0;

    /** Constant used to determine the size of the result from SQL select queries */
    public static final int MAXIMUM_QUERY_ROWCOUNT = 500; 
    
    
    /** Constants used to indicate status of a CA. */
    public static final int CA_ACTIVE = 1;
    public static final int CA_WAITING_CERTIFICATE_RESPONSE = 2;
    public static final int CA_EXPIRED = 3;
    public static final int CA_REVOKED = 4;
    public static final int CA_OFFLINE = 5;
    public static final int CA_EXTERNAL = 6;
    
    /** signs certificates issued by the CA */
    public static final int CAKEYPURPOSE_CERTSIGN            = 1;
    /** igns CRLs issues by the CA */
    public static final int CAKEYPURPOSE_CRLSIGN             = 2;
    /** encrypts entity keys stored in the database for key recovery */
    public static final int CAKEYPURPOSE_KEYENCRYPT          = 3;
    /** used for testing if the CA token is functioning and on-line */
    public static final int CAKEYPURPOSE_KEYTEST             = 4;
    /** encrypts hard token PIN/PUK codes etc */
    public static final int CAKEYPURPOSE_HARDTOKENENCRYPT    = 5;
    /** The CAs previous signing key, if any exists */
    public static final int CAKEYPURPOSE_CERTSIGN_PREVIOUS   = 6;
    /** The CAs next signing key, if any exists */
    public static final int CAKEYPURPOSE_CERTSIGN_NEXT       = 7;

    // Certificate request types
    public static final int CERT_REQ_TYPE_PKCS10	= 0;
    public static final int CERT_REQ_TYPE_CRMF		= 1;
    public static final int CERT_REQ_TYPE_SPKAC     = 2;
	public static final int CERT_REQ_TYPE_PUBLICKEY = 3;
	public static final int CERT_REQ_TYPE_CVC       = 4;

    
    // Certificate response types
    public static final int CERT_RES_TYPE_CERTIFICATE	 = 0;
    public static final int CERT_RES_TYPE_PKCS7      	 = 1;
    public static final int CERT_RES_TYPE_PKCS7WITHCHAIN = 2;
    
    /**
     * Default key lengths. Users are allowed to choose from these key lengths when
     * lookup of available bit lengths fails. 
     * @see org.ejbca.ui.web.pub.ApplyBean
     */
    public static final int[] DEFAULT_KEY_LENGTHS = new int[] {512, 1024, 2048};

    /**
     * Prevents creation of new SecConst
     */
    private SecConst() {
    }
    
    /**
     * @return true is certificate profile identified by profileId is fixed
     */
    // TODO: remove this method because it is in CertificateProfileConstants in CESeCore
    public static boolean isFixedCertificateProfile(final int profileId) {
    	return (
    			profileId == SecConst.CERTPROFILE_FIXED_ENDUSER ||
    			profileId == SecConst.CERTPROFILE_FIXED_SUBCA ||
    			profileId == SecConst.CERTPROFILE_FIXED_ROOTCA ||
    			profileId == SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH ||
    			profileId == SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC ||
    			profileId == SecConst.CERTPROFILE_FIXED_HARDTOKENENC ||
    			profileId == SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN ||
    			profileId == SecConst.CERTPROFILE_FIXED_OCSPSIGNER ||
    			profileId == SecConst.CERTPROFILE_FIXED_SERVER );
    }
    
    // Certificate status representations
    /** Certificate doesn't belong to anyone */
    public static final int CERT_UNASSIGNED = 0;
    /** Assigned, but not yet active */
    public static final int CERT_INACTIVE = 10;
    /** Certificate is active and assigned */
    public static final int CERT_ACTIVE = 20;
    /** Certificate is still active and the user is notified that it 
     * will soon expire. */
    public static final int CERT_NOTIFIEDABOUTEXPIRATION = 21;
    /** Certificate is temporarily blocked (reversible) */
    public static final int CERT_TEMP_REVOKED = 30;
    /** Certificate is permanently blocked (terminated) */
    public static final int CERT_REVOKED = 40;
    // there was previously a status 50, EXPIRED here as well, but it was not used so
    // it was removed to avoid misunderstandings.
    /** Certificate is expired and kept for archive purpose */
    public static final int CERT_ARCHIVED = 60;

    // Constants used in certificate generation and publication.
    /** Certificate belongs to an end entity. */
    public static final int CERTTYPE_ENDENTITY  =     0x1;    
    /** Certificate belongs to a sub ca. */
    public static final int CERTTYPE_SUBCA      =     0x2;
    /** Certificate belongs to a root ca. */
    public static final int CERTTYPE_ROOTCA     =     0x8;        
    /** Certificate belongs on a hard token. */
    public static final int CERTTYPE_HARDTOKEN  =     0x16;

    // Certificate types used to create certificates
    /** Certificate used for encryption. */
    public static final int CERT_TYPE_ENCRYPTION = 0x1;
    /** Certificate used for digital signatures. */
    public static final int CERT_TYPE_SIGNATURE = 0x2;
    /** Certificate used for both encryption and signatures. */
    public static final int CERT_TYPE_ENCSIGN = 0x3;

	// Revocation reasons identifiers
    public static final String[] reasontexts = {
        "REV_UNSPECIFIED",			"REV_KEYCOMPROMISE",	"REV_CACOMPROMISE",
        "REV_AFFILIATIONCHANGED",	"REV_SUPERSEDED",		"REV_CESSATIONOFOPERATION",
        "REV_CERTIFICATEHOLD",		"REV_UNUSED",			"REV_REMOVEFROMCRL",
        "REV_PRIVILEGEWITHDRAWN",	"REV_AACOMPROMISE"
    };
    public static final int HIGN_REASON_BOUNDRARY = 11;


}