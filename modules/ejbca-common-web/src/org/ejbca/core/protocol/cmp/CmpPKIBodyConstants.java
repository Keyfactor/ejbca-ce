package org.ejbca.core.protocol.cmp;

public class CmpPKIBodyConstants {
	// Message-specific body elements from RFC 4210
	public static final int INITIALIZATIONREQUEST   =  0;	// Initialization Request
	public static final int INITIALIZATIONRESPONSE  =  1;	// Initialization Response
	public static final int CERTIFICATAIONREQUEST   =  2;	// Certification Request
	public static final int CERTIFICATIONRESPONSE   =  3;	// Certification Response
	public static final int IMPORTEDFROMPKCS10      =  4;	// imported from [PKCS10]
	public static final int POPCHALLENGE            =  5;	// pop Challenge
	public static final int POPRESPONSE             =  6;	// pop Response
	public static final int KEYUPDATEREQUEST        =  7;	// Key Update Request
	public static final int KEYUPDATERESPONSE       =  8;	// Key Update Response
	public static final int KEYRECOVERYREQUEST      =  9;	// Key Recovery Request
	public static final int KEYRECOEVRYRESPONSE     = 10;	// Key Recovery Response
	public static final int REVOCATIONREQUEST       = 11;	// Revocation Request
	public static final int REVOCATIONRESPONSE      = 12;	// Revocation Response
	public static final int CROSSCERTREQUEST        = 13;	// Cross-Cert. Request
	public static final int CROSSCERTRESPONSE       = 14;	// Cross-Cert. Response
	public static final int CAKEYUPDATEANN          = 15;	// CA Key Update Ann.
	public static final int CERTIFICATEANN          = 16;	// Certificate Ann.
	public static final int REVOCATIONANN           = 17;	// Revocation Ann.
	public static final int CRLANNOUNCEMENT         = 18;	// CRL Announcement
	public static final int CONFIRMATION            = 19;	// Confirmation
	public static final int NESTEDMESSAGE           = 20;	// Nested Message
	public static final int GENERALMESSAGE          = 21;	// General Message
	public static final int GENERALRESPONSE         = 22;	// General Response
	public static final int ERRORMESSAGE            = 23;	// Error Message
	public static final int CERTIFICATECONFIRM      = 24;	// Certificate confirm
	public static final int POLLINGREQUEST          = 25;	// Polling request
	public static final int POLLINGRESPONSE         = 26;	// Polling response
}
