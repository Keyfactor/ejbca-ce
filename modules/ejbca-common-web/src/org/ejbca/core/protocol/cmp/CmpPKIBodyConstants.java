package org.ejbca.core.protocol.cmp;

public class CmpPKIBodyConstants {
	// Message-specific body elements from RFC 4210
	public final static int INITIALIZATIONREQUEST   =  0;	// Initialization Request
	public final static int INITIALIZATIONRESPONSE  =  1;	// Initialization Response
	public final static int CERTIFICATAIONREQUEST   =  2;	// Certification Request
	public final static int CERTIFICATIONRESPONSE   =  3;	// Certification Response
	public final static int IMPORTEDFROMPKCS10      =  4;	// imported from [PKCS10]
	public final static int POPCHALLENGE            =  5;	// pop Challenge
	public final static int POPRESPONSE             =  6;	// pop Response
	public final static int KEYUPDATEREQUEST        =  7;	// Key Update Request
	public final static int KEYUPDATERESPONSE       =  8;	// Key Update Response
	public final static int KEYRECOVERYREQUEST      =  9;	// Key Recovery Request
	public final static int KEYRECOEVRYRESPONSE     = 10;	// Key Recovery Response
	public final static int REVOCATIONREQUEST       = 11;	// Revocation Request
	public final static int REVOCATIONRESPONSE      = 12;	// Revocation Response
	public final static int CROSSCERTREQUEST        = 13;	// Cross-Cert. Request
	public final static int CROSSCERTRESPONSE       = 14;	// Cross-Cert. Response
	public final static int CAKEYUPDATEANN          = 15;	// CA Key Update Ann.
	public final static int CERTIFICATEANN          = 16;	// Certificate Ann.
	public final static int REVOCATIONANN           = 17;	// Revocation Ann.
	public final static int CRLANNOUNCEMENT         = 18;	// CRL Announcement
	public final static int CONFIRMATION            = 19;	// Confirmation
	public final static int NESTEDMESSAGE           = 20;	// Nested Message
	public final static int GENERALMESSAGE          = 21;	// General Message
	public final static int GENERALRESPONSE         = 22;	// General Response
	public final static int ERRORMESSAGE            = 23;	// Error Message
	public final static int CERTIFICATECONFIRM      = 24;	// Certificate confirm
	public final static int POLLINGREQUEST          = 25;	// Polling request
	public final static int POLLINGRESPONSE         = 26;	// Polling response
}
