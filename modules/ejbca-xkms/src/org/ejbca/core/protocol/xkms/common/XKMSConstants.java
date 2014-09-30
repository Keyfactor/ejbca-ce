/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.xkms.common;

import javax.xml.namespace.QName;

/**
 * Class containing constants from the XKMS specification
 * 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */

public class XKMSConstants {		
	
    private static final String DEFAULT_ANYURI = "http://www.w3.org/2002/03/xkms#";
    
    
    
    public static final String RESULTMAJOR_SUCCESS         = DEFAULT_ANYURI + "Success";
    public static final String RESULTMAJOR_VERSIONMISMATCH = DEFAULT_ANYURI + "VersionMismatch";
    public static final String RESULTMAJOR_SENDER          = DEFAULT_ANYURI + "Sender";
    public static final String RESULTMAJOR_RECIEVER        = DEFAULT_ANYURI + "Receiver";
    public static final String RESULTMAJOR_REPRESENT       = DEFAULT_ANYURI + "Represent";
    public static final String RESULTMAJOR_PENDING         = DEFAULT_ANYURI + "Pending";
    
    public static final String RESULTMINOR_NOMATCH                     = DEFAULT_ANYURI + "NoMatch";
    public static final String RESULTMINOR_TOOMANYRESPONSES            = DEFAULT_ANYURI + "TooManyResponses";
    public static final String RESULTMINOR_INCOMPLETE                  = DEFAULT_ANYURI + "Incomplete";
    public static final String RESULTMINOR_FAILURE                     = DEFAULT_ANYURI + "Failure";
    public static final String RESULTMINOR_REFUSED                     = DEFAULT_ANYURI + "Refused";
    public static final String RESULTMINOR_NOAUTHENTICATION            = DEFAULT_ANYURI + "NoAuthentication";
    public static final String RESULTMINOR_MESSAGENOTSUPPORTED         = DEFAULT_ANYURI + "MessageNotSupported";
    public static final String RESULTMINOR_UNKNOWNREPONSEID            = DEFAULT_ANYURI + "UnknownResponseId";
    public static final String RESULTMINOR_REPRESENTREQUIRED           = DEFAULT_ANYURI + "RepresentRequired";
    public static final String RESULTMINOR_NOTSYNCHRONOUS              = DEFAULT_ANYURI + "NotSynchronous";
    public static final String RESULTMINOR_OPTIONALELEMENTNOTSUPPORTED = DEFAULT_ANYURI + "OptionalElementNotSupported";    
    public static final String RESULTMINOR_POPREQUIRED                 = DEFAULT_ANYURI + "ProofOfPossessionRequired";
    public static final String RESULTMINOR_TIMEINSTANTNOTSUPPORTED     = DEFAULT_ANYURI + "TimeInstantNotSupported";
    public static final String RESULTMINOR_TIMEINSTANTOUTOFRANGE       = DEFAULT_ANYURI + "TimeInstantOutOfRange";    
    
    public static final String RESPONSMEC_PENDING               = DEFAULT_ANYURI + "Pending";
    public static final String RESPONSMEC_REPRESENT             = DEFAULT_ANYURI + "Represent";
    public static final String RESPONSMEC_REQUESTSIGNATUREVALUE = DEFAULT_ANYURI + "RequestSignatureValue";
    
    public static final String RESPONDWITH_KEYNAME           = DEFAULT_ANYURI + "KeyName";
    public static final String RESPONDWITH_KEYVALUE          = DEFAULT_ANYURI + "KeyValue";
    public static final String RESPONDWITH_X509CERT          = DEFAULT_ANYURI + "X509Cert";
    public static final String RESPONDWITH_X509CHAIN         = DEFAULT_ANYURI + "X509Chain";
    public static final String RESPONDWITH_X509CRL           = DEFAULT_ANYURI + "X509CRL";
    public static final String RESPONDWITH_RETRIEVALMETHOD   = DEFAULT_ANYURI + "RetrievalMethod";
    public static final String RESPONDWITH_PGP               = DEFAULT_ANYURI + "PGP";
    public static final String RESPONDWITH_PGPWEB            = DEFAULT_ANYURI + "PGPWeb";
    public static final String RESPONDWITH_SPKI              = DEFAULT_ANYURI + "SPKI";
    public static final String RESPONDWITH_PRIVATEKEY        = DEFAULT_ANYURI + "PrivateKey";
    
    public static final String KEYUSAGE_ENCRYPTION           = DEFAULT_ANYURI + "Encryption";
    public static final String KEYUSAGE_SIGNATURE            = DEFAULT_ANYURI + "Signature";
    public static final String KEYUSAGE_EXCHANGE             = DEFAULT_ANYURI + "Exchange";
    
    public static final String USEKEYWITH_XKMS               = DEFAULT_ANYURI;
    public static final String USEKEYWITH_XKMSPROFILE        = DEFAULT_ANYURI + "/profile";
    public static final String USEKEYWITH_SMIME              = "urn:ietf:rfc:2633";
    public static final String USEKEYWITH_PGP                = "urn:ietf:rfc:2440";
    public static final String USEKEYWITH_TLS                = "urn:ietf:rfc:2246";
    public static final String USEKEYWITH_TLSHTTP            = "urn:ietf:rfc:2818";
    public static final String USEKEYWITH_TLSSMTP            = "urn:ietf:rfc:2487";
    public static final String USEKEYWITH_IPSEC              = "urn:ietf:rfc:2401";
    public static final String USEKEYWITH_PKIX               = "urn:ietf:rfc:2459";
    
    public static final String STATUSVALUE_VALID             = DEFAULT_ANYURI + "Valid";
    public static final String STATUSVALUE_INVALID           = DEFAULT_ANYURI + "Invalid";
    public static final String STATUSVALUE_INDETERMINATE     = DEFAULT_ANYURI + "Indeterminate";
    
    public static final String STATUSREASON_ISSUERTRUST      = DEFAULT_ANYURI + "IssuerTrust";
    public static final String STATUSREASON_REVOCATIONSTATUS = DEFAULT_ANYURI + "RevocationStatus";
    public static final String STATUSREASON_VALIDITYINTERVAL = DEFAULT_ANYURI + "ValidityInterval";
    public static final String STATUSREASON_SIGNATURE        = DEFAULT_ANYURI + "Signature";
    
    public static final String PENDNOTIFICATION_MECHANISM_SMTP = "urn:ietf:rfc:822";
    public static final String PENDNOTIFICATION_MECHANISM_HTTP = "urn:ietf:rfc:2616";
    
    public static final String PENDNOTIFICATION_IDENTIFIER_SMTP = "mailto:";
    public static final String PENDNOTIFICATION_IDENTIFIER_HTTP = "http://";
    
    public final static QName _X509DataTypeX509Certificate_QNAME = new QName("http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
}
