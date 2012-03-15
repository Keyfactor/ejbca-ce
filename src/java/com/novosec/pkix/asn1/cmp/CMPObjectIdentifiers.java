// CMP implementation copyright (c) 2003 NOVOSEC AG (http://www.novosec.com)
//
// Author: Maik Stohn
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this 
// software and associated documentation files (the "Software"), to deal in the Software 
// without restriction, including without limitation the rights to use, copy, modify, merge, 
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
// to whom the Software is furnished to do so, subject to the following conditions: 
//
// The above copyright notice and this permission notice shall be included in all copies or 
// substantial portions of the Software. 
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING 
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

package com.novosec.pkix.asn1.cmp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * ASN.1 defined Object Identifier.
 *
 */
public class CMPObjectIdentifiers
{
  //
  // id-pkix      = { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) 7 }
  //
  //   id-it      = { id-pkix 4 }
  //

  static final String  _id_pkix     = "1.3.6.1.5.5.7";
  static final String  _id_it       = _id_pkix + ".4";

  public static final ASN1ObjectIdentifier it_CAProtEncCert        = new ASN1ObjectIdentifier( _id_it + ".1" );
  public static final ASN1ObjectIdentifier it_SignKeyPairTypes     = new ASN1ObjectIdentifier( _id_it + ".2" );
  public static final ASN1ObjectIdentifier it_EncKeyPairTypes      = new ASN1ObjectIdentifier( _id_it + ".3" );
  public static final ASN1ObjectIdentifier it_PreferredSymmAlg     = new ASN1ObjectIdentifier( _id_it + ".4" );
  public static final ASN1ObjectIdentifier it_CAKeyUpdateInfo      = new ASN1ObjectIdentifier( _id_it + ".5" );
  public static final ASN1ObjectIdentifier it_CurrentCRL           = new ASN1ObjectIdentifier( _id_it + ".6" );
  
  // PasswordBasedMac ::= OBJECT IDENTIFIER --{1 2 840 113533 7 66 13}
  public static final ASN1ObjectIdentifier passwordBasedMac        = new ASN1ObjectIdentifier( "1.2.840.113533.7.66.13" );
  
  // DHBasedMac ::= OBJECT IDENTIFIER --{1 2 840 113533 7 66 30}
  public static final ASN1ObjectIdentifier dHBasedMac              = new ASN1ObjectIdentifier( "1.2.840.113533.7.66.30" );

}

