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

package com.novosec.pkix.asn1.crmf;

import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * ASN.1 defined Object Identifier.
 *
 */
public class CRMFObjectIdentifiers
{
  //
  // id-pkix      = { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) 7 }
  //
  //   id-pkip      = { id-pkix 5 }
  //
  //      id-regCtrl   = { id-pkip 1 }
  //      id-regInfo   = { id-pkip 2 }

  static final String  _id_pkix     = "1.3.6.1.5.5.7";
  static final String  _id_pkip     = _id_pkix + ".5";
  static final String  _id_regCtrl  = _id_pkip + ".1";
  static final String  _id_regInfo  = _id_pkip + ".2";

  public static final DERObjectIdentifier regCtrl_regToken            = new DERObjectIdentifier( _id_regCtrl + ".1");
  public static final DERObjectIdentifier regCtrl_authenticator       = new DERObjectIdentifier( _id_regCtrl + ".2");
  public static final DERObjectIdentifier regCtrl_pkiPublicationInfo  = new DERObjectIdentifier( _id_regCtrl + ".3");
  public static final DERObjectIdentifier regCtrl_pkiArchiveOptions   = new DERObjectIdentifier( _id_regCtrl + ".4");
  public static final DERObjectIdentifier regCtrl_oldCertID           = new DERObjectIdentifier( _id_regCtrl + ".5");
  public static final DERObjectIdentifier regCtrl_protocolEncrKey     = new DERObjectIdentifier( _id_regCtrl + ".6");

  public static final DERObjectIdentifier regInfo_utf8Pairs           = new DERObjectIdentifier( _id_regInfo + ".1");
  public static final DERObjectIdentifier regInfo_certReq             = new DERObjectIdentifier( _id_regInfo + ".2");
}

