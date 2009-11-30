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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import com.novosec.pkix.asn1.crmf.EncryptedValue;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   CertOrEncCert ::= CHOICE {
 *     certificate     [0] Certificate,    (X509CertificateStructure)
 *     encryptedCert   [1] EncryptedValue
 *   }
 *  
 * </pre>
 */
public class CertOrEncCert implements DEREncodable
{
    DEREncodable  	obj;
    int           	tag;

    public CertOrEncCert( DEREncodable obj, int tag )
    {
        this.obj = obj;
        this.tag = tag;
    }

    public X509CertificateStructure getCertificate()
    {
      if( this.tag != 0 ) {
        return null;
      }
      return (X509CertificateStructure)this.obj;
    }

    public EncryptedValue getEncryptedCert()
    {
      if( this.tag != 1 ) {
        return null;
      }
      return (EncryptedValue)this.obj;
    }

    public static CertOrEncCert getInstance( DERObject obj )
    {
      return getInstance( (ASN1TaggedObject)obj, true );
    }

    public static CertOrEncCert getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = tagObj.getTagNo();

        switch (tag)
        {
          case 0:  return new CertOrEncCert(X509CertificateStructure.getInstance(tagObj.getObject()), 0);
          case 1:  return new CertOrEncCert(EncryptedValue.getInstance(tagObj.getObject()),           1);
        }

        throw new IllegalArgumentException("unknown tag: " + tag);
    }

    public DERObject getDERObject()
    {
      return new DERTaggedObject(true, tag, obj);
    }

    public String toString()
    {
      return "CertOrEncCert: (" + obj + ")";
    }
}
