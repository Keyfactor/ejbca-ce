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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import com.novosec.pkix.asn1.crmf.EncryptedValue;
import com.novosec.pkix.asn1.crmf.PKIPublicationInfo;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  CertifiedKeyPair ::= SEQUENCE {
 *      certOrEncCert       CertOrEncCert,
 *      privateKey      [0] EncryptedValue      OPTIONAL,
 *      publicationInfo [1] PKIPublicationInfo  OPTIONAL
 *  }
 *
 * </pre>
 */
public class CertifiedKeyPair implements ASN1Encodable
{
    CertOrEncCert      certOrEncCert;
    EncryptedValue     privateKey;
    PKIPublicationInfo publicationInfo;

    public static CertifiedKeyPair getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertifiedKeyPair getInstance( Object obj )
    {
        if (obj instanceof CertifiedKeyPair)
        {
            return (CertifiedKeyPair)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertifiedKeyPair((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertifiedKeyPair( ASN1Sequence seq )
    {
      Enumeration<?> e = seq.getObjects();

      certOrEncCert = CertOrEncCert.getInstance( (ASN1Primitive)e.nextElement() );
      
      while (e.hasMoreElements())
      {
        ASN1TaggedObject tagObj = (ASN1TaggedObject)e.nextElement();

        switch (tagObj.getTagNo())
        {
          case 0: privateKey = EncryptedValue.getInstance( tagObj.getObject() ); break;
          case 1: publicationInfo = PKIPublicationInfo.getInstance( tagObj.getObject() ); break;
        }
      }
    }

    public CertifiedKeyPair( CertOrEncCert certOrEncCert )
    {
      this.certOrEncCert = certOrEncCert;
    }

    public CertOrEncCert getCertOrEncCert()
    {
        return certOrEncCert;
    }
    
    public void setPrivateKey( EncryptedValue privateKey )
    {
      this.privateKey = privateKey;
    }

    public EncryptedValue getPrivateKey()
    {
      return privateKey;
    }

    public void setPublicationInfo( PKIPublicationInfo publicationInfo )
    {
      this.publicationInfo = publicationInfo;
    }

    public PKIPublicationInfo getPublicationInfo()
    {
      return publicationInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( certOrEncCert );
      
      if( privateKey != null ) {
        v.add( new DERTaggedObject( true, 0, privateKey ) );
      }

      if( publicationInfo != null ) {
        v.add( new DERTaggedObject( true, 1, publicationInfo ) );
      }
      
      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "CertifiedKeyPair: ( certOrEncCert: " + this.getCertOrEncCert() + ", ";

      if( this.getPrivateKey() != null ) {
        s += "privateKey: "+ this.getPrivateKey() + ", ";
      }

      if( this.getPublicationInfo() != null ) {
        s += "publicationInfo: "+ this.getPublicationInfo() + ", ";
      }

      s += ")";
      
      return s;
    }
}
