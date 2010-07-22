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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.novosec.pkix.asn1.crmf.CertId;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   OOBCertHash ::= SEQUENCE {
 *       hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
 *       certId      [1] CertId                  OPTIONAL,
 *       hashVal         BIT STRING                        -- hashVal is calculated over DER encoding of the subjectPublicKey field of the corresponding cert.
 *   }
 *
 * </pre>
 */
public class OOBCertHash implements DEREncodable
{
    AlgorithmIdentifier hashAlg;
    CertId              certId;
    DERBitString        hashVal;

    public static OOBCertHash getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OOBCertHash getInstance( Object obj )
    {
        if (obj instanceof OOBCertHash)
        {
            return (OOBCertHash)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new OOBCertHash((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public OOBCertHash( ASN1Sequence seq )
    {
      Enumeration e = seq.getObjects();
      
      while( e.hasMoreElements() )
      {
        Object obj = e.nextElement();
      
        if( obj instanceof ASN1TaggedObject )
        {
          ASN1TaggedObject tagObj = (ASN1TaggedObject)obj;
          
          switch( tagObj.getTagNo() )
          {
            case 0: hashAlg = AlgorithmIdentifier.getInstance(tagObj.getObject()); break;
            case 1: certId = CertId.getInstance(tagObj.getObject()); break;
          }
        }
        else
        {
          hashVal = DERBitString.getInstance( obj );
          
          break;
        }
      }
    }

    public OOBCertHash( DERBitString hashVal )
    {
      this.hashVal = hashVal;
    }

    public DERBitString getHashVal()
    {
      return hashVal;
    }

    public void setHashAlg( AlgorithmIdentifier hashAlg )
    {
      this.hashAlg = hashAlg;
    }

    public AlgorithmIdentifier getHashAlg()
    {
      return hashAlg;
    }
    
    public void setCertId( CertId certId )
    {
      this.certId = certId;
    }

    public CertId getCertId()
    {
      return certId;
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();
      
      if( hashAlg != null ) {
        v.add( new DERTaggedObject( true, 0, hashAlg ) );
      }
        
      if( certId != null ) {
        v.add( new DERTaggedObject( true, 1, certId ) );
      }
  
      v.add( hashVal );
      
      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "OOBCertHash: ( ";

      if( this.getHashAlg() != null ) {
        s += "hashAlg: " + this.getHashAlg() + ", ";
      }

      if( this.getCertId() != null ) {
        s += "certId: " + this.getCertId() + ", ";
      }

      s += "hashVal: " + this.getHashVal();

      s += ")";
      
      return s;
    }
}
