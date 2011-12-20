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

import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * CertRequest ::= SEQUENCE {
 *   certReqId     INTEGER,              -- ID for matching request and reply
 *   certTemplate  CertTemplate,         -- Selected fields of cert to be issued
 *   controls      Controls OPTIONAL }   -- Attributes affecting issuance
 *
 * </pre>
 */
public class CertRequest implements DEREncodable
{
    DERInteger   certReqId;
    CertTemplate certTemplate;
    Vector<AttributeTypeAndValue>       controls = new Vector<AttributeTypeAndValue>();

    public static CertRequest getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertRequest getInstance( Object obj )
    {
        if (obj instanceof CertRequest)
        {
            return (CertRequest)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertRequest((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertRequest( ASN1Sequence seq )
    {
      this.certReqId = DERInteger.getInstance(seq.getObjectAt(0));
      this.certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
      if( seq.size()>2 )
      {
        ASN1Sequence s = (ASN1Sequence)seq.getObjectAt(2);
        for( int i=0; i<s.size(); i++ ) {
          controls.addElement( AttributeTypeAndValue.getInstance(s.getObjectAt(i)) );
        }
      }
    }

    public CertRequest( DERInteger certReqId, CertTemplate certTemplate )
    {
      this.certReqId = certReqId;
      this.certTemplate = certTemplate;
    }

    public DERInteger getCertReqId()
    {
        return certReqId;
    }

    public CertTemplate getCertTemplate()
    {
        return certTemplate;
    }

    public AttributeTypeAndValue getControls(int nr)
    {
      if( controls.size() > nr ) {
        return (AttributeTypeAndValue)controls.elementAt(nr);
      }
        
      return null;
    }

    public void addControls(AttributeTypeAndValue control)
    {
      controls.addElement( control );
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( certReqId );
      v.add( certTemplate );

      if( controls.size() > 0 )
      {
        ASN1EncodableVector pubiv = new ASN1EncodableVector();
        for (int i=0;i<controls.size();i++) {
          pubiv.add( (AttributeTypeAndValue)controls.elementAt(i) );
        }
          
        v.add( new DERSequence( pubiv ) );
      }

      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "CertRequest: (certReqId = " + this.getCertReqId() + ", ";
      
      s += "certTemplate: " + this.getCertTemplate() + ", ";
      
      if( controls.size() > 0 )
      {
        s += "controls : (";
        
        for (int i=0;i<controls.size();i++) {
          s += (AttributeTypeAndValue)controls.elementAt(i);
        }
          
        s += ")";
      }

      s += ")";
      
      return s;
    }
}
