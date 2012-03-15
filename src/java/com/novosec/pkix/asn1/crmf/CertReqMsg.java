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

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  CertReqMsg ::= SEQUENCE {
 *    certReq   CertRequest,
 *    pop       ProofOfPossession  OPTIONAL,                              -- content depends upon key type
 *    regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
 *
 * </pre>
 */
public class CertReqMsg implements ASN1Encodable
{
    CertRequest       certReq;
    ProofOfPossession pop;
    Vector<AttributeTypeAndValue>            regInfos = new Vector<AttributeTypeAndValue>();

    public static CertReqMsg getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertReqMsg getInstance( Object obj )
    {
        if (obj instanceof CertReqMsg)
        {
            return (CertReqMsg)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertReqMsg((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertReqMsg( ASN1Sequence seq )
    {
      @SuppressWarnings("unchecked")
    Enumeration<Object> e = seq.getObjects();
      this.certReq = CertRequest.getInstance(e.nextElement());

      Object obj = null;

      if( e.hasMoreElements() ) {      
        obj = e.nextElement();
      }
      
      if( obj instanceof ASN1TaggedObject )
      {
        this.pop = ProofOfPossession.getInstance((ASN1TaggedObject)obj);
        
        if( e.hasMoreElements() ) {      
          obj = e.nextElement();
        }
      }
      
      if( obj instanceof ASN1Sequence )
      {
        ASN1Sequence s = (ASN1Sequence)obj;
        for( int i=0; i<s.size(); i++ ) {
          regInfos.addElement( AttributeTypeAndValue.getInstance(s.getObjectAt(i)) );
        }
      }
    }

    public CertReqMsg( CertRequest certReq )
    {
      this.certReq = certReq;
    }

    public CertRequest getCertReq()
    {
      return certReq;
    }

    public ProofOfPossession getPop()
    {
      return pop;
    }

    public void setPop( ProofOfPossession pop )
    {
      this.pop = pop;
    }

    public AttributeTypeAndValue getRegInfo(int nr)
    {
      if( regInfos.size() > nr ) {
        return (AttributeTypeAndValue)regInfos.elementAt(nr);
      }
        
      return null;
    }

    public void addRegInfo(AttributeTypeAndValue regInfo)
    {
      regInfos.addElement( regInfo );
    }

    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( certReq );
      
      if( pop != null ) {
        v.add( pop );
      }

      if( regInfos.size() > 0 )
      {
        ASN1EncodableVector regiv = new ASN1EncodableVector();
        for (int i=0;i<regInfos.size();i++) {
          regiv.add( (AttributeTypeAndValue)regInfos.elementAt(i) );
        }
          
        v.add( new DERSequence( regiv ) );
      }

      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "CertReqMsg: (certReq = " + this.getCertReq() + ", ";
      
      if( this.getPop() != null ) {
        s += "pop: " + this.getPop() + ", ";
      }
      
      if( regInfos.size() > 0 )
      {
        s += "regInfo : (";
        
        for (int i=0;i<regInfos.size();i++) {
          s += (AttributeTypeAndValue)regInfos.elementAt(i);
        }
          
        s += ")";
      }

      s += ")";
      
      return s;
    }
}
