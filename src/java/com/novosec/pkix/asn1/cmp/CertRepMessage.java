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
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  CertRepMessage ::= SEQUENCE {
 *      caPubs       [1] SEQUENCE SIZE (1..MAX) OF Certificate OPTIONAL,  (X509CertificateStructure)
 *      response         SEQUENCE OF CertResponse
 *  }
 *
 * </pre>
 */
public class CertRepMessage implements DEREncodable
{
    Vector caPubs    = new Vector();
    Vector responses = new Vector();

    public static CertRepMessage getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertRepMessage getInstance( Object obj )
    {
        if (obj instanceof CertRepMessage)
        {
            return (CertRepMessage)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertRepMessage((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertRepMessage( ASN1Sequence seq )
    {
      Enumeration e = seq.getObjects();
      
      Object obj = e.nextElement();
      
      if( obj instanceof ASN1TaggedObject )
      {
        ASN1Sequence s = (ASN1Sequence)(((ASN1TaggedObject)obj).getObject());
        
        for (int i=0;i<s.size();i++) {
          caPubs.add(X509CertificateStructure.getInstance(s.getObjectAt(i)));
        }
        
        obj = e.nextElement();
      }

      ASN1Sequence s = (ASN1Sequence)obj;

      for (int i=0;i<s.size();i++) {
        responses.add(CertResponse.getInstance(s.getObjectAt(i)));
      }
    }

    public CertRepMessage( CertResponse response )
    {
      responses.addElement(response);
    }

    public void addCaPubs( X509CertificateStructure caPub )
    {
      caPubs.addElement(caPub);
    }
    
    public X509CertificateStructure getCaPubs( int nr )
    {
      if( nr<caPubs.size() ) {
        return (X509CertificateStructure)caPubs.elementAt(nr);
      }
        
      return null;
    }

    public void addResponse( CertResponse response )
    {
      responses.addElement(response);
    }
    
    public CertResponse getResponse( int nr )
    {
      if( nr<responses.size() ) {
        return (CertResponse)responses.elementAt(nr);
      }
        
      return null;
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      if( caPubs.size() > 0 )
      {
        ASN1EncodableVector capv = new ASN1EncodableVector();
        
        for( int i=0; i<caPubs.size(); i++ ) {
          capv.add( (X509CertificateStructure)caPubs.elementAt(i) );
        }
        
        v.add( new DERTaggedObject( true, 1, new DERSequence(capv) ) );
      }

      ASN1EncodableVector resp = new ASN1EncodableVector();
      
      for( int i=0; i<responses.size(); i++ ) {
        resp.add( (CertResponse)responses.elementAt(i) );
      }
      
      v.add( new DERSequence(resp) );
      
      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "CertRepMessage: ( ";

      if( caPubs.size() > 0 )
      {
        s += "caPubs: (";

        for( int i=0; i<caPubs.size(); i++ ) {
          s += (X509CertificateStructure)caPubs.elementAt(i);
        }
          
        s += "), ";
      }

      s += "responses: (";

      for( int i=0; i<responses.size(); i++ ) {
        s += (CertResponse)responses.elementAt(i);
      }

      s += ")";
      
      return s;
    }
}
