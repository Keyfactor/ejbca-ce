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

import java.util.Vector;
import java.util.Enumeration;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  PKIMessage ::= SEQUENCE {
 *      header           PKIMessage,
 *      body             PKIBody,
 *      protection   [0] PKIProtection OPTIONAL,                        -- (BIT STRING)
 *      extraCerts   [1] SEQUENCE SIZE (1..MAX) OF Certificate OPTIONAL
 *  }
 *
 * </pre>
 */
public class PKIMessage implements DEREncodable
{
    PKIHeader      header;
    PKIBody        body;
    DERBitString   protection;
    Vector         extraCerts = new Vector();
    byte           protectedBytes[];

    public static PKIMessage getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIMessage getInstance( Object obj )
    {
        if (obj instanceof PKIMessage)
        {
            return (PKIMessage)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PKIMessage((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
  
    public PKIMessage( ASN1Sequence seq )
    {
      Enumeration e = seq.getObjects();
      
/*
      header     = PKIHeader.getInstance( e.nextElement() );
      body       = PKIBody.getInstance( (ASN1TaggedObject)e.nextElement() );
*/

      DEREncodable derHeader = (DEREncodable)e.nextElement();
      DEREncodable derBody   = (DEREncodable)e.nextElement();
      
      try
      {
        //store protected part in unmodified form...
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add( derHeader );
        v.add( derBody );
        
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream( bao );
        out.writeObject( new DERSequence(v) );
      
        protectedBytes = bao.toByteArray();
      }
      catch( Exception ex ) {}
         
      header     = PKIHeader.getInstance( derHeader );
      body       = PKIBody.getInstance( (ASN1TaggedObject)derBody );
      
      while (e.hasMoreElements())
      {
        ASN1TaggedObject tagObj = (ASN1TaggedObject)e.nextElement();

        switch (tagObj.getTagNo())
        {
          case 0: protection = DERBitString.getInstance( tagObj.getObject() ); break;
          case 1: 
            ASN1Sequence s = (ASN1Sequence)tagObj.getObject();
            for( int i=0; i<s.size(); i++ ) {
              extraCerts.addElement( X509CertificateStructure.getInstance(s.getObjectAt(i)) );
            }
            break;
        }
      }
    }

    public PKIMessage( PKIHeader header, PKIBody body )
    {
        this.header = header;
        this.body = body;
    }

    public PKIHeader getHeader()
    {
        return header;
    }

    public PKIBody getBody()
    {
        return body;
    }
    
    public void setProtection( DERBitString protection )
    {
      this.protection = protection;
    }

    public DERBitString getProtection()
    {
      return protection;
    }

    public void addExtraCert( X509CertificateStructure extraCert )
    {
      this.extraCerts.addElement(extraCert);
    }

    public X509CertificateStructure getExtraCert(int nr)
    {
      if (extraCerts.size() > nr) {
        return (X509CertificateStructure)extraCerts.elementAt(nr);
      }

      return null;
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( header );
      v.add( body );
      
      if( protection != null ) {
        v.add( new DERTaggedObject( true, 0, protection ) );
      }

      if( extraCerts.size() > 0 )
      {
        ASN1EncodableVector giv = new ASN1EncodableVector();
  
        for (int i=0;i<extraCerts.size();i++) {
          giv.add((X509CertificateStructure)extraCerts.elementAt(i));
        }
  
        v.add( new DERTaggedObject( true, 1, new DERSequence(giv) ) );
      }
      
      return new DERSequence(v);
    }
    
    public byte[] getProtectedBytes()
    {
      if( protectedBytes != null ) {
        return protectedBytes;
      }

      try
      {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream( bao );
        out.writeObject( getProtectedPart() );
        return bao.toByteArray();
      }
      catch(Exception ex){}
      
      return null;
    }
    
    public ProtectedPart getProtectedPart()
    {
      return new ProtectedPart( header, body );
    }

    public String toString()
    {
      String s = "PKIMessage: ( header: " + this.getHeader() + ", body: " + this.getBody() + ", ";

      if( this.getProtection() != null ) {
        s += "protection: "+ this.getProtection() + ", ";
      }
      
      if( extraCerts.size() > 0 )
      {
        s += "extraCerts: (";
        for (int i=0;i<extraCerts.size();i++) {
          s += extraCerts.elementAt(i) + ", ";
        }
        s += ")";
      }        

      s += ")";
      
      return s;
    }
}
