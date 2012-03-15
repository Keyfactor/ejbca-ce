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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CertificateList;

import com.novosec.pkix.asn1.crmf.CertId;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   RevRepContent ::= SEQUENCE {
 *       status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,              -- in same order as was sent in RevReqContent
 *       revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,            -- IDs for which revocation was requested (same order as status)
 *       crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList  OPTIONAL   -- the resulting CRLs (there may be more than one)
 *   }
 *
 * </pre>
 */

public class RevRepContent implements ASN1Encodable
{
    Vector<PKIStatusInfo> status    = new Vector<PKIStatusInfo>();
    Vector<CertId> revCerts  = new Vector<CertId>();
    Vector<CertificateList> crls      = new Vector<CertificateList>();

    public static RevRepContent getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RevRepContent getInstance( Object obj )
    {
        if (obj instanceof RevRepContent)
        {
            return (RevRepContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new RevRepContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    @SuppressWarnings("unchecked")
    public RevRepContent( ASN1Sequence seq )
    {
      Enumeration<Object> e = seq.getObjects();
      
      Enumeration<Object> estatus = ((ASN1Sequence)e.nextElement()).getObjects();
      while (estatus.hasMoreElements()) {
        status.addElement( PKIStatusInfo.getInstance( estatus.nextElement() ) );
      }
      
      while( e.hasMoreElements() )
      {
        DERTaggedObject obj = (DERTaggedObject)e.nextElement();

        switch( obj.getTagNo() )
        {
          case 0: 
//            Enumeration erevcerts = ((ASN1Sequence)e.nextElement()).getObjects();
          Enumeration<Object> erevcerts = ((ASN1Sequence)obj.getObject()).getObjects();
            while (erevcerts.hasMoreElements()) {
              revCerts.addElement( CertId.getInstance( erevcerts.nextElement() ) );
            }
            break;
          case 1: 
//            Enumeration ecrls = ((ASN1Sequence)e.nextElement()).getObjects();
          Enumeration<Object> ecrls = ((ASN1Sequence)obj.getObject()).getObjects();
            while (ecrls.hasMoreElements()) {
              crls.addElement( CertificateList.getInstance( ecrls.nextElement() ) );
            }
            break;
        }
      }
    }

    public RevRepContent(PKIStatusInfo pKIStatusInfo)
    {
      status.clear();
      status.addElement( pKIStatusInfo );
      revCerts.clear();
      crls.clear();
    }

    public void addPKIStatusInfo( PKIStatusInfo pKIStatusInfo )
    {
      status.addElement( pKIStatusInfo );
    }

    public PKIStatusInfo getPKIStatusInfo( int nr )
    {
      if (status.size() > nr) {
        return (PKIStatusInfo)status.elementAt(nr);
      }

      return null;
    }
   
    public void addRevCert( CertId certId )
    {
      revCerts.addElement( certId );
    }

    public CertId getRevCert( int nr )
    {
      if (revCerts.size() > nr) {
        return (CertId)revCerts.elementAt(nr);
      }

      return null;
    }
   
    public void addCrl( CertificateList crl )
    {
      crls.addElement( crl );
    }

    public CertificateList getCrl( int nr )
    {
      if (crls.size() > nr) {
        return (CertificateList)crls.elementAt(nr);
      }

      return null;
    }
  
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        ASN1EncodableVector  statv = new ASN1EncodableVector();
        for (int i=0;i<status.size();i++) {
          statv.add( (PKIStatusInfo)status.elementAt(i) );
        }
        v.add( new DERSequence( statv ) );

        if( revCerts.size() > 0 )
        {
          ASN1EncodableVector  revcv = new ASN1EncodableVector();
          for (int i=0;i<revCerts.size();i++) {
            revcv.add( (CertId)revCerts.elementAt(i) );
          }
          v.add( new DERSequence( revcv ) );
        }

        if( crls.size() > 0 )
        {
          ASN1EncodableVector  crlsv = new ASN1EncodableVector();
          for (int i=0;i<crls.size();i++) {
            crlsv.add( (CertificateList)crls.elementAt(i) );
          }
          v.add( new DERSequence( crlsv ) );
        }

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "RevRepContent: (";

      
      if( status.size() > 0 )
      {
        s += "status: (";
        
        for (int i=0;i<status.size();i++) {
          s += (PKIStatusInfo)status.elementAt(i);
        }
          
        s += "), ";
      }
      
      if( revCerts.size() > 0 )
      {
        s += "revCerts: (";

        for (int i=0;i<revCerts.size();i++) {
          s += (CertId)revCerts.elementAt(i);
        }

        s += "), ";
      }
     
      if( crls.size() > 0 )
      {
        s += "crls: (";
  
        for (int i=0;i<crls.size();i++) {
          s += (CertificateList)crls.elementAt(i);
        }
  
        s += ")";
      }
      
      s += ")";
        
      return s;
    }
}
