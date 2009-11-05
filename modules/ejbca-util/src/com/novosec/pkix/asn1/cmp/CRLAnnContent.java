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
import org.bouncycastle.asn1.x509.CertificateList;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * CRLAnnContent ::= SEQUENCE OF CertificateList
 *
 * </pre>
 */
public class CRLAnnContent implements DEREncodable
{
    Vector certificateLists = new Vector();

    public static CRLAnnContent getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CRLAnnContent getInstance( Object obj )
    {
        if (obj instanceof CRLAnnContent)
        {
            return (CRLAnnContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CRLAnnContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    public CRLAnnContent( ASN1Sequence seq )
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            CertificateList s = CertificateList.getInstance(e.nextElement());
            certificateLists.addElement(s);
        }
    }

    public CRLAnnContent( CertificateList certificateList )
    {
      certificateLists.addElement( certificateList );
    }

    public void addCertificateList( CertificateList certificateList )
    {
      certificateLists.addElement( certificateList );
    }
    
    public CertificateList getCertificateList(int nr)
    {
      if (certificateLists.size() > nr) {
        return (CertificateList)certificateLists.elementAt(nr);
      }

      return null;
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        for (int i=0;i<certificateLists.size();i++)
        {
          v.add((CertificateList)certificateLists.elementAt(i));
        }

        return new DERSequence(v);
    }

    public String toString()
    {
        String p = null;
        for (int i=0;i<certificateLists.size();i++) {
          if( p == null ) {
            p = ((CertificateList)certificateLists.elementAt(i)).toString();
          } else {
            p += (CertificateList)certificateLists.elementAt(i);
          }
        }
        return "CRLAnnContent: "+p;
    }
}
