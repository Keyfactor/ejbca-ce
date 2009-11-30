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
 *  KeyRecRepContent ::= SEQUENCE {
 *      status                  PKIStatusInfo,
 *      newSigCert          [0] Certificate                                 OPTIONAL, (X509CertificateStructure)
 *      caCerts             [1] SEQUENCE SIZE (1..MAX) OF Certificate       OPTIONAL, (X509CertificateStructure)
 *      keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair  OPTIONAL
 *  }
 *
 * </pre>
 */
public class KeyRecRepContent implements DEREncodable
{
  PKIStatusInfo            status;
  X509CertificateStructure newSigCert;
  Vector                   caCerts      = new Vector();
  Vector                   keyPairHists = new Vector();

  public static KeyRecRepContent getInstance(ASN1TaggedObject obj, boolean explicit)
  {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static KeyRecRepContent getInstance(Object obj)
  {
    if (obj instanceof KeyRecRepContent)
    {
      return (KeyRecRepContent) obj;
    }
    else if (obj instanceof ASN1Sequence)
    {
      return new KeyRecRepContent((ASN1Sequence) obj);
    }

    throw new IllegalArgumentException("unknown object in factory");
  }

  public KeyRecRepContent(ASN1Sequence seq)
  {
    Enumeration e = seq.getObjects();

    status = PKIStatusInfo.getInstance(e.nextElement());

    while (e.hasMoreElements())
    {
      ASN1TaggedObject tagObj = (ASN1TaggedObject) e.nextElement();

      switch (tagObj.getTagNo())
      {
        case 0 :
          newSigCert = X509CertificateStructure.getInstance(tagObj.getObject());
          break;
        case 1 :
          {
            ASN1Sequence s = (ASN1Sequence) tagObj.getObject();
            for (int i = 0; i < s.size(); i++) {
              caCerts.addElement(X509CertificateStructure.getInstance(s.getObjectAt(i)));
            }
          }
          break;
        case 2 :
          {
            ASN1Sequence s = (ASN1Sequence) tagObj.getObject();
            for (int i = 0; i < s.size(); i++) {
              keyPairHists.addElement(CertifiedKeyPair.getInstance(s.getObjectAt(i)));
            }
          }
          break;
      }
    }
  }

  public KeyRecRepContent(PKIStatusInfo status)
  {
    this.status = status;
  }

  public PKIStatusInfo getStatus()
  {
    return status;
  }

  public X509CertificateStructure getNewSigCert()
  {
    return newSigCert;
  }

  public void setNewSigCert(X509CertificateStructure newSigCert)
  {
    this.newSigCert = newSigCert;
  }

  public void addCaCerts(X509CertificateStructure caCert)
  {
    caCerts.addElement(caCert);
  }

  public X509CertificateStructure getCaCerts(int nr)
  {
    if (nr < caCerts.size()) {
      return (X509CertificateStructure) caCerts.elementAt(nr);
    }

    return null;
  }

  public void addKeyPairHist(CertifiedKeyPair keyPairHist)
  {
    keyPairHists.addElement(keyPairHist);
  }

  public CertifiedKeyPair getKeyPairHist(int nr)
  {
    if (nr < keyPairHists.size()) {
      return (CertifiedKeyPair) keyPairHists.elementAt(nr);
    }

    return null;
  }

  public DERObject getDERObject()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();

    v.add(status);

    if (newSigCert != null) {
      v.add(new DERTaggedObject(true, 0, newSigCert));
    }

    if (caCerts.size() > 0)
    {
      ASN1EncodableVector cacv = new ASN1EncodableVector();

      for (int i = 0; i < caCerts.size(); i++) {
        cacv.add((X509CertificateStructure) caCerts.elementAt(i));
      }

      v.add(new DERTaggedObject(true, 1, new DERSequence(cacv)));
    }

    if (keyPairHists.size() > 0)
    {
      ASN1EncodableVector keyphv = new ASN1EncodableVector();

      for (int i = 0; i < keyPairHists.size(); i++) {
        keyphv.add((CertifiedKeyPair) keyPairHists.elementAt(i));
      }

      v.add(new DERTaggedObject(true, 2, new DERSequence(keyphv)));
    }

    return new DERSequence(v);
  }

  public String toString()
  {
    String s = "CertifiedKeyPair: ( status: " + this.getStatus() + ", ";

    if( this.getNewSigCert() != null ) {
      s += "newSigCert: "+ this.getNewSigCert() + ", ";
    }

    if( caCerts.size() > 0 )
    {
      s += "caCerts: (";
      
      for( int i=0; i<caCerts.size(); i++ ) {
        s += (X509CertificateStructure)caCerts.elementAt(i);
      }
        
      s += "), ";
    }
    
    if( keyPairHists.size() > 0 )
    {
      s += "keyPairHist: (";
      
      for( int i=0; i<caCerts.size(); i++ ) {
        s += (CertifiedKeyPair)keyPairHists.elementAt(i);
      }
        
      s += ")";
    }

    s += ")";
    
    return s;
  }
}
