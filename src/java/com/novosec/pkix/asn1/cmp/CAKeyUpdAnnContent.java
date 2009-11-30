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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   CAKeyUpdAnnContent ::= SEQUENCE {
 *    oldWithNew          Certificate, -- old pub signed with new priv (X509CertificateStructure)
 *    newWithOld          Certificate, -- new pub signed with old priv (X509CertificateStructure)
 *    newWithNew          Certificate  -- new pub signed with new priv (X509CertificateStructure)
 * }
 *
 * </pre>
 */
public class CAKeyUpdAnnContent implements DEREncodable
{
  X509CertificateStructure oldWithNew;
  X509CertificateStructure newWithOld;
  X509CertificateStructure newWithNew;

  public static CAKeyUpdAnnContent getInstance(ASN1TaggedObject obj, boolean explicit)
  {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static CAKeyUpdAnnContent getInstance(Object obj)
  {
    if (obj instanceof CAKeyUpdAnnContent)
    {
      return (CAKeyUpdAnnContent) obj;
    }
    else if (obj instanceof ASN1Sequence)
    {
      return new CAKeyUpdAnnContent((ASN1Sequence) obj);
    }

    throw new IllegalArgumentException("unknown object in factory");
  }

  public CAKeyUpdAnnContent(ASN1Sequence seq)
  {
    this.oldWithNew = X509CertificateStructure.getInstance(seq.getObjectAt(0));
    this.newWithOld = X509CertificateStructure.getInstance(seq.getObjectAt(1));
    this.newWithNew = X509CertificateStructure.getInstance(seq.getObjectAt(2));
  }

  public CAKeyUpdAnnContent(
    X509CertificateStructure oldWithNew,
    X509CertificateStructure newWithOld,
    X509CertificateStructure newWithNew)
  {
    this.oldWithNew = oldWithNew;
    this.newWithOld = newWithOld;
    this.newWithNew = newWithNew;
  }

  public X509CertificateStructure getOldWithNew()
  {
    return oldWithNew;
  }

  public X509CertificateStructure getNewWithOld()
  {
    return newWithOld;
  }

  public X509CertificateStructure getNewWithNew()
  {
    return newWithNew;
  }

  public DERObject getDERObject()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();

    v.add(oldWithNew);
    v.add(newWithOld);
    v.add(newWithNew);

    return new DERSequence(v);
  }

  public String toString()
  {
    return "CAKeyUpdAnnContent: oldWithNew = " + this.getOldWithNew() + ", " +
                                "newWithOld = " + this.getNewWithOld() + ", " +
                                "newWithNew = " + this.getNewWithNew() + ")";
  }
}
