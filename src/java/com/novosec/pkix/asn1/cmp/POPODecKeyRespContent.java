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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   POPODecKeyRespContent ::= SEQUENCE OF INTEGER   -- One INTEGER per encryption key certification request (in the same order as these requests appear in CertReqMessages).  The
 *                                                   -- retrieved INTEGER A (above) is returned to the sender of the corresponding Challenge.
 * </pre>
 */
public class POPODecKeyRespContent implements ASN1Encodable
{
  Vector<DERInteger> integers = new Vector<DERInteger>();

  public static POPODecKeyRespContent getInstance(ASN1TaggedObject obj, boolean explicit)
  {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static POPODecKeyRespContent getInstance(Object obj)
  {
    if (obj instanceof POPODecKeyRespContent)
    {
      return (POPODecKeyRespContent) obj;
    }
    else if (obj instanceof ASN1Sequence)
    {
      return new POPODecKeyRespContent((ASN1Sequence) obj);
    }

    throw new IllegalArgumentException("unknown object in factory");
  }

  public POPODecKeyRespContent(ASN1Sequence seq)
  {
    @SuppressWarnings("unchecked")
    Enumeration<Object> e = seq.getObjects();

    while (e.hasMoreElements()) {
      integers.addElement( (DERInteger) e.nextElement() );
    }
  }

  public POPODecKeyRespContent(DERInteger p)
  {
    integers.addElement(p);
  }

  public void addInteger(DERInteger p)
  {
    integers.addElement(p);
  }

  public DERInteger getInteger(int nr)
  {
    if (integers.size() > nr) {
      return integers.elementAt(nr);
    }

    return null;
  }

  public ASN1Primitive toASN1Primitive()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();

    for (int i = 0; i < integers.size(); i++) {
      v.add((DERInteger) integers.elementAt(i));
    }

    return new DERSequence(v);
  }

  public String toString()
  {
    String s = "POPODecKeyRespContent: (";
    
    for (int i=0;i<integers.size();i++) {
      s += integers.elementAt(i) + ", ";
    }
    
    s += ")";
    
    return s;
  }
}
