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

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   POPODecKeyChallContent ::= SEQUENCE OF Challenge -- One Challenge per encryption key certification request (in the same order as these requests appear in CertReqMessages).
 * </pre>
 */
public class POPODecKeyChallContent implements DEREncodable
{
  Vector<Challenge> challenges = new Vector<Challenge>();

  public static POPODecKeyChallContent getInstance(ASN1TaggedObject obj, boolean explicit)
  {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static POPODecKeyChallContent getInstance(Object obj)
  {
    if (obj instanceof POPODecKeyChallContent)
    {
      return (POPODecKeyChallContent) obj;
    }
    else if (obj instanceof ASN1Sequence)
    {
      return new POPODecKeyChallContent((ASN1Sequence) obj);
    }

    throw new IllegalArgumentException("unknown object in factory");
  }

  public POPODecKeyChallContent(ASN1Sequence seq)
  {
    @SuppressWarnings("unchecked")
    Enumeration<Object> e = seq.getObjects();

    while (e.hasMoreElements()) {
      challenges.addElement( Challenge.getInstance(e.nextElement()) );
    }
  }

  public POPODecKeyChallContent(Challenge p)
  {
    challenges.addElement(p);
  }

  public void addChallenge(Challenge p)
  {
    challenges.addElement(p);
  }

  public Challenge getChallenge(int nr)
  {
    if (challenges.size() > nr) {
      return (Challenge) challenges.elementAt(nr);
    }

    return null;
  }

  public DERObject getDERObject()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();

    for (int i = 0; i < challenges.size(); i++) {
      v.add((Challenge) challenges.elementAt(i));
    }

    return new DERSequence(v);
  }

  public String toString()
  {
    String s = "POPODecKeyChallContent: (";
    
    for (int i=0;i<challenges.size();i++) {
      s += challenges.elementAt(i) + ", ";
    }
    
    s += ")";
    
    return s;
  }
}
