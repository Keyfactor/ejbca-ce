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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   DHBMParameter ::= SEQUENCE {
 *       owf                 AlgorithmIdentifier, -- AlgId for a One-Way Function (SHA-1 recommended)
 *       mac                 AlgorithmIdentifier  -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11], or HMAC [RFC2104, RFC2202])
 *   }
 *
 * </pre>
 */
public class DHBMParameter implements ASN1Encodable
{
    AlgorithmIdentifier owf;
    AlgorithmIdentifier mac;

    public static DHBMParameter getInstance(ASN1TaggedObject obj, boolean explicit)
    {
      return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static DHBMParameter getInstance(Object obj)
    {
      if (obj instanceof DHBMParameter)
      {
        return (DHBMParameter) obj;
      }
      else if (obj instanceof ASN1Sequence)
      {
        return new DHBMParameter((ASN1Sequence) obj);
      }

      throw new IllegalArgumentException("unknown object in factory");
    }

    public DHBMParameter(ASN1Sequence seq)
    {
      this.owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
      this.mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
    }

    public DHBMParameter(AlgorithmIdentifier owf, AlgorithmIdentifier mac)
    {
      this.owf = owf;
      this.mac = mac;
    }

    public AlgorithmIdentifier getOwf()
    {
      return owf;
    }

    public AlgorithmIdentifier getMac()
    {
      return mac;
    }

    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector v = new ASN1EncodableVector();

      v.add(owf);
      v.add(mac);

      return new DERSequence(v);
    }

    public String toString()
    {
        return "DHBMParameter: (owf = " + this.getOwf() + ", mac = " + this.getMac() + ")";
    }
}
