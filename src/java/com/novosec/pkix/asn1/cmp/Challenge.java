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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   Challenge ::= SEQUENCE {
 *       owf                 AlgorithmIdentifier  OPTIONAL,   -- MUST be present in the first Challenge; MAY be omitted in any subsequent Challenge in POPODecKeyChallContent (if omitted,
 *                                                            -- then the owf used in the immediately preceding Challenge is to be used).
 *       witness             OCTET STRING,                    -- the result of applying the one-way function (owf) to a randomly-generated INTEGER, A.  [Note that a different INTEGER MUST be used for each Challenge.]
 *       challenge           OCTET STRING                     -- the encryption (under the public key for which the cert. request is being made) of Rand, where Rand is specified as Rand ::= SEQUENCE {int INTEGER, sender GeneralName}  
 *                                                            --   rand --> the randomly-generated INTEGER A (above); sender --> the sender's name (as included in PKIHeader)
 *   }
 *
 * </pre>
 */
public class Challenge implements DEREncodable
{
  AlgorithmIdentifier owf;
  DEROctetString      witness;
  DEROctetString      challenge;

  public static Challenge getInstance(ASN1TaggedObject obj, boolean explicit)
  {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  public static Challenge getInstance(Object obj)
  {
    if (obj instanceof Challenge)
    {
      return (Challenge) obj;
    }
    else if (obj instanceof ASN1Sequence)
    {
      return new Challenge((ASN1Sequence) obj);
    }

    throw new IllegalArgumentException("unknown object in factory");
  }

  public Challenge(ASN1Sequence seq)
  {
    int idx = 0;
    Object obj = seq.getObjectAt(idx);
    
    if( !(obj instanceof DEROctetString) )
    {
      owf = AlgorithmIdentifier.getInstance(obj);
      idx++;  
    }
    
    this.witness = (DEROctetString)seq.getObjectAt(idx++);
    this.challenge = (DEROctetString)seq.getObjectAt(idx);
  }

  public Challenge( DEROctetString witness, DEROctetString challenge )
  {
    this.witness = witness;
    this.challenge = challenge;
  }

  public AlgorithmIdentifier getOwf()
  {
    return owf;
  }

  public void setOwf(AlgorithmIdentifier owf)
  {
    this.owf = owf;
  }

  public DEROctetString getWitness()
  {
    return witness;
  }

  public DEROctetString getChallenge()
  {
    return challenge;
  }

  public DERObject getDERObject()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();

    if( owf != null ) {
      v.add(owf);
    }
      
    v.add(witness);
    v.add(challenge);

    return new DERSequence(v);
  }

  public String toString()
  {
    String s = "Challenge: (";
    
    if( this.getOwf() != null ) {
      s += "owf: "+ this.getOwf() + ", ";
    }

    s += "witness: " + this.getWitness();
    s += "challenge: " + this.getChallenge();
    
    s += ")";
    
    return s;
  }
}
