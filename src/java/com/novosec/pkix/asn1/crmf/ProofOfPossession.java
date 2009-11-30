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

package com.novosec.pkix.asn1.crmf;

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   ProofOfPossession ::= CHOICE {
 *     raVerified        [0] NULL,          -- used if the RA has already verified that the requester is in possession of the private key
 *     signature         [1] POPOSigningKey,
 *     keyEncipherment   [2] POPOPrivKey,
 *     keyAgreement      [3] POPOPrivKey }
 *
 * </pre>
 */
public class ProofOfPossession implements DEREncodable
{
    DEREncodable  	obj;
    int           	tag;

    public ProofOfPossession( DEREncodable obj, int tag )
    {
        this.obj = obj;
        this.tag = tag;
    }
    
    public DERNull getRaVerified()
    {
    	if( this.tag != 0 ) {
    		return null;
    	}
    	// This can sometimes be a 0 length Octet string it seems
    	if (obj instanceof DEROctetString) {
    		//DEROctetString o = (DEROctetString) obj;
    		return new DERNull();
    	}
    	return (DERNull)this.obj;
    }

    public POPOSigningKey getSignature()
    {
      if( this.tag != 1 ) {
        return null;
      }
      return (POPOSigningKey)this.obj;
    }

    public POPOPrivKey getKeyEncipherment()
    {
      if( this.tag != 2 ) {
        return null;
      }
      return (POPOPrivKey)this.obj;
    }

    public POPOPrivKey getKeyAgreement()
    {
      if( this.tag != 3 ) {
        return null;
      }
      return (POPOPrivKey)this.obj;
    }

    public static ProofOfPossession getInstance( DERObject obj )
    {
      return getInstance( (ASN1TaggedObject)obj, true );
    }

    public static ProofOfPossession getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = tagObj.getTagNo();

        switch (tag)
        {
          case 0:  return new ProofOfPossession(tagObj.getObject(),                  0);
          case 1:  return new ProofOfPossession(POPOSigningKey.getInstance(tagObj.getObject()), 1);
          case 2:  return new ProofOfPossession(POPOPrivKey.getInstance(tagObj.getObject()),    2);
          case 3:  return new ProofOfPossession(POPOPrivKey.getInstance(tagObj.getObject()),    3);
        }

        throw new IllegalArgumentException("unknown tag: " + tag);
    }

    public DERObject getDERObject()
    {
      return new DERTaggedObject(true, tag, obj);  //tag explicit since we are in a choice
    }

    public String toString()
    {
      return "ProofOfPossession: (" + obj + ")";
    }
}
