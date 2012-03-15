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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *
 *   POPOPrivKey ::= CHOICE {
 *       thisMessage       [0] BIT STRING,        -- posession is proven in this message (which contains the private key itself (encrypted for the CA))
 *       subsequentMessage [1] SubsequentMessage, -- possession will be proven in a subsequent message (INTEGER)
 *       dhMAC             [2] BIT STRING }       -- for keyAgreement (only), possession is proven in this message (which contains a MAC (over the DER-encoded value of the
 *                                                -- certReq parameter in CertReqMsg, which MUST include both subject and publicKey) based on a key derived from the end entity's
 *                                                -- private DH key and the CA's public DH key); the dhMAC value MUST be calculated as per the directions given in Appendix A.
 *   
 *   SubsequentMessage ::= INTEGER {
 *       encrCert (0),        -- requests that resulting certificate be encrypted for the end entity (following which, POP will be proven in a confirmation message)
 *       challengeResp (1) }  -- requests that CA engage in challenge-response exchange with end entity in order to prove private key possession 
 *
 * </pre>
 */
public class POPOPrivKey implements ASN1Encodable
{
    ASN1Encodable  	obj;
    int           	tag;

    public POPOPrivKey( ASN1Primitive obj, int tag )
    {
        this.obj = obj;
        this.tag = tag;
    }
    
    public DERBitString getThisMessage()
    {
      if( this.tag != 0 ) {
        return null;
      }
      return (DERBitString)this.obj;
    }

    public DERInteger getSubsequentMessage()
    {
      if( this.tag != 1 ) {
        return null;
      }
      return (DERInteger)this.obj;
    }

    public DERBitString getDhMAC()
    {
      if( this.tag != 2 ) {
        return null;
      }
      return (DERBitString)this.obj;
    }

    public static POPOPrivKey getInstance( ASN1Primitive obj )
    {
      return getInstance( (ASN1TaggedObject)obj, true );
    }

    public static POPOPrivKey getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = tagObj.getTagNo();

        switch (tag)
        {
          case 0:  return new POPOPrivKey(DERBitString.getInstance(tagObj.getObject()), 0);
          case 1:  return new POPOPrivKey(DERInteger.getInstance(tagObj.getObject()),   1);
          case 2:  return new POPOPrivKey(DERBitString.getInstance(tagObj.getObject()), 2);
        }

        throw new IllegalArgumentException("unknown tag: " + tag);
    }

    public ASN1Primitive toASN1Primitive()
    {
      return new DERTaggedObject(true, tag, obj);
    }

    public String toString()
    {
      return "POPOPrivKey: (" + obj + ")";
    }
}
