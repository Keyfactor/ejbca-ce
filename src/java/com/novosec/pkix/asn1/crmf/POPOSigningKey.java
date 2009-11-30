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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  POPOSigningKey ::= SEQUENCE {
 *    poposkInput           [0] POPOSigningKeyInput OPTIONAL,
 *    algorithmIdentifier   AlgorithmIdentifier,
 *    signature             BIT STRING }                      -- The signature (using "algorithmIdentifier") is on the DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
 *                                                            -- certReq CertTemplate contains the subject and publicKey values, then poposkInput MUST be omitted and the signature MUST be
 *                                                            -- computed on the DER-encoded value of CertReqMsg certReq.  If the CertReqMsg certReq CertTemplate does not contain the public
 *                                                            -- key and subject values, then poposkInput MUST be present and MUST be signed.  This strategy ensures that the public key is
 *                                                            -- not present in both the poposkInput and CertReqMsg certReq CertTemplate fields.
 *
 * </pre>
 */
public class POPOSigningKey implements DEREncodable
{
    POPOSigningKeyInput poposkInput;
    AlgorithmIdentifier algorithmIdentifier;
    DERBitString        signature;

    public static POPOSigningKey getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static POPOSigningKey getInstance( Object obj )
    {
        if (obj instanceof POPOSigningKey)
        {
            return (POPOSigningKey)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new POPOSigningKey((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public POPOSigningKey( ASN1Sequence seq )
    {
      int idx = 0;
      Object obj = seq.getObjectAt(idx++);
      
      if( obj instanceof ASN1TaggedObject )
      {
        ASN1TaggedObject tagObj = (ASN1TaggedObject)obj;
        if( tagObj.getTagNo() == 0 ) {
          this.poposkInput = POPOSigningKeyInput.getInstance( tagObj.getObject() );
        } else {
          throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
        }
      } else {
        idx--;
      }
        
      this.algorithmIdentifier = AlgorithmIdentifier.getInstance( seq.getObjectAt(idx++) );
      this.signature = DERBitString.getInstance( seq.getObjectAt(idx) );
    }

    public POPOSigningKey( AlgorithmIdentifier algorithmIdentifier, DERBitString signature )
    {
      this.algorithmIdentifier = algorithmIdentifier;
      this.signature = signature;
    }

    public POPOSigningKeyInput getPoposkInput()
    {
      return poposkInput;
    }

    public void setPoposkInput( POPOSigningKeyInput poposkInput )
    {
      this.poposkInput = poposkInput;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
      return algorithmIdentifier;
    }

    public DERBitString getSignature()
    {
      return signature;
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      if( poposkInput != null ) {
        v.add( new DERTaggedObject( false, 0, poposkInput ) );
      }
      v.add( algorithmIdentifier );
      v.add( signature );

      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "POPOSigningKey: (";
      
      if( this.getPoposkInput() != null ) {
        s += "poposkInput: " + this.getPoposkInput() + ", ";
      }
      s += "algorithmIdentifier: " + this.getAlgorithmIdentifier() + ", ";
        
      s += "signature: " + this.getSignature() + ")";
      
      return s;
    }
}
