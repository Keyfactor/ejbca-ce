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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * CertConfirmContent ::= SEQUENCE OF CertStatus
 * 
 * CertStatus ::= SEQUENCE {
 *     certHash    OCTET STRING,
 *     certReqId   INTEGER,
 *     statusInfo  PKIStatusInfo OPTIONAL
 * }
 *
 * </pre>
 */
public class CertConfirmContent implements ASN1Encodable
{
    ASN1OctetString  certHash;
    DERInteger      certReqId;
    PKIStatusInfo   statusInfo;

    public static CertConfirmContent getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertConfirmContent getInstance( Object obj )
    {
        if (obj instanceof CertConfirmContent)
        {
            return (CertConfirmContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertConfirmContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertConfirmContent( ASN1Sequence seq )
    {
    	ASN1Sequence s = ASN1Sequence.getInstance(seq.getObjectAt(0));
    	
    	this.certHash = ASN1OctetString.getInstance( s.getObjectAt(0) );
    	this.certReqId = DERInteger.getInstance( s.getObjectAt(1) );
    	this.statusInfo = null;
    	
    	if( s.size() > 2 )
    	{
    		this.statusInfo = PKIStatusInfo.getInstance( s.getObjectAt(2) );
    	}
    }

    public CertConfirmContent( ASN1OctetString certHash, DERInteger certReqId)
    {
    	this.certHash = certHash;
    	this.certReqId = certReqId;
    	this.statusInfo = null;
    }

    public DERInteger getCertReqId()
    {
      return certReqId;
    }

    public ASN1OctetString getCertHash()
    {
      return certHash;
    }

    public PKIStatusInfo getPKIStatus()
    {
      return statusInfo;
    }

    public void setPKIStatus(PKIStatusInfo status)
    {
      this.statusInfo = status;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  outer = new ASN1EncodableVector();
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( certHash );
        v.add( certReqId );

        if ( statusInfo != null ) {
            v.add( statusInfo);
        }

        outer.add( new DERSequence(v) );
        
        return new DERSequence(outer);
    }

    public String toString()
    {
      String s = "CertConfirmContent: (certHash = " + this.getCertHash() + 
      		", certReqId = " + this.getCertReqId();
      
      if( this.getPKIStatus() != null ) {
        s += "pkiStatus = " + this.getPKIStatus();
      }
        
      s += ")";
      
      return s;
    }
}
