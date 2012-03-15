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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * PKIStatusInfo ::= SEQUENCE {
 *     status        PKIStatus,                (INTEGER)
 *     statusString  PKIFreeText     OPTIONAL,
 *     failInfo      PKIFailureInfo  OPTIONAL  (BIT STRING)
 * }
 *
 * PKIStatus:
 *   granted                (0), -- you got exactly what you asked for
 *   grantedWithMods        (1), -- you got something like what you asked for
 *   rejection              (2), -- you don't get it, more information elsewhere in the message
 *   waiting                (3), -- the request body part has not yet been processed, expect to hear more later
 *   revocationWarning      (4), -- this message contains a warning that a revocation is imminent
 *   revocationNotification (5), -- notification that a revocation has occurred
 *   keyUpdateWarning       (6)  -- update already done for the oldCertId specified in CertReqMsg
 *
 * PKIFailureInfo:     
 *   badAlg           (0), -- unrecognized or unsupported Algorithm Identifier
 *   badMessageCheck  (1), -- integrity check failed (e.g., signature did not verify)
 *   badRequest       (2), -- transaction not permitted or supported
 *   badTime          (3), -- messageTime was not sufficiently close to the system time, as defined by local policy
 *   badCertId        (4), -- no certificate could be found matching the provided criteria
 *   badDataFormat    (5), -- the data submitted has the wrong format
 *   wrongAuthority   (6), -- the authority indicated in the request is different from the one creating the response token
 *   incorrectData    (7), -- the requester's data is incorrect (for notary services)
 *   missingTimeStamp (8), -- when the timestamp is missing but should be there (by policy)
 *   badPOP           (9)  -- the proof-of-possession failed
 *
 * </pre>
 */
public class PKIStatusInfo implements ASN1Encodable
{
    DERInteger      status;
    PKIFreeText     statusString;
    DERBitString    failInfo;

    public static PKIStatusInfo getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIStatusInfo getInstance( Object obj )
    {
        if (obj instanceof PKIStatusInfo)
        {
            return (PKIStatusInfo)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PKIStatusInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public PKIStatusInfo( ASN1Sequence seq )
    {
        this.status = DERInteger.getInstance(seq.getObjectAt(0));

        this.statusString = null;
        this.failInfo = null;
        
        if (seq.size() > 2)
        {
          this.statusString = PKIFreeText.getInstance(seq.getObjectAt(1));
          this.failInfo = DERBitString.getInstance(seq.getObjectAt(2));
        }
        else
        if (seq.size() > 1)
        {
          Object obj = seq.getObjectAt(1);

          if( obj instanceof ASN1Sequence ) {
            this.statusString = PKIFreeText.getInstance(obj);
          } else {
            this.failInfo = DERBitString.getInstance(obj);
          }
        }
    }
    
    public PKIStatusInfo( DERInteger status )
    {
      this.status = status;
    }

    public DERInteger getStatus()
    {
      return status;
    }

    public PKIFreeText getStatusString()
    {
      return statusString;
    }

    public void setStatusString(PKIFreeText statusString)
    {
      this.statusString = statusString;
    }


    public DERBitString getFailInfo()
    {
      return failInfo;
    }

    public void setFailInfo(DERBitString failInfo)
    {
      this.failInfo = failInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( status );

        if ( statusString != null ) {
            v.add( statusString );
        }

        if ( failInfo!= null ) {
            v.add( failInfo );
        }

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "PKIStatusInfo: (status = " + this.getStatus();
      
      if( this.getStatusString() != null ) {
        s += ", statusString: " + this.getStatusString();
      }

      if( this.getFailInfo() != null ) {
        s += ", failInfo: " + this.getFailInfo();
      }

      s += ")";
      
      return s;
    }
}
