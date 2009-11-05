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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * ErrorMsgContent ::= SEQUENCE {
 *     pKIStatusInfo          PKIStatusInfo,
 *     errorCode              INTEGER           OPTIONAL, -- implementation-specific error codes
 *     errorDetails           PKIFreeText       OPTIONAL  -- implementation-specific error details
 * }
 *
 * </pre>
 */
public class ErrorMsgContent implements DEREncodable
{
    PKIStatusInfo   pKIStatusInfo;
    DERInteger      errorCode;
    PKIFreeText     errorDetails;

    public static ErrorMsgContent getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ErrorMsgContent getInstance( Object obj )
    {
        if (obj instanceof ErrorMsgContent)
        {
            return (ErrorMsgContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new ErrorMsgContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public ErrorMsgContent( ASN1Sequence seq )
    {
      this.pKIStatusInfo = PKIStatusInfo.getInstance( seq.getObjectAt(0) );
      
      this.errorCode = null;
      this.errorDetails = null;
      
      if( seq.size() > 2 ) {
    	  this.errorCode = DERInteger.getInstance( seq.getObjectAt(1) );
    	  this.errorDetails = PKIFreeText.getInstance( seq.getObjectAt(2) );
      } else {
    	  if (seq.size() > 1)
    	  {
    		  Object obj = seq.getObjectAt(1);

    		  if( obj instanceof ASN1Sequence ) {
    			  this.errorDetails = PKIFreeText.getInstance(obj);
    		  } else {
    			  this.errorCode = DERInteger.getInstance(obj);
    		  }
    	  }
      }
    }

    public ErrorMsgContent( PKIStatusInfo pKIstatusInfo )
    {
      this.pKIStatusInfo = pKIstatusInfo;
      this.errorCode     = null;
      this.errorDetails  = null;
    }

    public PKIStatusInfo getPKIStatus()
    {
      return pKIStatusInfo;
    }

    public DERInteger getErrorCode()
    {
      return errorCode;
    }

    public void setErrorCode(DERInteger errorCode)
    {
      this.errorCode = errorCode;
    }

    public PKIFreeText getErrorDetails()
    {
      return errorDetails;
    }

    public void setErrorDetails(PKIFreeText errorDetails)
    {
      this.errorDetails = errorDetails;
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( pKIStatusInfo );

        if ( errorCode != null ) {
            v.add( errorCode );
        }

        if ( errorDetails!= null) {
            v.add( errorDetails );
        }

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "ErrorMsgContent: (pKIStatus = " + this.getPKIStatus() + ", ";
      
      if( this.getErrorCode() != null ) {
        s += "errorCode = " + this.getErrorCode() + ", ";
      }
      
      if( this.getErrorDetails() != null ) {
        s += "errorDetails = " + this.getErrorDetails();
      }
        
      s += ")";
      
      return s;
    }
}
