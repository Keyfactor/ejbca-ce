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
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.novosec.pkix.asn1.crmf.CertId;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * RevAnnContent ::= SEQUENCE {
 *     status             PKIStatus,
 *     certId             CertId,
 *     willBeRevokedAt    DERGeneralizedTime,
 *     badSinceDate       DERGeneralizedTime,
 *     crlDetails         Extensions  OPTIONAL
 *     
 * }
 *
 * </pre>
 */
public class RevAnnContent implements ASN1Encodable
{
     DERInteger           status;
     CertId               certId;
     DERGeneralizedTime   willBeRevokedAt;
     DERGeneralizedTime   badSinceDate;
     X509Extensions       crlDetails;

    public static RevAnnContent getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RevAnnContent getInstance( Object obj )
    {
        if (obj instanceof RevAnnContent)
        {
            return (RevAnnContent)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new RevAnnContent((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public RevAnnContent( ASN1Sequence seq )
    {
      this.status          = DERInteger.getInstance( seq.getObjectAt(0) );
      this.certId          = CertId.getInstance( seq.getObjectAt(1) );
      this.willBeRevokedAt = DERGeneralizedTime.getInstance( seq.getObjectAt(2) );
      this.badSinceDate    = DERGeneralizedTime.getInstance( seq.getObjectAt(3) );
      
      if( seq.size() > 4 ) {
        this.crlDetails = X509Extensions.getInstance( seq.getObjectAt(4) );
      }
    }

    public RevAnnContent( DERInteger status, CertId certId, DERGeneralizedTime willBeRevokedAt, 
                          DERGeneralizedTime badSinceDate )
    {
      this.status          = status;
      this.certId          = certId;
      this.willBeRevokedAt = willBeRevokedAt;
      this.badSinceDate    = badSinceDate;
    }

    public DERInteger getStatus()
    {
      return status;
    }

    public CertId getCertId()
    {
      return certId;
    }

    public DERGeneralizedTime getWillBeRevokedAt()
    {
      return willBeRevokedAt;
    }

    public DERGeneralizedTime getBadSinceDate()
    {
      return badSinceDate;
    }

    public X509Extensions getCrlDetails()
    {
      return crlDetails;
    }

    public void setCrlDetails( X509Extensions crlDetails )
    {
      this.crlDetails      = crlDetails;
    }


    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( status );
      v.add( certId );
      v.add( willBeRevokedAt );
      v.add( badSinceDate );

      if( crlDetails != null ) {
        v.add( crlDetails );
      }

      return new DERSequence(v);
    }

    public String toString()
    {
      String s =  "RevAnnContent: (status = " + this.getStatus() + ", " +
                                  "certId = " + this.getCertId() + ", " +
                                  "willBeRevokedAt = " + this.getWillBeRevokedAt() + ", " +
                                  "badSinceDate = " + this.getBadSinceDate();
                                 
      if( this.getCrlDetails() != null ) {
        s += ", crlDetails = " + this.getCrlDetails();
      }
        
      s += ")";
      
      return s;
    }
}
