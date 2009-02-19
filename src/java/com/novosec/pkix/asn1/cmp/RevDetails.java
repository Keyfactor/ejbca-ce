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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.novosec.pkix.asn1.crmf.CertTemplate;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * RevDetails ::= SEQUENCE {
 *     certDetails         CertTemplate,                -- allows requester to specify as much as they can about the cert. for which revocation is requested
 *     revocationReason    ReasonFlags      OPTIONAL,   -- the reason that revocation is requested
 *     badSinceDate        GeneralizedTime  OPTIONAL,   -- indicates best knowledge of sender
 *     crlEntryDetails     Extensions       OPTIONAL    -- requested crlEntryExtensions (X509Extensions)
 * }
 *
 *  ReasonFlags ::= BIT STRING {
 *                                unused(0), 
 *                                keyCompromise(1), 
 *                                caCompromise(2), 
 *                                affiliationChanged(3),
 *                                superseded(4), 
 *                                cessationOfOperation(5), 
 *                                certificateHold(6)
 *                             }
 *
 * </pre>
 */
public class RevDetails implements DEREncodable
{
     CertTemplate       certDetails;
     DERBitString       revocationReason;
     DERGeneralizedTime badSinceDate;
     X509Extensions     crlEntryDetails;

    public static RevDetails getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static RevDetails getInstance( Object obj )
    {
        if (obj instanceof RevDetails)
        {
            return (RevDetails)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new RevDetails((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public RevDetails( ASN1Sequence seq )
    {
      this.certDetails = CertTemplate.getInstance( seq.getObjectAt(0) );
      
      int idx = 1;
      
      Object obj = null;
      
      if( idx < seq.size() ) {
        obj = seq.getObjectAt(idx++);
      }
      
      if( obj instanceof DERBitString )
      {
        this.revocationReason = DERBitString.getInstance( obj );
        if( idx < seq.size() ) {
          obj = seq.getObjectAt(idx++);
        } else {
          obj = null;
        }
      }
    
      if( obj instanceof DERGeneralizedTime )
      {
        this.badSinceDate = DERGeneralizedTime.getInstance( obj );
        if( idx < seq.size() ) {
          obj = seq.getObjectAt(idx++);
        } else {
          obj = null;
        }
      }
    
      if( obj instanceof ASN1Sequence )
      {
        this.crlEntryDetails = X509Extensions.getInstance( obj );
        if( idx < seq.size() ) {
          obj = seq.getObjectAt(idx++);
        } else {
          obj = null;
        }
      }

      if( obj != null ) {
        throw new IllegalArgumentException("unknown object in factory");
      }
    }

    public RevDetails( CertTemplate certDetails )
    {
      this.certDetails = certDetails;
      this.revocationReason = null;
      this.badSinceDate = null;
      this.crlEntryDetails = null;
    }

    public CertTemplate getCertDetails()
    {
        return certDetails;
    }

    public void setCertDetails( CertTemplate certDetails )
    {
        this.certDetails = certDetails;
    }

    public DERBitString getRevocationReason()
    {
        return revocationReason;
    }

    public void setRevocationReason( DERBitString revocationReason )
    {
        this.revocationReason = revocationReason;
    }

    public DERGeneralizedTime getBadSinceDate()
    {
        return badSinceDate;
    }

    public void setBadSinceDate( DERGeneralizedTime badSinceDate )
    {
        this.badSinceDate = badSinceDate;
    }

    public X509Extensions getCrlEntryDetails()
    {
        return crlEntryDetails;
    }

    public void setCrlEntryDetails( X509Extensions crlEntryDetails )
    {
        this.crlEntryDetails = crlEntryDetails;
    }
    
    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( certDetails );

        if ( revocationReason != null ) {
            v.add( revocationReason );
        }

        if ( badSinceDate!= null) {
            v.add( badSinceDate );
        }

        if ( crlEntryDetails!= null) {
            v.add( crlEntryDetails );
        }

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "RevDetails: ( certDetails = " + this.getCertDetails() + ", ";
      
      if( this.getRevocationReason() != null ) {
       s += "revocationReason = " + this.getRevocationReason() + ", ";
      }
      
      if( this.getBadSinceDate() != null ) {
       s += "badSinceDate = " + this.getBadSinceDate() + ", ";
      }
      
      if( this.getCrlEntryDetails() != null ) {
       s += "crlEntryDetails = " + this.getCrlEntryDetails() + ", ";
      }
      
      s += ")";
      
      return s;
    }
}
