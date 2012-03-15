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

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Time;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * OptionalValidity ::= SEQUENCE {
 *     notBefore  [0] Time OPTIONAL,
 *     notAfter   [1] Time OPTIONAL } --at least one MUST be present
 *
 * </pre>
 */
public class OptionalValidity implements ASN1Encodable
{
    // time is a choice type --> tag it explicit
    public static final boolean bTimeIsExplicit = true;

    private Time notBefore = null;
    private Time notAfter = null;

    public static OptionalValidity getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static OptionalValidity getInstance( Object obj )
    {
        if (obj == null) {
            return new OptionalValidity();
        }
        else if (obj instanceof OptionalValidity) {
            return (OptionalValidity)obj;
        }
        else if (obj instanceof ASN1Sequence) {
            return new OptionalValidity((ASN1Sequence)obj);
        }
        else {
            throw new IllegalArgumentException("unknown object in factory");
        }
    }

    public OptionalValidity( ASN1Sequence seq )
    {
      @SuppressWarnings("unchecked")
    Enumeration<DERTaggedObject> e = (seq == null ? null : seq.getObjects());
      while (e != null && e.hasMoreElements())
      {
        DERTaggedObject obj = e.nextElement();
        int tagno = (obj == null ? -1 : obj.getTagNo());
        switch( tagno )
        {
          case 0: this.notBefore = Time.getInstance( obj, bTimeIsExplicit ); break;
          case 1: this.notAfter  = Time.getInstance( obj, bTimeIsExplicit ); break;
          default : throw new IllegalArgumentException("invalid asn1 sequence");
        }
      }
    }

    public OptionalValidity()
    {
    }

    public void setNotBefore( Time notBefore )
    {
      this.notBefore = notBefore;
    }

    public Time getNotBefore()
    {
      return notBefore;
    }

    public void setNotAfter( Time notAfter )
    {
      this.notAfter = notAfter;
    }

    public Time getNotAfter()
    {
      return notAfter;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if( notBefore != null ) {
          v.add( new DERTaggedObject( bTimeIsExplicit, 0, notBefore ) );
        }
        if( notAfter != null ) {
          v.add( new DERTaggedObject( bTimeIsExplicit, 1, notAfter ) );
        }
        return new DERSequence(v);
    }

    public String toString() {
    	StringBuilder sb = new StringBuilder(this.getClass().getName());
        sb.append(" (");

        if( this.getNotBefore() != null ) {
            sb.append("notBefore: " + this.getNotBefore() + ", ");
        }
        if( this.getNotBefore() != null ) {
            sb.append("notAfter: " + this.getNotAfter() + ", ");
        }
        sb.append("hashCode: " + Integer.toHexString(this.hashCode()) + ")");
        return sb.toString();
    }
}
