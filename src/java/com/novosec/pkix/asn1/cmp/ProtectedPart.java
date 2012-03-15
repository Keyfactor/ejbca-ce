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
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 * ProtectedPart ::= SEQUENCE {
 *     header        PKIHeader,
 *     body          PKIBody
 * }
 *
 * </pre>
 */
public class ProtectedPart implements ASN1Encodable
{
    PKIHeader header;
    PKIBody   body;

    public static ProtectedPart getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ProtectedPart getInstance( Object obj )
    {
        if (obj instanceof ProtectedPart)
        {
            return (ProtectedPart)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new ProtectedPart((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public ProtectedPart( ASN1Sequence seq )
    {
        this.header = PKIHeader.getInstance(seq.getObjectAt(0));
        this.body   = PKIBody.getInstance((ASN1TaggedObject)seq.getObjectAt(1));
    }

    public ProtectedPart( PKIHeader header, PKIBody body )
    {
        this.header = header;
        this.body   = body;
    }
    
    public PKIHeader getHeader()
    {
        return header;
    }

    public PKIBody getBody()
    {
        return body;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( header );
        v.add( body );

        return new DERSequence(v);
    }

    public String toString()
    {
        return "ProtectedPart: (header = " + this.getHeader() + ", body = " + this.getBody() + ")";
    }
}
