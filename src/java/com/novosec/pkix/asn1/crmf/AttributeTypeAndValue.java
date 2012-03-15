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

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *      AttributeTypeAndValue ::= SEQUENCE {
 *                            type OBJECT IDENTIFIER,
 *                            value ANY DEFINED BY type }
 * </pre>
 */
public class AttributeTypeAndValue implements ASN1Encodable
{
    private ASN1ObjectIdentifier type;
    private ASN1Encodable        value;
	
    public static AttributeTypeAndValue getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    public static AttributeTypeAndValue getInstance(
        Object  obj)
    {
        if (obj instanceof AttributeTypeAndValue)
        {
            return (AttributeTypeAndValue)obj;
        }
        
        if (obj instanceof ASN1ObjectIdentifier)
        {
            return new AttributeTypeAndValue((ASN1ObjectIdentifier)obj);
        }

        if (obj instanceof String)
        {
            return new AttributeTypeAndValue((String)obj);
        }

        if (obj instanceof ASN1Sequence)
        {
            return new AttributeTypeAndValue((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }

    public AttributeTypeAndValue(
        ASN1ObjectIdentifier     type)
    {
        this.type = type;
    }

    public AttributeTypeAndValue(
        String     type)
    {
        this.type = new ASN1ObjectIdentifier(type);
    }

    public AttributeTypeAndValue(ASN1ObjectIdentifier type, ASN1Encodable value )
    {
        this.type = type;
        this.value = value;
    }

    public AttributeTypeAndValue(ASN1Sequence seq)
    {
        type = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        value = seq.getObjectAt(1);
    }

    public ASN1ObjectIdentifier getObjectId()
    {
        return type;
    }

    public ASN1Encodable getParameters()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add(type);
        v.add(value);

        return new DERSequence(v);
    }

    public boolean equals( Object o )
    {
        if ((o == null) || !(o instanceof AttributeTypeAndValue))
        {
            return false;
        }

        AttributeTypeAndValue other = (AttributeTypeAndValue)o;

        if (!this.getObjectId().equals(other.getObjectId()))
        {
            return false;
        }

        if (this.getParameters() == null && other.getParameters() == null)
        {
            return true;
        }

        if (this.getParameters() == null || other.getParameters() == null)
        {
            return false;
        }

        ByteArrayOutputStream   b1Out = new ByteArrayOutputStream();
        ByteArrayOutputStream   b2Out = new ByteArrayOutputStream();
        DEROutputStream         d1Out = new DEROutputStream(b1Out);
        DEROutputStream         d2Out = new DEROutputStream(b2Out);

        try
        {
            d1Out.writeObject(this.getParameters());
            d2Out.writeObject(other.getParameters());

            byte[]  b1 = b1Out.toByteArray();
            byte[]  b2 = b2Out.toByteArray();

            if (b1.length != b2.length)
            {
                return false;
            }

            for (int i = 0; i != b1.length; i++)
            {
                if (b1[i] != b2[i])
                {
                    return false;
                }
            }
        }
        catch (Exception e)
        {
            return false;
        }

        return true;
    }
}
