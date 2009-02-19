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

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *      InfoTypeAndValue ::= SEQUENCE {
 *                            infoType OBJECT IDENTIFIER,
 *                            infoValue ANY DEFINED BY infoType OPTIONAL }
 * </pre>
 */
public class InfoTypeAndValue implements DEREncodable
{
    private DERObjectIdentifier infoType;
    private DEREncodable        infoValue;
	
    public static InfoTypeAndValue getInstance( ASN1TaggedObject obj, boolean explicit )
    {
      return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }
    
    public static InfoTypeAndValue getInstance( Object obj )
    {
      if (obj instanceof InfoTypeAndValue)
      {
        return (InfoTypeAndValue)obj;
      }
      else if (obj instanceof ASN1Sequence)
      {
        return new InfoTypeAndValue((ASN1Sequence)obj);
      }

      throw new IllegalArgumentException("unknown object in factory");
    }

    public InfoTypeAndValue( ASN1Sequence seq )
    {
      infoType = (DERObjectIdentifier)seq.getObjectAt(0);

      if (seq.size() == 2) {
        infoValue = seq.getObjectAt(1);
      } else {
        infoValue = null;
      }
    }

    public InfoTypeAndValue( DERObjectIdentifier infoType )
    {
      this.infoType = infoType;
    }

    public DERObjectIdentifier getInfoType()
    {
      return infoType;
    }

    public DEREncodable getInfoValue()
    {
      return infoValue;
    }

    public void setInfoValue( DEREncodable infoValue )
    {
      this.infoValue = infoValue;
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add(infoType);

      if( infoValue != null ) {
        v.add(infoValue);
      }

      return new DERSequence(v);
    }

    public boolean equals( Object o )
    {
        if ((o == null) || !(o instanceof InfoTypeAndValue))
        {
            return false;
        }

        InfoTypeAndValue other = (InfoTypeAndValue)o;

        if (!this.getInfoType().equals(other.getInfoType()))
        {
            return false;
        }

        if (this.getInfoValue() == null && other.getInfoValue() == null)
        {
            return true;
        }

        if (this.getInfoValue() == null || other.getInfoValue() == null)
        {
            return false;
        }

        ByteArrayOutputStream   b1Out = new ByteArrayOutputStream();
        ByteArrayOutputStream   b2Out = new ByteArrayOutputStream();
        DEROutputStream         d1Out = new DEROutputStream(b1Out);
        DEROutputStream         d2Out = new DEROutputStream(b2Out);

        try
        {
            d1Out.writeObject(this.getInfoValue());
            d2Out.writeObject(other.getInfoValue());

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
    
    public String toString()
    {
      String s = "InfoTypeAndValue: (" + getInfoType();
      
      if( getInfoValue() != null ) {
        s += ", " + getInfoValue();
      }
        
      s += ")";
        
      return s;
    }
}
