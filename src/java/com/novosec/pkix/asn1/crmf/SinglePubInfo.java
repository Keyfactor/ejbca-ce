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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  SinglePubInfo ::= SEQUENCE {
 *    pubMethod    INTEGER {
 *        dontCare    (0),
 *        x500        (1),
 *        web         (2),
 *        ldap        (3) },
 *    pubLocation  GeneralName OPTIONAL }
 *
 * </pre>
 */
public class SinglePubInfo implements ASN1Encodable
{
    DERInteger   pubMethod;
    GeneralName  pubLocation;

    public static SinglePubInfo getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SinglePubInfo getInstance( Object obj )
    {
        if (obj instanceof SinglePubInfo)
        {
            return (SinglePubInfo)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new SinglePubInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public SinglePubInfo( ASN1Sequence seq )
    {
      this.pubMethod = DERInteger.getInstance(seq.getObjectAt(0));
      
      if( seq.size()>1 ) {
        this.pubLocation = GeneralName.getInstance((ASN1TaggedObject)seq.getObjectAt(1),true); //QQQ ??? choice is always explicit --> true
      }
    }

    public SinglePubInfo( DERInteger pubMethod )
    {
      this.pubMethod = pubMethod;
    }

    public DERInteger getPubMethod()
    {
        return pubMethod;
    }

    public GeneralName getPubLocation()
    {
        return pubLocation;
    }

    public void setPubLocation(GeneralName pubLocation)
    {
      this.pubLocation = pubLocation;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( pubMethod );
        
        if( pubLocation != null ) {
          v.add( pubLocation );
        }

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "SinglePubInfo: (pubMethod = " + this.getPubMethod() + ", ";
      
      if( this.getPubLocation() != null ) {
        s += "pubLocation = " + this.getPubLocation();
      }
      
      s += ")";
      
      return s;
    }
}
