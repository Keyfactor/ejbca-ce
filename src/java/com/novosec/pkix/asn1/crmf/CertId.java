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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  CertId ::= SEQUENCE {
 *  issuer           GeneralName,
 *  serialNumber     INTEGER }
 *
 * </pre>
 */
public class CertId implements DEREncodable
{
    GeneralName  issuer;
    DERInteger   serialNumber;

    public static CertId getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertId getInstance( Object obj )
    {
        if (obj instanceof CertId)
        {
            return (CertId)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new CertId((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public CertId( ASN1Sequence seq )
    {
      this.issuer = GeneralName.getInstance((ASN1TaggedObject)seq.getObjectAt(0),true); //QQQ??? implicit because inside of a seq
      this.serialNumber = (DERInteger)seq.getObjectAt(1);
    }

    public CertId( GeneralName issuer, DERInteger serialNumber )
    {
      this.issuer = issuer;
      this.serialNumber = serialNumber;
    }

    public GeneralName getIssuer()
    {
        return issuer;
    }

    public DERInteger getSerialNumber()
    {
        return serialNumber;
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        v.add( issuer );
        v.add( serialNumber );

        return new DERSequence(v);
    }

    public String toString()
    {
      return "CertId: (issuer = " + this.getIssuer() + ", serialNumber = " + this.getSerialNumber() + ")";
    }
}
