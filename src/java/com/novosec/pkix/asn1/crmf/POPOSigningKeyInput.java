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
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *
 *  POPOSigningKeyInput ::= SEQUENCE {
 *    authInfo            CHOICE {
 *        sender              [0] GeneralName,    -- used only if an authenticated identity has been established for the sender (e.g., a DN from a previously-issued and currently-valid certificate
 *        publicKeyMAC        PKMACValue },       -- used if no authenticated GeneralName currently exists for the sender; publicKeyMAC contains a password-based MAC on the DER-encoded value of publicKey
 *
 *    publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
 *
 * </pre>
 */
public class POPOSigningKeyInput implements ASN1Encodable
{
    GeneralName           sender;
    PKMACValue            publicKeyMAC;
    SubjectPublicKeyInfo  publicKey;

    public static POPOSigningKeyInput getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static POPOSigningKeyInput getInstance( Object obj )
    {
        if (obj instanceof POPOSigningKeyInput)
        {
            return (POPOSigningKeyInput)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new POPOSigningKeyInput((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public POPOSigningKeyInput( ASN1Sequence seq )
    {
      Object obj = seq.getObjectAt(0);
      
      if( obj instanceof ASN1TaggedObject )
      {
        ASN1TaggedObject tagObj = (ASN1TaggedObject)obj;
        if( tagObj.getTagNo() == 0 ) {
          this.sender = GeneralName.getInstance(tagObj.getObject());
        } else {
          throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
        }
      } else {
        publicKeyMAC = PKMACValue.getInstance( obj );
      }
   
      this.publicKey = SubjectPublicKeyInfo.getInstance( seq.getObjectAt(1) );
    }

    public POPOSigningKeyInput( GeneralName sender, SubjectPublicKeyInfo publicKey )
    {
      this.sender = sender;
      this.publicKey = publicKey;
    }
    public POPOSigningKeyInput( PKMACValue publicKeyMAC, SubjectPublicKeyInfo publicKey )
    {
      this.publicKeyMAC = publicKeyMAC;
      this.publicKey = publicKey;
    }

    public GeneralName getSender()
    {
      return sender;
    }

    public PKMACValue getPublicKeyMAC()
    {
      return publicKeyMAC;
    }

    public SubjectPublicKeyInfo getPublicKey()
    {
      return publicKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      if( sender != null ) {
        v.add( new DERTaggedObject( false, 0, sender ) );
      } else {
        v.add( publicKeyMAC );
      }
      
      v.add( publicKey );

      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "POPOSigningKeyInput: (";
      
      if( this.getSender() != null ) {
        s += "sender: " + this.getSender() + ", ";
      } else {
        s += "publicKeyMAC: " + this.getPublicKeyMAC() + ", ";
      }
      
      s += "publicKey: " + this.getPublicKey() + ")";
      
      return s;
    }
}
