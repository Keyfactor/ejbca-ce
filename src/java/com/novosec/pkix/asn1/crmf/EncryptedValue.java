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
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   EncryptedValue ::= SEQUENCE {
 *     intendedAlg   [0] AlgorithmIdentifier  OPTIONAL, -- the intended algorithm for which the value will be used
 *     symmAlg       [1] AlgorithmIdentifier  OPTIONAL, -- the symmetric algorithm used to encrypt the value
 *     encSymmKey    [2] BIT STRING           OPTIONAL, -- the (encrypted) symmetric key used to encrypt the value
 *     keyAlg        [3] AlgorithmIdentifier  OPTIONAL, -- algorithm used to encrypt the symmetric key
 *     valueHint     [4] OCTET STRING         OPTIONAL, -- a brief description or identifier of the encValue content (may be meaningful only to the sending entity, and used only if EncryptedValue might be re-examined by the sending entity in the future)
 *     encValue       BIT STRING }                      -- the encrypted value itself
 *
 * </pre>
 */
 
public class EncryptedValue implements ASN1Encodable
{
    AlgorithmIdentifier  intendedAlg;
    AlgorithmIdentifier  symmAlg;
    DERBitString         encSymmKey;
    AlgorithmIdentifier  keyAlg;
    DEROctetString       valueHint;
    DERBitString         encValue;       

    public static EncryptedValue getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EncryptedValue getInstance( Object obj )
    {
        if (obj instanceof EncryptedValue)
        {
            return (EncryptedValue)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new EncryptedValue((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public EncryptedValue( ASN1Sequence seq )
    {
      @SuppressWarnings("unchecked")
    Enumeration<Object> e = seq.getObjects();
      while (e.hasMoreElements())
      {
        Object obj = e.nextElement();
        
        if( obj instanceof DERTaggedObject )
        {
          DERTaggedObject tagObj = (DERTaggedObject)obj;
          
          switch( tagObj.getTagNo() )
          {
            case 0: this.intendedAlg = AlgorithmIdentifier.getInstance( tagObj.getObject() ); break;
            case 1: this.symmAlg = AlgorithmIdentifier.getInstance( tagObj.getObject() ); break;
            case 2: this.encSymmKey = DERBitString.getInstance( tagObj.getObject() ); break;
            case 3: this.keyAlg = AlgorithmIdentifier.getInstance( tagObj.getObject() ); break;
            case 4: this.valueHint = (DEROctetString)DEROctetString.getInstance( tagObj.getObject() ); break;
          }
        }
        else
        {
          encValue = DERBitString.getInstance( obj );
          break;
        }
      }
    }

    public EncryptedValue(DERBitString encValue)
    {
      this.encValue = encValue;
    }

    public AlgorithmIdentifier getIntendedAlg()
    {
      return intendedAlg;
    }

    public void setIntendedAlg(AlgorithmIdentifier intendedAlg)
    {
      this.intendedAlg = intendedAlg;
    }

    public AlgorithmIdentifier getSymmAlg()
    {
      return symmAlg;
    }

    public void setSymmAlg(AlgorithmIdentifier symmAlg)
    {
      this.symmAlg = symmAlg;
    }

    public DERBitString getEncSymmKey()
    {
      return encSymmKey;
    }

    public void setEncSymmKey(DERBitString encSymmKey)
    {
      this.encSymmKey = encSymmKey;
    }

    public AlgorithmIdentifier getKeyAlg()
    {
      return keyAlg;
    }

    public void setKeyAlg(AlgorithmIdentifier keyAlg)
    {
      this.keyAlg = keyAlg;
    }

    public DEROctetString getValueHint()
    {
      return valueHint;
    }

    public void setValueHint(DEROctetString valueHint)
    {
      this.valueHint = valueHint;
    }

    public DERBitString getEncValue()
    {
      return encValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if( intendedAlg != null ) {
          v.add( new DERTaggedObject( false, 0, intendedAlg ) );
        }
        if( symmAlg != null ) {
          v.add( new DERTaggedObject( false, 1, symmAlg ) );
        }
        if( encSymmKey != null ) {
          v.add( new DERTaggedObject( false, 2, encSymmKey ) );
        }
        if( keyAlg != null ) {
          v.add( new DERTaggedObject( false, 3, keyAlg ) );
        }
        if( valueHint != null ) {
          v.add( new DERTaggedObject( false, 4, valueHint ) );
        }

        v.add( encValue );

        return new DERSequence(v);
    }

    public String toString()
    {
      String s = "EncryptedValue: (";
      
      if( this.getIntendedAlg() != null ) {
        s += "intendedAlg: " + this.getIntendedAlg() + ", ";
      }
      if( this.getSymmAlg() != null ) {
        s += "symmAlg: " + this.getSymmAlg() + ", ";
      }
      if( this.getEncSymmKey() != null ) {
        s += "encSymmKey: " + this.getEncSymmKey() + ", ";
      }
      if( this.getKeyAlg() != null ) {
        s += "keyAlg: " + this.getKeyAlg() + ", ";
      }
      if( this.getValueHint() != null ) {
        s += "valueHint: " + this.getValueHint() + ", ";
      }
      s += "encValue: " + this.getEncValue() + ")";
      
      return s;
    }
}
