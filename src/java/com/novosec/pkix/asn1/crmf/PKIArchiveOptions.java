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
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *
 *  PKIArchiveOptions ::= CHOICE {
 *    encryptedPrivKey     [0] EncryptedKey,      -- the actual value of the private key
 *    keyGenParameters     [1] KeyGenParameters,  -- parameters which allow the private key to be re-generated (OCTET STRING)
 *    archiveRemGenPrivKey [2] BOOLEAN }          -- set to TRUE if sender wishes receiver to archive the private key of a key pair which the receiver generates in response to this request; set to FALSE if no archival is desired.
 *
 * </pre>
 */
public class PKIArchiveOptions implements ASN1Encodable
{
    ASN1Encodable  	obj;
    int           	tag;

    public PKIArchiveOptions( ASN1Encodable obj, int tag )
    {
        this.obj = obj;
        this.tag = tag;
    }
    
    public EncryptedKey getEncryptedKey()
    {
      if( this.tag != 0 ) {
        return null;
      }
      return (EncryptedKey)this.obj;
    }

    public DEROctetString getKeyGenParameters()
    {
      if( this.tag != 1 ) {
        return null;
      }
      return (DEROctetString)this.obj;
    }

    public DERBoolean getArchiveRemGenPrivKey()
    {
      if( this.tag != 2 ) {
        return null;
      }
      return (DERBoolean)this.obj;
    }

    public static PKIArchiveOptions getInstance( ASN1Primitive obj )
    {
      return getInstance( (ASN1TaggedObject)obj, true );
    }

    public static PKIArchiveOptions getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = tagObj.getTagNo();

        switch (tag)
        {
          case 0:  return new PKIArchiveOptions(EncryptedKey.getInstance(tagObj.getObject()),     0);
          case 1:  return new PKIArchiveOptions(DEROctetString.getInstance(tagObj.getObject()), 1);
          case 2:  return new PKIArchiveOptions(DERBoolean.getInstance(tagObj.getObject()),       2);
        }

        throw new IllegalArgumentException("unknown tag: " + tag);
    }

    public ASN1Primitive toASN1Primitive()
    {
      return new DERTaggedObject(true, tag, obj);
    }

    public String toString()
    {
      return "PKIArchiveOptions: (" + obj + ")";
    }
}
