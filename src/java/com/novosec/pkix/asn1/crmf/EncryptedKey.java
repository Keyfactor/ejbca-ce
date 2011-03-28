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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EnvelopedData;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *
 *   EncryptedKey ::= CHOICE {
 *     encryptedValue        EncryptedValue,
 *     envelopedData     [0] EnvelopedData }    -- The encrypted private key MUST be placed in the envelopedData encryptedContentInfo encryptedContent OCTET STRING.
 *
 * </pre>
 */
public class EncryptedKey implements DEREncodable
{
    public static final int TAGNO_ENV_DATA = 0;
    public static final int TAGNO_ENC_VALUE = 1;

    private int            tagNo          = -1;
    private DEREncodable   obj            = null;
    private EncryptedValue encryptedValue = null;

    public static EncryptedKey getInstance( DEREncodable derObj )
    {
        if(derObj instanceof EnvelopedData) {
            return new EncryptedKey( (EnvelopedData)derObj );
        } else if(derObj instanceof EncryptedValue) {
            return new EncryptedKey( (EncryptedValue)derObj );
        } else if(derObj instanceof ASN1TaggedObject) {
            return getInstance( (ASN1TaggedObject)derObj, false );
        } else {
            return new EncryptedKey( EncryptedValue.getInstance(derObj) ); // last try ;-)
        }
    }

    public static EncryptedKey getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = (tagObj == null ? -1 : tagObj.getTagNo());
        switch (tag)
        {
          case TAGNO_ENV_DATA: return new EncryptedKey(EnvelopedData.getInstance(tagObj, explicit));
          default: return new EncryptedKey(EncryptedValue.getInstance(tagObj, explicit));
        }
    }

    public EncryptedKey( DEREncodable derObj, int tag )
    {
        this.tagNo = tag;

        if(derObj instanceof EnvelopedData) {
            this.obj = (EnvelopedData)derObj;
        } else if(derObj instanceof EncryptedValue) {
            this.encryptedValue = (EncryptedValue)derObj;
        } else {
            switch( this.tagNo ) {
                case TAGNO_ENV_DATA: this.obj = EnvelopedData.getInstance(derObj); break;
                default: this.encryptedValue = EncryptedValue.getInstance(derObj); break;
            }
        }
    }

    public EncryptedKey( EnvelopedData envelopedData )
    {
        this( envelopedData, TAGNO_ENV_DATA );
    }

    public EncryptedKey( EncryptedValue encryptedValue )
    {
        this( encryptedValue, TAGNO_ENC_VALUE );
    }

    public void setEncryptedValue(EncryptedValue value) {
        encryptedValue = value;
    }

    public EncryptedValue getEncryptedValue()
    {
      return encryptedValue;
    }

    public void setTagNo(int tn) {
        this.tagNo = tn;
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public EnvelopedData getEnvelopedData() {
        return EnvelopedData.getInstance(obj);
    }

    public DERObject getDERObject()
    {
        if( this.encryptedValue != null ) {
            return encryptedValue.getDERObject();
        } else if( this.obj != null ) {
            return new DERTaggedObject(true, this.tagNo, this.obj);  // choice is allways explictly tagged
        } else {
            return null;
        }
    }

    public String toString() {
    	StringBuilder sb = new StringBuilder(this.getClass().getName());
        sb.append(" (");

        sb.append("tagNo: " + this.tagNo + ", ");

        if( this.encryptedValue != null ) {
            sb.append("encryptedValue: " + this.encryptedValue + ", ");
        }
        if( this.obj != null ) {
            sb.append("envelopedData: " + this.obj + ", ");
        }

        sb.append("hashCode: " + Integer.toHexString(this.hashCode()) + ")");
        return sb.toString();
    }
}
