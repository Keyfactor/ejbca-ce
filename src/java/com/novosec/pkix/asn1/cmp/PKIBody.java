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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x509.X509CertificateStructure;

import com.novosec.pkix.asn1.crmf.CertReqMessages;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   PKIBody ::= CHOICE {
 *       ir      [0]  CertReqMessages,        --Initialization Request
 *       ip      [1]  CertRepMessage,         --Initialization Response
 *       cr      [2]  CertReqMessages,        --Certification Request
 *       cp      [3]  CertRepMessage,         --Certification Response
 *       p10cr   [4]  CertificationRequest,   --imported from [PKCS10]
 *       popdecc [5]  POPODecKeyChallContent, --pop Challenge
 *       popdecr [6]  POPODecKeyRespContent,  --pop Response
 *       kur     [7]  CertReqMessages,        --Key Update Request
 *       kup     [8]  CertRepMessage,         --Key Update Response
 *       krr     [9]  CertReqMessages,        --Key Recovery Request
 *       krp     [10] KeyRecRepContent,       --Key Recovery Response
 *       rr      [11] RevReqContent,          --Revocation Request
 *       rp      [12] RevRepContent,          --Revocation Response
 *       ccr     [13] CertReqMessages,        --Cross-Cert. Request
 *       ccp     [14] CertRepMessage,         --Cross-Cert. Response
 *       ckuann  [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
 *       cann    [16] CertAnnContent,         --Certificate Ann.      (X509Certificate)
 *       rann    [17] RevAnnContent,          --Revocation Ann.
 *       crlann  [18] CRLAnnContent,          --CRL Announcement
 *       conf    [19] PKIConfirmContent,      --Confirmation          (NULL)
 *       nested  [20] NestedMessageContent,   --Nested Message        (PKIMessage)
 *       genm    [21] GenMsgContent,          --General Message
 *       genp    [22] GenRepContent,          --General Response
 *       error   [23] ErrorMsgContent         --Error Message
 *       certConf[24] CertConfirmContent      --Certificate Confirm
 *   }
 *  
 * </pre>
 */
public class PKIBody implements DEREncodable
{
    DEREncodable  	obj;
    int           	tag;

    public PKIBody( DEREncodable obj, int tag )
    {
        this.obj = obj;
        this.tag = tag;
    }

    public int getTagNo() 
    {
      return tag;
    }
    
    public CertReqMessages getIr()
    {
      if( this.tag != 0 ) {
        return null;
      }
      return (CertReqMessages)this.obj;
    }
    
    public CertRepMessage getIp()
    {
      if( this.tag != 1 ) {
        return null;
      }
      return (CertRepMessage)this.obj;
    }

    public CertReqMessages getCr()
    {
      if( this.tag != 2 ) {
        return null;
      }
      return (CertReqMessages)this.obj;
    }

    public CertRepMessage getCp()
    {
      if( this.tag != 3 ) {
        return null;
      }
      return (CertRepMessage)this.obj;
    }
    
    public CertificationRequest getP10cr()
    {
      if( this.tag != 4 ) {
        return null;
      }
      return (CertificationRequest)this.obj;
    }
    
    public POPODecKeyChallContent getPopdecc()
    {
      if( this.tag != 5 ) {
        return null;
      }
      return (POPODecKeyChallContent)this.obj;
    }

    public POPODecKeyRespContent getPopdecr()
    {
      if( this.tag != 6 ) {
        return null;
      }
      return (POPODecKeyRespContent)this.obj;
    }
    
    public CertReqMessages getKur()
    {
      if( this.tag != 7 ) {
        return null;
      }
      return (CertReqMessages)this.obj;
    }
    
    public CertRepMessage getKup()
    {
      if( this.tag != 8 ) {
        return null;
      }
      return (CertRepMessage)this.obj;
    }

    public CertReqMessages getKrr()
    {
      if( this.tag != 9 ) {
        return null;
      }
      return (CertReqMessages)this.obj;
    }
    
    public KeyRecRepContent getKrp()
    {
      if( this.tag != 10 ) {
        return null;
      }
      return (KeyRecRepContent)this.obj;
    }

    public RevReqContent getRr()
    {
      if( this.tag != 11 ) {
        return null;
      }
      return (RevReqContent)this.obj;
    }
    
    public RevRepContent getRp()
    {
      if( this.tag != 12 ) {
        return null;
      }
      return (RevRepContent)this.obj;
    }

    public CertReqMessages getCcr()
    {
      if( this.tag != 13 ) {
        return null;
      }
      return (CertReqMessages)this.obj;
    }

    public CertRepMessage getCcp()
    {
      if( this.tag != 14 ) {
        return null;
      }
      return (CertRepMessage)this.obj;
    }

    public CAKeyUpdAnnContent getCkuann()
    {
      if( this.tag != 15 ) {
        return null;
      }
      return (CAKeyUpdAnnContent)this.obj;
    }

    public X509CertificateStructure getCann()
    {
      if( this.tag != 16 ) {
        return null;
      }
      return (X509CertificateStructure)this.obj;
    }

    public RevAnnContent getRann()
    {
      if( this.tag != 17 ) {
        return null;
      }
      return (RevAnnContent)this.obj;
    }

    public CRLAnnContent getCrlann()
    {
      if( this.tag != 18 ) {
        return null;
      }
      return (CRLAnnContent)this.obj;
    }

    public DERNull getConf()
    {
      if( this.tag != 19 ) {
        return null;
      }
      return (DERNull)this.obj;
    }

    public PKIMessage getNested()
    {
      if( this.tag != 20 ) {
        return null;
      }
      return (PKIMessage)this.obj;
    }

    public GenMsgContent getGenm()
    {
      if( this.tag != 21 ) {
        return null;
      }
      return (GenMsgContent)this.obj;
    }

    public GenRepContent getGenp()
    {
      if( this.tag != 22 ) {
        return null;
      }
      return (GenRepContent)this.obj;
    }

    public ErrorMsgContent getError()
    {
      if( this.tag != 23 ) {
        return null;
      }
      return (ErrorMsgContent)this.obj;
    }

    public CertConfirmContent getCertConf() {
    	if (this.tag != 24 ) { 
    		return null;
    	}
    	return (CertConfirmContent)this.obj;
    }
    
    public static PKIBody getInstance( DERObject obj )
    {
      return getInstance( (ASN1TaggedObject)obj, true );
    }

    public static PKIBody getInstance( ASN1TaggedObject tagObj, boolean explicit )
    {
        int tag = tagObj.getTagNo();

        switch (tag)
        {
          case 0:  return new PKIBody(CertReqMessages.getInstance(tagObj.getObject()),          0);
          case 1:  return new PKIBody(CertRepMessage.getInstance(tagObj.getObject()),           1);
          case 2:  return new PKIBody(CertReqMessages.getInstance(tagObj.getObject()),          2);
          case 3:  return new PKIBody(CertRepMessage.getInstance(tagObj.getObject()),           3);
          case 4:  return new PKIBody(tagObj.getObject(), 4);
          case 5:  return new PKIBody(POPODecKeyChallContent.getInstance(tagObj.getObject()),   5);
          case 6:  return new PKIBody(POPODecKeyRespContent.getInstance(tagObj.getObject()),    6);
          case 7:  return new PKIBody(CertReqMessages.getInstance(tagObj.getObject()),          7);
          case 8:  return new PKIBody(CertRepMessage.getInstance(tagObj.getObject()),           8);
          case 9:  return new PKIBody(CertReqMessages.getInstance(tagObj.getObject()),          9);
          case 10: return new PKIBody(KeyRecRepContent.getInstance(tagObj.getObject()),        10);
          case 11: return new PKIBody(RevReqContent.getInstance(tagObj.getObject()),           11);
          case 12: return new PKIBody(RevRepContent.getInstance(tagObj.getObject()),           12);
          case 13: return new PKIBody(CertReqMessages.getInstance(tagObj.getObject()),         13);
          case 14: return new PKIBody(CertRepMessage.getInstance(tagObj.getObject()),          14);
          case 15: return new PKIBody(CAKeyUpdAnnContent.getInstance(tagObj.getObject()),      15);
          case 16: return new PKIBody(X509CertificateStructure.getInstance(tagObj.getObject()),16);          
          case 17: return new PKIBody(RevAnnContent.getInstance(tagObj.getObject()),           17);
          case 18: return new PKIBody(CRLAnnContent.getInstance(tagObj.getObject()),           18);
          case 19: return new PKIBody(tagObj.getObject(),                             19);
          case 20: return new PKIBody(PKIMessage.getInstance(tagObj.getObject()),              20);          
          case 21: return new PKIBody(GenMsgContent.getInstance(tagObj.getObject()),           21);
          case 22: return new PKIBody(GenRepContent.getInstance(tagObj.getObject()),           22);
          case 23: return new PKIBody(ErrorMsgContent.getInstance(tagObj.getObject()),         23);
          case 24: return new PKIBody(CertConfirmContent.getInstance(tagObj.getObject()),      24);
        }

        throw new IllegalArgumentException("unknown tag: " + tag);
    }

    public DERObject getDERObject()
    {
      return new DERTaggedObject(true, tag, obj);
    }

    public String toString()
    {
      return "PKIBody: (" + obj + ")";
    }
}
