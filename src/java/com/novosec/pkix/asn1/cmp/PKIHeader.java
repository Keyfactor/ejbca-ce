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

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *  PKIHeader ::= SEQUENCE {
 *      pvno                INTEGER     { ietf-version2 (1) },
 *      sender              GeneralName,                        -- identifies the sender
 *      recipient           GeneralName,                        -- identifies the intended recipient
 *      messageTime     [0] GeneralizedTime         OPTIONAL,   -- time of production of this message
 *      protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,   -- algorithm used for calculation of protection bits
 *      senderKID       [2] KeyIdentifier           OPTIONAL,   -- (OCTET STRING)
 *      recipKID        [3] KeyIdentifier           OPTIONAL,   -- (OCTET STRING) to identify specific keys used for protection
 *      transactionID   [4] OCTET STRING            OPTIONAL,   -- identifies the transaction; i.e., this will be the same in corresponding request, response and confirmation messages
 *      senderNonce     [5] OCTET STRING            OPTIONAL,
 *      recipNonce      [6] OCTET STRING            OPTIONAL,   -- nonces used to provide replay protection, senderNonce is inserted by the creator of this message; recipNonce is a nonce previously inserted in a related message by the intended recipient of this message
 *      freeText        [7] PKIFreeText             OPTIONAL,   -- this may be used to indicate context-specific instructions (this field is intended for human consumption)
 *      generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
 *                             InfoTypeAndValue     OPTIONAL    -- this may be used to convey context-specific information (this field not primarily intended for human consumption)
 *  }     
 *
 * </pre>
 */
public class PKIHeader implements ASN1Encodable
{
    DERInteger           pvno;
    GeneralName          sender;
    GeneralName          recipient;
    DERGeneralizedTime   messageTime;
    AlgorithmIdentifier  protectionAlg;
    DEROctetString       senderKID;
    DEROctetString       recipKID;
    DEROctetString       transactionID;
    DEROctetString       senderNonce;
    DEROctetString       recipNonce;
    PKIFreeText          freeText;
    Vector<InfoTypeAndValue>               generalInfos = new Vector<InfoTypeAndValue>();

    public static PKIHeader getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIHeader getInstance( Object obj )
    {
        if (obj instanceof PKIHeader)
        {
            return (PKIHeader)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PKIHeader((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public PKIHeader( ASN1Sequence seq )
    {
      @SuppressWarnings("unchecked")
    Enumeration<Object> e = seq.getObjects();

      pvno      = DERInteger.getInstance(e.nextElement());
      sender    = GeneralName.getInstance(e.nextElement());
      recipient = GeneralName.getInstance(e.nextElement());
      
      while (e.hasMoreElements())
      {
        ASN1TaggedObject tagObj = (ASN1TaggedObject)e.nextElement();

        switch (tagObj.getTagNo())
        {
          case 0: messageTime   = DERGeneralizedTime.getInstance(tagObj, tagObj.isExplicit()); break;
          case 1: protectionAlg = AlgorithmIdentifier.getInstance(tagObj, tagObj.isExplicit()); break;
          case 2: senderKID     = (DEROctetString)DEROctetString.getInstance(tagObj, tagObj.isExplicit()); break;
          case 3: recipKID      = (DEROctetString)DEROctetString.getInstance(tagObj, tagObj.isExplicit()); break;
          case 4: transactionID = (DEROctetString)DEROctetString.getInstance(tagObj, tagObj.isExplicit()); break;
          case 5: senderNonce   = (DEROctetString)DEROctetString.getInstance(tagObj, tagObj.isExplicit()); break;
          case 6: recipNonce    = (DEROctetString)DEROctetString.getInstance(tagObj, tagObj.isExplicit()); break;
          case 7: freeText      = PKIFreeText.getInstance(tagObj.getObject()); break;
          case 8: 
            ASN1Sequence s = (ASN1Sequence)tagObj.getObject();
            for( int i=0; i<s.size(); i++ ) {
              generalInfos.addElement( InfoTypeAndValue.getInstance(s.getObjectAt(i)) );
            }
            break;
        }
      }
    }

    public PKIHeader( DERInteger pvno, GeneralName sender, GeneralName recipient )
    {
        this.pvno = pvno;
        this.sender = sender;
        this.recipient = recipient;
    }

    public DERInteger getPvno()
    {
        return pvno;
    }

    public GeneralName getSender()
    {
        return sender;
    }

    public GeneralName getRecipient()
    {
        return recipient;
    }
    
    public void setMessageTime( DERGeneralizedTime messageTime )
    {
      this.messageTime = messageTime;
    }

    public DERGeneralizedTime getMessageTime()
    {
      return messageTime;
    }

    public void setProtectionAlg( AlgorithmIdentifier protectionAlg )
    {
      this.protectionAlg = protectionAlg;
    }

    public AlgorithmIdentifier getProtectionAlg()
    {
      return protectionAlg;
    }

    public void setSenderKID( DEROctetString senderKID )
    {
      this.senderKID = senderKID;
    }

    public DEROctetString getSenderKID()
    {
      return senderKID;
    }

    public void setRecipKID( DEROctetString recipKID )
    {
      this.recipKID = recipKID;
    }

    public DEROctetString getRecipKID()
    {
      return recipKID;
    }

    public void setTransactionID( DEROctetString transactionID )
    {
      this.transactionID = transactionID;
    }

    public DEROctetString getTransactionID()
    {
      return transactionID;
    }

    public void setSenderNonce( DEROctetString senderNonce )
    {
      this.senderNonce = senderNonce;
    }

    public DEROctetString getSenderNonce()
    {
      return senderNonce;
    }

    public void setRecipNonce( DEROctetString recipNonce )
    {
      this.recipNonce = recipNonce;
    }

    public DEROctetString getRecipNonce()
    {
      return recipNonce;
    }

    public void setFreeText( PKIFreeText freeText )
    {
      this.freeText = freeText;
    }

    public PKIFreeText getFreeText()
    {
      return freeText;
    }

    public void addGeneralInfo( InfoTypeAndValue generalInfo )
    {
      this.generalInfos.addElement(generalInfo);
    }

    public InfoTypeAndValue getGeneralInfo(int nr)
    {
      if (generalInfos.size() > nr) {
        return generalInfos.elementAt(nr);
      }

      return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( pvno );
      v.add( sender );
      v.add( recipient );
      
      if( messageTime != null ) {
        v.add( new DERTaggedObject( true, 0, messageTime ) );
      }

      if( protectionAlg != null ) {
        v.add( new DERTaggedObject( true, 1, protectionAlg ) );
      }

      if( senderKID != null ) {
        v.add( new DERTaggedObject( true, 2, senderKID ) );
      }

      if( recipKID != null ) {
        v.add( new DERTaggedObject( true, 3, recipKID ) );
      }

      if( transactionID != null ) {
        v.add( new DERTaggedObject( true, 4, transactionID ) );
      }

      if( senderNonce != null ) {
        v.add( new DERTaggedObject( true, 5, senderNonce ) );
      }

      if( recipNonce != null ) {
        v.add( new DERTaggedObject( true, 6, recipNonce ) );
      }

      if( freeText != null ) {
        v.add( new DERTaggedObject( true, 7, freeText ) );
      }

      if( generalInfos.size() > 0 )
      {
        ASN1EncodableVector giv = new ASN1EncodableVector();
  
        for (int i=0;i<generalInfos.size();i++) {
          giv.add(generalInfos.elementAt(i));
        }
  
        v.add( new DERTaggedObject( true, 8, new DERSequence(giv) ) );
      }
      
      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "PKIHeader: ( pvno: " + pvno + ", sender: " + sender + ", recipient: " + recipient + ", ";

      if( messageTime != null ) {
        s += "messageTime: "  + messageTime + ", ";
      }

      if( protectionAlg != null ) {
        s += "protectionAlg: "  + protectionAlg + ", ";
      }

      if( senderKID != null ) {
        s += "senderKID: "  + senderKID + ", ";
      }

      if( recipKID != null ) {
        s += "recipKID: "  + recipKID + ", ";
      }

      if( transactionID != null ) {
        s += "transactionID: "  + transactionID + ", ";
      }

      if( senderNonce != null ) {
        s += "senderNonce: "  + senderNonce + ", ";
      }

      if( recipNonce != null ) {
        s += "recipNonce: "  + recipNonce + ", ";
      }
      
      if( freeText != null ) {
        s += "freeText: "  + freeText + ", ";
      }

      if( generalInfos.size() > 0 )
      {
        s += "generalInfo: (";
        for (int i=0;i<generalInfos.size();i++) {
          s += generalInfos.elementAt(i) + ", ";
        }
        s += ")";
      }        
      
      return s;
    }
}
