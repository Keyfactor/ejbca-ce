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

import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   PKIPublicationInfo ::= SEQUENCE {
 *     action     INTEGER {
 *                  dontPublish (0),
 *                  pleasePublish (1) },
 *     pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL } -- pubInfos MUST NOT be present if action is "dontPublish" (if action is "pleasePublish" and pubInfos is omitted, "dontCare" is assumed)
 *
 * </pre>
 */
public class PKIPublicationInfo implements DEREncodable
{
    DERInteger   action;
    Vector<SinglePubInfo>       pubInfos = new Vector<SinglePubInfo>();

    public static PKIPublicationInfo getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIPublicationInfo getInstance( Object obj )
    {
        if (obj instanceof PKIPublicationInfo)
        {
            return (PKIPublicationInfo)obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new PKIPublicationInfo((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("unknown object in factory");
    }
	
    public PKIPublicationInfo( ASN1Sequence seq )
    {
      this.action = DERInteger.getInstance(seq.getObjectAt(0));
      if( seq.size()>1 )
      {
        ASN1Sequence s = (ASN1Sequence)seq.getObjectAt(1);
        for( int i=0; i<s.size(); i++ ) {
          pubInfos.addElement( SinglePubInfo.getInstance(s.getObjectAt(i)) );
        }
      }
    }

    public PKIPublicationInfo( DERInteger action )
    {
      this.action = action;
    }

    public DERInteger getAction()
    {
        return action;
    }

    public SinglePubInfo getPubInfo(int nr)
    {
      if( pubInfos.size() > nr ) {
        return (SinglePubInfo)pubInfos.elementAt(nr);
      }
      return null;
    }

    public void addPubInfo(SinglePubInfo pubInfo)
    {
      pubInfos.addElement( pubInfo );
    }

    public DERObject getDERObject()
    {
      ASN1EncodableVector  v = new ASN1EncodableVector();

      v.add( action );

      if( pubInfos.size() > 0 )
      {
        ASN1EncodableVector pubiv = new ASN1EncodableVector();
        for (int i=0;i<pubInfos.size();i++) {
          pubiv.add( (SinglePubInfo)pubInfos.elementAt(i) );
        }
        v.add( new DERSequence( pubiv ) );
      }

      return new DERSequence(v);
    }

    public String toString()
    {
      String s = "PKIPublicationInfo: (action = " + this.getAction();
      
      if( pubInfos.size() > 0 )
      {
        s += "pubInfos : (";
        
        for (int i=0;i<pubInfos.size();i++) {
          s += (SinglePubInfo)pubInfos.elementAt(i);
        }
        s += ")";
      }

      s += ")";
      
      return s;
    }
}
