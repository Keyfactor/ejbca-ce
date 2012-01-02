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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * ASN.1 structure DER En/DeCoder.
 *
 * <pre>
 *   CertTemplate ::= SEQUENCE {
 *       version      [0] Version               OPTIONAL,
 *       serialNumber [1] INTEGER               OPTIONAL,
 *       signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 *       issuer       [3] Name                  OPTIONAL,
 *       validity     [4] OptionalValidity      OPTIONAL,
 *       subject      [5] Name                  OPTIONAL,
 *       publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 *       issuerUID    [7] UniqueIdentifier      OPTIONAL,
 *       subjectUID   [8] UniqueIdentifier      OPTIONAL,
 *       extensions   [9] Extensions            OPTIONAL }
 *
 * </pre>
 */
public class CertTemplate implements DEREncodable
{
    // name is not a choice type --> tag it implicit...no but it should be explicit?
	// Change to explicit by PrimeKey Solutions AB, Tomas Gustavsson
    public static final boolean bNameIsExplicit = true;

    private DERInteger            version = null;
    private DERInteger            serialNumber = null;
    private AlgorithmIdentifier   signingAlg = null;
    private X509Name              issuer = null;
    private OptionalValidity      validity = null;
    private X509Name              subject = null;
    private SubjectPublicKeyInfo  publicKey = null;
    private DERBitString          issuerUID = null;
    private DERBitString          subjectUID = null;
    private X509Extensions        extensions = null;

    public static CertTemplate getInstance( ASN1TaggedObject obj, boolean explicit )
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertTemplate getInstance( Object obj )
    {
        if (obj == null) {
            return new CertTemplate();
        }
        else if (obj instanceof CertTemplate) {
            return (CertTemplate)obj;
        }
        else if (obj instanceof ASN1Sequence) {
            return new CertTemplate((ASN1Sequence)obj);
        }
        else {
            throw new IllegalArgumentException("unknown object in factory");
        }
    }

    public CertTemplate( ASN1Sequence seq )
    {
      @SuppressWarnings("unchecked")
    Enumeration<DERTaggedObject> e = (seq == null ? null : seq.getObjects());
      while (e != null && e.hasMoreElements())
      {
        DERTaggedObject obj = e.nextElement();
        int tagno = (obj == null ? -1 : obj.getTagNo());
        switch( tagno )
        {
          case 0: this.version      = DERInteger.getInstance( obj, false ); break;
          case 1: this.serialNumber = DERInteger.getInstance( obj, false ); break;
          case 2: this.signingAlg   = AlgorithmIdentifier.getInstance( obj, false ); break;
          case 3: this.issuer       = X509Name.getInstance( obj, bNameIsExplicit ); break;
          case 4: this.validity     = OptionalValidity.getInstance( obj, false ); break;
          case 5: this.subject      = X509Name.getInstance( obj, bNameIsExplicit ); break;
          case 6: this.publicKey    = SubjectPublicKeyInfo.getInstance( obj, false ); break;
          case 7: this.issuerUID    = DERBitString.getInstance( obj, false ); break;
          case 8: this.subjectUID   = DERBitString.getInstance( obj, false ); break;
          case 9: this.extensions   = X509Extensions.getInstance( obj, false ); break;
          default : throw new IllegalArgumentException("invalid asn1 sequence");
        }
      }
    }

    public CertTemplate()
    {
    }

    public DERInteger getVersion()
    {
      return version;
    }

    public void setVersion(DERInteger version)
    {
      this.version = version;
    }

    public DERInteger getSerialNumber()
    {
      return serialNumber;
    }

    public void setSerialNumber(DERInteger serialNumber)
    {
      this.serialNumber = serialNumber;
    }

    public AlgorithmIdentifier getSigningAlg()
    {
      return signingAlg;
    }

    public void setSigningAlg(AlgorithmIdentifier signingAlg)
    {
      this.signingAlg = signingAlg;
    }

    public X509Name getIssuer()
    {
      return issuer;
    }

    public void setIssuer(X509Name issuer)
    {
      this.issuer = issuer;
    }

    public OptionalValidity getValidity()
    {
      return validity;
    }

    public void setValidity(OptionalValidity validity)
    {
      this.validity = validity;
    }

    public X509Name getSubject()
    {
      return subject;
    }

    public void setSubject(X509Name subject)
    {
      this.subject = subject;
    }

    public SubjectPublicKeyInfo getPublicKey()
    {
      return publicKey;
    }

    public void setPublicKey(SubjectPublicKeyInfo publicKey)
    {
      this.publicKey = publicKey;
    }

    public DERBitString getIssuerUID()
    {
      return issuerUID;
    }

    public void setIssuerUID(DERBitString issuerUID)
    {
      this.issuerUID = issuerUID;
    }

    public DERBitString getSubjectUID()
    {
      return subjectUID;
    }

    public void setSubjectUID(DERBitString subjectUID)
    {
      this.subjectUID = subjectUID;
    }

    public X509Extensions getExtensions()
    {
      return extensions;
    }

    public void setExtensions(X509Extensions extensions)
    {
      this.extensions = extensions;
    }

    public DERObject getDERObject()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector();

        if( version != null ) {
          v.add( new DERTaggedObject( false, 0, version ) );
        }
        if( serialNumber != null ) {
          v.add( new DERTaggedObject( false, 1, serialNumber ) );
        }
        if( signingAlg != null ) {
          v.add( new DERTaggedObject( false, 2, signingAlg ) );
        }
        if( issuer != null ) {
          v.add( new DERTaggedObject( bNameIsExplicit, 3, issuer) );
        }
        if( validity != null ) {
          v.add( new DERTaggedObject( false, 4, validity ) );
        }
        if( subject != null ) {
          v.add( new DERTaggedObject( bNameIsExplicit, 5, subject ) );
        } 
        if( publicKey != null ) {
          v.add( new DERTaggedObject( false, 6, publicKey ) );
        }
        if( issuerUID != null ) {
          v.add( new DERTaggedObject( false, 7, issuerUID ) );
        }
        if( subjectUID != null ) {
          v.add( new DERTaggedObject( false, 8, subjectUID ) );
        }
        if( extensions != null ) {
          v.add( new DERTaggedObject( false, 9, extensions ) );
        }

        return new DERSequence(v);
    }

    public String toString() {
    	StringBuilder sb = new StringBuilder(this.getClass().getName());
        sb.append(" (");

        if( this.getVersion() != null ) {
            sb.append("version: " + this.getVersion() + ", ");
        }
        if( this.getSerialNumber() != null ) {
            sb.append("serialNumber: " + this.getSerialNumber() + ", ");
        }
        if( this.getSigningAlg() != null ) {
            sb.append("signingAlg: " + this.getSigningAlg() + ", ");
        }
        if( this.getIssuer() != null ) {
            sb.append("issuer: " + this.getIssuer() + ", ");
        }
        if( this.getValidity() != null ) {
            sb.append("validity: " + this.getValidity() + ", ");
        }
        if( this.getSubject() != null ) {
            sb.append("subject: " + this.getSubject() + ", ");
        }
        if( this.getPublicKey() != null ) {
            sb.append("publicKey: " + this.getPublicKey() + ", ");
        }
        if( this.getIssuerUID() != null ) {
            sb.append("issuerUID: " + this.getIssuerUID() + ", ");
        }
        if( this.getSubjectUID() != null ) {
            sb.append("subjectUID: " + this.getSubjectUID() + ", ");
        }
        if( this.getExtensions() != null ) {
            sb.append("extensions: " + this.getExtensions() + ", ");
        }
        sb.append("hashCode: " + Integer.toHexString(this.hashCode()) + ")");
        return sb.toString();
    }
}
