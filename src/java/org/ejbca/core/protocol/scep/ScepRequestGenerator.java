package org.ejbca.core.protocol.scep;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/** Class used to generate SCEP messages. Used for SCEP clients and testing
 * 
 * @author tomas
 * @version $Id$
 */
public class ScepRequestGenerator {
    private static Logger log = Logger.getLogger(ScepRequestGenerator.class);

    private X509Certificate cert = null;
    private X509Certificate cacert = null;
    private String reqdn = null;
    private KeyPair keys = null;
    private String digestOid = CMSSignedGenerator.DIGEST_SHA1;
    private String senderNonce = null;

    /** A good random source for nounces, can take a long time to initialize on vmware */
    private static SecureRandom randomSource = null;

    public ScepRequestGenerator() {
    	try { 
    		if (randomSource == null) {
        		randomSource = SecureRandom.getInstance("SHA1PRNG");    			
    		}
    	} catch (Exception e) {
    		log.error(e);
    	}
    }
    
    public void setKeys(KeyPair myKeys) {
        this.keys = myKeys;
    }
    public void setDigestOid(String oid) {
    	digestOid = oid;
    }
    /** Base 64 encode senderNonce
     */
    public String getSenderNonce() {
        return senderNonce;
    }

    public byte[] generateCrlReq(String dn, String transactionId, X509Certificate ca) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, CMSException, InvalidAlgorithmParameterException, CertStoreException, IllegalStateException, OperatorCreationException, CertificateException {
        this.cacert = ca;
        this.reqdn = dn;
        X500Name name = CertTools.stringToBcX500Name(cacert.getIssuerDN().getName());
        IssuerAndSerialNumber ias = new IssuerAndSerialNumber(name, cacert.getSerialNumber());
        // Create self signed cert, validity 1 day
        cert = CertTools.genSelfCert(reqdn,24*60*60*1000,null,keys.getPrivate(),keys.getPublic(),AlgorithmConstants.SIGALG_SHA1_WITH_RSA,false);
        
        // wrap message in pkcs#7
        byte[] msg = wrap(ias.getEncoded(), "22", transactionId);        
        return msg;
    }
    public byte[] generateCertReq(String dn, String password, String transactionId, X509Certificate ca) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, CMSException, InvalidAlgorithmParameterException, CertStoreException, IllegalStateException, OperatorCreationException, CertificateException {
        // Extension request attribute is a set of X509Extensions
        // ASN1EncodableVector x509extensions = new ASN1EncodableVector();
        // An X509Extensions is a sequence of Extension which is a sequence of {oid, X509Extension}
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        // Requested extensions attribute
        // AltNames
        final GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo.bar.com,iPAddress=10.0.0.1");
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final DEROutputStream dOut = new DEROutputStream(bOut);
        try {
            dOut.writeObject(san);
        } catch (IOException e) {
            throw new IllegalArgumentException("error encoding value: " + e);
        }
        extgen.addExtension(Extension.subjectAlternativeName, false, new DEROctetString(bOut.toByteArray()));
        return generateCertReq( dn, password, transactionId, ca, extgen.generate() );
    }
    public byte[] generateCertReq(String dn, String password, String transactionId, X509Certificate ca, Extensions exts) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, CMSException, InvalidAlgorithmParameterException, CertStoreException, IllegalStateException, OperatorCreationException, CertificateException {
        this.cacert = ca;
        this.reqdn = dn;
        // Generate keys

        // Create challenge password attribute for PKCS10
        // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
        //
        // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
        //    type    ATTRIBUTE.&id({IOSet}),
        //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
        // }
        ASN1EncodableVector challpwdattr = new ASN1EncodableVector();
        // Challenge password attribute
        challpwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
        ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
        pwdvalues.add(new DERUTF8String(password));
        challpwdattr.add(new DERSet(pwdvalues));
        ASN1EncodableVector extensionattr = new ASN1EncodableVector();
        extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        extensionattr.add(new DERSet(exts));
        // Complete the Attribute section of the request, the set (Attributes) contains two sequences (Attribute)
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(challpwdattr));
        v.add(new DERSequence(extensionattr));
        DERSet attributes = new DERSet(v);
        // Create PKCS#10 certificate request
        final PKCS10CertificationRequest p10request = CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX500Name(reqdn), keys.getPublic(), attributes, keys.getPrivate(), null);
        
        // Create self signed cert, validity 1 day
        this.cert = CertTools.genSelfCert(reqdn,24*60*60*1000,null,keys.getPrivate(),keys.getPublic(),AlgorithmConstants.SIGALG_SHA1_WITH_RSA,false);
        
        // wrap message in pkcs#7
        byte[] msg = wrap(p10request.getEncoded(), "19", transactionId);
        return msg;        
    }

    public byte[] generateGetCertInitial(String dn, String transactionId, X509Certificate ca) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, CertStoreException, IOException, CMSException, CertificateEncodingException {
        this.cacert = ca;
        this.reqdn = dn;

        // pkcsGetCertInitial issuerAndSubject ::= { 
        //	    issuer "the certificate authority issuer name" 
        //	    subject "the requester subject name as given in PKCS#10" 
        //	} 
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new DERUTF8String(ca.getIssuerDN().getName()));
        vec.add(new DERUTF8String(dn));
        DERSequence seq = new DERSequence(vec);

        // The self signed certificate has already been generated when the request message was created
        // Create self signed cert, validity 1 day
        //cert = CertTools.genSelfCert(reqdn,24*60*60*1000,null,keys.getPrivate(),keys.getPublic(),AlgorithmConstants.SIGALG_SHA1_WITH_RSA,false);

        // wrap message in pkcs#7
        byte[] msg = wrap(seq.getEncoded(), "20", transactionId);
        return msg;
    }
    
    private CMSEnvelopedData envelope(CMSTypedData envThis) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, CertificateEncodingException {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        // Envelope the CMS message
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cacert));
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC);
        CMSEnvelopedData ed = edGen.generate(envThis, jceCMSContentEncryptorBuilder.build());
        return ed;
    }

    private CMSSignedData sign(CMSTypedData signThis, String messageType, String transactionId) throws NoSuchAlgorithmException,
            NoSuchProviderException, CMSException, IOException, InvalidAlgorithmParameterException, CertStoreException, CertificateEncodingException {
        CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();

        // add authenticated attributes...status, transactionId, sender- and more...
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
        ASN1ObjectIdentifier oid;
        Attribute attr;
        DERSet value;
        
        // Message type (certreq)
        oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType);
        value = new DERSet(new DERPrintableString(messageType));
        attr = new Attribute(oid, value);
        attributes.put(attr.getAttrType(), attr);

        // TransactionId
        oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_transId);
        value = new DERSet(new DERPrintableString(transactionId));
        attr = new Attribute(oid, value);
        attributes.put(attr.getAttrType(), attr);

        // senderNonce
        byte[] nonce = new byte[16];
        randomSource.nextBytes(nonce);
        senderNonce = new String(Base64.encode(nonce));
        if (nonce != null) {
            oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce);
            log.debug("Added senderNonce: " + senderNonce);
            value = new DERSet(new DEROctetString(nonce));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);
        }

        // Add our signer info and sign the message
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(cert);
        gen1.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(certList)));
        gen1.addSigner(keys.getPrivate(), cert, digestOid,
                new AttributeTable(attributes), null);
        // The signed data to be enveloped
        CMSSignedData s = gen1.generate(signThis, true);
        return s;
    }

    private byte[] wrap(byte[] envBytes, String messageType, String transactionId) throws IOException, NoSuchAlgorithmException,
            NoSuchProviderException, CMSException, InvalidAlgorithmParameterException, CertStoreException, CertificateEncodingException {

        // 
        // Create inner enveloped data
        //
        CMSEnvelopedData ed = envelope(new CMSProcessableByteArray(envBytes));
        log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
        CMSTypedData msg = new CMSProcessableByteArray(ed.getEncoded());
        //
        // Create the outer signed data
        //
        CMSSignedData s = sign(msg, messageType, transactionId);

        byte[] ret = s.getEncoded();
        return ret;

    }
}
