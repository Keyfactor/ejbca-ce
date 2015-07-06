package org.ejbca.core.protocol.scep;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
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
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/** Class used to generate SCEP messages. Used for SCEP clients and testing
 * 
 * @version $Id: ScepRequestGenerator.java 20960 2015-03-23 15:10:52Z mikekushner $
 */
public class ScepRequestGenerator {
    private static Logger log = Logger.getLogger(ScepRequestGenerator.class);

    private X509Certificate cacert = null;
    private String reqdn = null;
    private KeyPair keys = null;
    private String signatureProvider = null;
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
    
    public void setKeys(KeyPair myKeys, String signatureProvider) {
        this.keys = myKeys;
        this.signatureProvider = signatureProvider;
    }
    public void setDigestOid(String oid) {
        digestOid = oid;
    }
    /** Base 64 encode senderNonce
     */
    public String getSenderNonce() {
        return senderNonce;
    }

    public byte[] generateCrlReq(String dn, String transactionId, X509Certificate ca, final X509Certificate senderCertificate,
            final PrivateKey signatureKey) throws CertificateEncodingException, CMSException, IOException {
        this.cacert = ca;
        this.reqdn = dn;
        X500Name name = CertTools.stringToBcX500Name(cacert.getIssuerDN().getName());
        IssuerAndSerialNumber ias = new IssuerAndSerialNumber(name, cacert.getSerialNumber());       
        // wrap message in pkcs#7
        return wrap(ias.getEncoded(), "22", transactionId, senderCertificate, signatureKey);        
    }

    public byte[] generateCertReq(String dn, String password, String transactionId, X509Certificate ca, final X509Certificate senderCertificate,
            final PrivateKey signatureKey) throws IOException, OperatorCreationException, CertificateException, CMSException {
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
        return generateCertReq( dn, password, transactionId, ca, extgen.generate(), senderCertificate, signatureKey);
    }

    public byte[] generateCertReq(String dn, String password, String transactionId, X509Certificate ca, Extensions exts,
            final X509Certificate senderCertificate, final PrivateKey signatureKey) throws OperatorCreationException, CertificateException,
            IOException, CMSException {
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
        
        // wrap message in pkcs#7
        return wrap(p10request.getEncoded(), "19", transactionId, senderCertificate, signatureKey);
    }

    public byte[] generateGetCertInitial(String dn, String transactionId, X509Certificate ca, final X509Certificate senderCertificate,
            final PrivateKey signatureKey) throws NoSuchAlgorithmException,
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

        // wrap message in pkcs#7
        return wrap(seq.getEncoded(), "20", transactionId, senderCertificate, signatureKey);
    }
    
    private CMSEnvelopedData envelope(CMSTypedData envThis) throws CMSException, CertificateEncodingException {
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        // Envelope the CMS message
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cacert).setProvider(BouncyCastleProvider.PROVIDER_NAME));
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        CMSEnvelopedData ed = edGen.generate(envThis, jceCMSContentEncryptorBuilder.build());
        return ed;
    }

    private CMSSignedData sign(CMSTypedData signThis, String messageType, String transactionId, final X509Certificate senderCertificate,
            final PrivateKey signatureKey) throws CertificateEncodingException, CMSException {
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
        certList.add(senderCertificate);
        gen1.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(certList)));
       
        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(digestOid, signatureKey.getAlgorithm());
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(signatureProvider).build(signatureKey);
            JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
            builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
            gen1.addSignerInfoGenerator(builder.build(contentSigner, senderCertificate));
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
        }
        // The signed data to be enveloped
        CMSSignedData s = gen1.generate(signThis, true);
        return s;
    }

    private byte[] wrap(byte[] envBytes, String messageType, String transactionId, final X509Certificate senderCertificate,
            final PrivateKey signatureKey) throws CertificateEncodingException, CMSException, IOException {

        // 
        // Create inner enveloped data
        //
        CMSEnvelopedData ed = envelope(new CMSProcessableByteArray(envBytes));
        log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
        CMSTypedData msg = new CMSProcessableByteArray(ed.getEncoded());
        //
        // Create the outer signed data
        //
        CMSSignedData s = sign(msg, messageType, transactionId, senderCertificate, signatureKey);

        byte[] ret = s.getEncoded();
        return ret;

    }
}
