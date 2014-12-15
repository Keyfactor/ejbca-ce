/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.scep;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * A response message for scep (pkcs7).
 *
 * @version $Id$
 */
public class ScepResponseMessage implements CertificateResponseMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 2016710353393853879L;

    private static Logger log = Logger.getLogger(ScepResponseMessage.class);

    /** The encoded response message */
    private byte[] responseMessage = null;

    /** status for the response */
    private ResponseStatus status = ResponseStatus.SUCCESS;

    /** Possible fail information in the response. Defaults to 'badRequest (2)'. */
    private FailInfo failInfo = FailInfo.BAD_REQUEST;

    /** Possible clear text error information in the response. Defaults to null. */
    private String failText = null;

    /**
     * SenderNonce. This is base64 encoded bytes
     */
    private String senderNonce = null;
    /**
     * RecipientNonce in a response is the senderNonce from the request. This is base64 encoded bytes
     */
    private String recipientNonce = null;

    /** transaction id */
    private String transactionId = null;

    /** recipient key identifier, usually IssuerAndSerialno in X509 world. */
    private byte[] recipientKeyInfo = null;

    /** Certificate to be in response message, not serialized */
    private transient Certificate cert = null;
    private transient CRL crl = null;
    /** Certificate for the signer of the response message (CA or RA) */
    private transient Collection<Certificate> signCertChain = null;
    /** Certificate for the CA of the response certificate in successful responses, is the same as signCert if not using RA mode */
    private transient Certificate caCert = null;
    /** Private key used to sign the response message */
    private transient PrivateKey signKey = null;
    /** If the CA certificate should be included in the reponse or not, default to true = yes */
    private transient boolean includeCACert = true;

    /** Default digest algorithm for SCEP response message, can be overridden */
    private transient String digestAlg = CMSSignedGenerator.DIGEST_MD5;
    
    private transient CertificateData certificateData;
    private transient Base64CertData base64CertData;
    
    @Override
    public CertificateData getCertificateData() {
        return certificateData;
    }
    
    @Override
    public void setCertificateData(CertificateData certificateData) {
        if (certificateData != null) {
            this.certificateData = new CertificateData(certificateData);
        } else {
            this.certificateData = null;
        }
    }
    
    @Override
    public Base64CertData getBase64CertData() {
        return base64CertData;
    }
    
    @Override
    public void setBase64CertData(final Base64CertData base64CertData) {
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }

    @Override
    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }
    
    @Override
    public Certificate getCertificate() {
        try {
            return CertTools.getCertfromByteArray(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new Error("Could not encode certificate. This should not happen", e);
        } catch (CertificateException e) {
            throw new Error("Response was created without containing valid certificate. This should not happen", e);
        }
    }

    @Override
    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    @Override
    public void setIncludeCACert(boolean incCACert) {
    	this.includeCACert = incCACert;
    }

    @Override
    public void setCACert(Certificate caCert) {
    	this.caCert = caCert;
    }

    @Override
    public byte[] getResponseMessage() throws CertificateEncodingException {
        return responseMessage;
    }

    @Override
    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    @Override
    public ResponseStatus getStatus() {
        return status;
    }

    @Override
    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    @Override
    public FailInfo getFailInfo() {
        return failInfo;
    }

    @Override
    public void setFailText(String failText) {
    	this.failText = failText;
    }

    @Override
    public String getFailText() {
    	return this.failText;
    }

    @Override
    public boolean create() throws CertificateEncodingException, CRLException {
      boolean ret = false;
        try {
            if (status.equals(ResponseStatus.SUCCESS)) {
                log.debug("Creating a STATUS_OK message.");
            } else {
            	if (status.equals(ResponseStatus.FAILURE)) {
                    log.debug("Creating a STATUS_FAILED message (or returning false).");
                    if (failInfo.equals(FailInfo.WRONG_AUTHORITY)) {
                    	return false;      
                    }
                    if (failInfo.equals(FailInfo.INCORRECT_DATA)) {
                        return false;     
                    }
                } else {
                    log.debug("Creating a STATUS_PENDING message.");
                }               
            }

            CMSTypedData msg;
            // Create encrypted response if this is success and NOT a CRL response message
            if (status.equals(ResponseStatus.SUCCESS)) {

                CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
                // Add the issued certificate to the signed portion of the CMS (as signer, degenerate case)
                List<X509Certificate> certList = new ArrayList<X509Certificate>();
                if (cert != null) {
                    log.debug("Adding certificates to response message");
                    certList.add((X509Certificate) cert);
                    // Add the CA cert, it's optional but Cisco VPN client complains if it isn't there
                    if (includeCACert) {
                    	if (caCert != null) {
                    		// If we have an explicit CAcertificate
                    		log.debug("Including explicitly set CA certificate in SCEP response.");
                    		certList.add((X509Certificate) caCert);
                    	} else {
                    		// If we don't have an explicit caCert, we think that the signCert is the CA cert
                    		// If we have an explicit caCert, the signCert is probably the RA certificate, and we don't include that one
                    		log.debug("Including message signer certificate in SCEP response.");
                    		certList.add((X509Certificate) signCertChain.iterator().next());
                    	}
                    }
                }
                // Create the signed CMS message to be contained inside the envelope
                // this message does not contain any message, and no signerInfo
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(certList)));
                if(crl != null) {
                    gen.addCRL(new JcaX509CRLHolder((X509CRL) crl));
                }
                CMSSignedData s = gen.generate(null, false);

                // Envelope the CMS message
                if (recipientKeyInfo != null) {
                    try {
                        X509Certificate rec = (X509Certificate)CertTools.getCertfromByteArray(recipientKeyInfo);
                        log.debug("Added recipient information - issuer: '" + CertTools.getIssuerDN(rec) + "', serno: '" + CertTools.getSerialNumberAsString(rec));
                        edGen.addKeyTransRecipient(rec);
                    } catch (CertificateParsingException e) {
                        throw new IllegalArgumentException("Can not decode recipients self signed certificate!", e);
                    }
                } else {
                    edGen.addKeyTransRecipient((X509Certificate) cert);
                }
                try {
                    JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC);
                    CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(s.getEncoded()), jceCMSContentEncryptorBuilder.build());
                    if (log.isDebugEnabled()) {
                        log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
                    }
                    msg = new CMSProcessableByteArray(ed.getEncoded());
                } catch (IOException e) {
                    throw new IllegalStateException("Unexpected IOException caught", e);
                }
            } else {
                // Create an empty message here
                //msg = new CMSProcessableByteArray("PrimeKey".getBytes());
                msg = new CMSProcessableByteArray(new byte[0]);
            }

            // Create the outermost signed data
            CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();

            // add authenticated attributes...status, transactionId, sender- and recipientNonce and more...
            Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
            ASN1ObjectIdentifier oid;
            Attribute attr;
            DERSet value;

            // Message type (certrep)
            oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType);
            value = new DERSet(new DERPrintableString("3"));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            // TransactionId
            if (transactionId != null) {
                oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_transId);
                log.debug("Added transactionId: " + transactionId);
                value = new DERSet(new DERPrintableString(transactionId));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // status
            oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus);
            value = new DERSet(new DERPrintableString(status.getStringValue()));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            if (status.equals(ResponseStatus.FAILURE)) {
                oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo);
                log.debug("Added failInfo: " + failInfo.getValue());
                value = new DERSet(new DERPrintableString(failInfo.getValue()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // senderNonce
            if (senderNonce != null) {
                oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce);
                log.debug("Added senderNonce: " + senderNonce);
                value = new DERSet(new DEROctetString(Base64.decode(senderNonce.getBytes())));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // recipientNonce
            if (recipientNonce != null) {
                oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_recipientNonce);
                log.debug("Added recipientNonce: " + recipientNonce);
                value = new DERSet(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // Add our signer info and sign the message
            Certificate cacert = signCertChain.iterator().next();
            log.debug("Signing SCEP message with cert: "+CertTools.getSubjectDN(cacert));
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromOID(PKCSObjectIdentifiers.md5WithRSAEncryption);
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithmName).setSecureRandom(new SecureRandom());
            try {
                ContentSigner contentSigner = signerBuilder.build(signKey);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                builder.setSignedAttributeGenerator(new SimpleAttributeTableGenerator(new AttributeTable(attributes)));
                gen1.addSignerInfoGenerator(builder.build(contentSigner, (X509Certificate) cacert));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            }
            // The un-encoded response message itself
            final CMSSignedData signedData = gen1.generate(msg, true);
            try {
                responseMessage = signedData.getEncoded();
            } catch (IOException e) {
                throw new IllegalStateException("Unexpected IOException caught.", e);
            }
            if (responseMessage != null) {
                ret = true;
            }
        } catch (CMSException e) {
            log.error("Error creating CMS message: ", e);
        }

        return ret;
    }

    @Override
    public boolean requireSignKeyInfo() {
        return true;
    }

    @Override
    public void setSignKeyInfo(Collection<Certificate> certs, PrivateKey key, String prov) {
        this.signCertChain = certs;
        this.signKey = key;

    }

    @Override
    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    @Override
    public void setRecipientNonce(String recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    @Override
    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    @Override
    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
        this.recipientKeyInfo = recipientKeyInfo;
    }

    @Override
    public void setPreferredDigestAlg(String digest) {
    	this.digestAlg = digest;
    }

    @Override
    public void setRequestType(int reqtype) {
	}

    @Override
    public void setRequestId(int reqid) {
    }

    @Override
    public void setProtectionParamsFromRequest(RequestMessage reqMsg) {
    }
}
