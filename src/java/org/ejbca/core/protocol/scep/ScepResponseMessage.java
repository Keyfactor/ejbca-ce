/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * A response message for scep (pkcs7).
 *
 * @version $Id$
 */
public class ScepResponseMessage implements IResponseMessage {
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

    /** The un-encoded response message itself */
    private transient CMSSignedData signedData = null;

    /** Certificate to be in response message, not serialized */
    private transient Certificate cert = null;
    private transient CRL crl = null;
    /** Certificate for the signer of the response message (CA or RA) */
    private transient Certificate signCert = null;
    /** Certificate for the CA of the response certificate in successful responses, is the same as signCert if not using RA mode */
    private transient Certificate caCert = null;
    /** Private key used to sign the response message */
    private transient PrivateKey signKey = null;
    /** The default provider is BC, if nothing else is specified when setting SignKeyInfo */
    private transient String provider = "BC";
    /** If the CA certificate should be included in the reponse or not, default to true = yes */
    private transient boolean includeCACert = true;

    /** Default digest algorithm for SCEP response message, can be overridden */
    private transient String digestAlg = CMSSignedGenerator.DIGEST_MD5;
    /**
     * Sets the complete certificate in the response message.
     *
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert) {
        this.cert = cert;
    }

    /**
     * Sets the CRL (if present) in the response message.
     *
     * @param crl crl in the response message.
     */
    public void setCrl(CRL crl) {
        this.crl = crl;
    }

    /** @see org.ejbca.core.protocol.IResponseMessage#setIncludeCACert
     * 
     */
    public void setIncludeCACert(boolean incCACert) {
    	this.includeCACert = incCACert;
    }

    public void setCACert(Certificate caCert) {
    	this.caCert = caCert;
    }

    /**
     * Gets the response message in the default encoding format.
     *
     * @return the response message in the default encoding format.
     */
    public byte[] getResponseMessage() throws IOException, CertificateEncodingException {
        return responseMessage;
    }

    /**
     * Sets the status of the response message.
     *
     * @param status status of the response.
     */
    public void setStatus(ResponseStatus status) {
        this.status = status;
    }

    /**
     * Gets the status of the response message.
     *
     * @return status status of the response.
     */
    public ResponseStatus getStatus() {
        return status;
    }

    /**
     * Sets info about reason for failure.
     *
     * @param failInfo reason for failure.
     */
    public void setFailInfo(FailInfo failInfo) {
        this.failInfo = failInfo;
    }

    /**
     * Gets info about reason for failure.
     *
     * @return failInfo reason for failure.
     */
    public FailInfo getFailInfo() {
        return failInfo;
    }

    public void setFailText(String failText) {
    	this.failText = failText;
    }

    public String getFailText() {
    	return this.failText;
    }

    /**
     * Create encrypts and creates signatures as needed to produce a complete response message.  If
     * needed setSignKeyInfo and setEncKeyInfo must be called before this method. After this is
     * called the response message can be retrieved with getResponseMessage();
     *
     * @return True if signature/encryption was successful, false if it failed, request should not
     *         be sent back i failed.
     *
     * @throws IOException If input/output or encoding failed.
     * @throws InvalidKeyException If the key used for signing/encryption is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     * @throws NotFoundException 
     *
     * @see #setSignKeyInfo
     * @see #setEncKeyInfo
     */
    public boolean create()
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignRequestException, NotFoundException {
        boolean ret = false;

        try {

            if (status.equals(ResponseStatus.SUCCESS)) {
                log.debug("Creating a STATUS_OK message.");
            } else {
            	if (status.equals(ResponseStatus.FAILURE)) {
                    log.debug("Creating a STATUS_FAILED message (or throwing an exception).");
                    if (failInfo.equals(FailInfo.WRONG_AUTHORITY)) {
                    	throw new SignRequestException(failText);            
                    }
                    if (failInfo.equals(FailInfo.INCORRECT_DATA)) {
                    	throw new NotFoundException(failText);
                    }

                } else {
                    log.debug("Creating a STATUS_PENDING message.");
                }               
            }

            CMSProcessable msg;
            // Create encrypted response if this is success and NOT a CRL response message
            if (status.equals(ResponseStatus.SUCCESS)) {

                CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
                // Add the issued certificate to the signed portion of the CMS (as signer, degenerate case)
                ArrayList certList = new ArrayList();
                if (crl != null) {
                    log.debug("Adding CRL to response message (inner signer)");
                    certList.add(crl);
                } else if (cert != null) {
                    log.debug("Adding certificates to response message");
                    certList.add(cert);
                    // Add the CA cert, it's optional but Cisco VPN client complains if it isn't there
                    if (includeCACert) {
                    	if (caCert != null) {
                    		// If we have an explicit CAcertificate
                    		log.debug("Including explicitly set CA certificate in SCEP response.");
                    		certList.add(caCert);
                    	} else {
                    		// If we don't have an explicit caCert, we think that the signCert is the CA cert
                    		// If we have an explicit caCert, the signCert is probably the RA certificate, and we don't include that one
                    		log.debug("Including message signer certificate in SCEP response.");
                    		certList.add(signCert);
                    	}
                    }
                }
                CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

                // Create the signed CMS message to be contained inside the envelope
                // this message does not contain any message, and no signerInfo
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addCertificatesAndCRLs(certs);
                CMSSignedData s = gen.generate(null, false, "BC");

                // Envelope the CMS message
                if (recipientKeyInfo != null) {
                    try {
                        X509Certificate rec = (X509Certificate)CertTools.getCertfromByteArray(recipientKeyInfo);
                        log.debug("Added recipient information - issuer: '" + CertTools.getIssuerDN(rec) + "', serno: '" + CertTools.getSerialNumberAsString(rec));
                        edGen.addKeyTransRecipient(rec);
                    } catch (CertificateException e) {
                        throw new IOException("Can not decode recipients self signed certificate!");
                    }
                } else {
                    edGen.addKeyTransRecipient((X509Certificate) cert);
                }
                CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(s.getEncoded()),
                        SMIMECapability.dES_CBC.getId(), "BC");

                log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
                msg = new CMSProcessableByteArray(ed.getEncoded());
            } else {
                // Create an empty message here
                //msg = new CMSProcessableByteArray("PrimeKey".getBytes());
                msg = new CMSProcessableByteArray(new byte[0]);
            }

            // Create the outermost signed data
            CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();

            // add authenticated attributes...status, transactionId, sender- and recipientNonce and more...
            Hashtable attributes = new Hashtable();
            DERObjectIdentifier oid;
            Attribute attr;
            DERSet value;
            
            // Content Type
            /* Added automagically by CMSSignedDataGenerator
            oid = PKCSObjectIdentifiers.pkcs_9_at_contentType;
            value = new DERSet(PKCSObjectIdentifiers.data);
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);
            */

            // Message digest
            /* Added automagically by CMSSignedDataGenerator
            byte[] digest = null;
            if (s != null) {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                digest = md.digest(s.getEncoded());
            } else {
                digest = new byte[]{0};
            }
            oid = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
            value = new DERSet(new DEROctetString(digest));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);
            */

            // Message type (certrep)
            oid = new DERObjectIdentifier(ScepRequestMessage.id_messageType);
            value = new DERSet(new DERPrintableString("3"));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            // TransactionId
            if (transactionId != null) {
                oid = new DERObjectIdentifier(ScepRequestMessage.id_transId);
                log.debug("Added transactionId: " + transactionId);
                value = new DERSet(new DERPrintableString(transactionId));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // status
            oid = new DERObjectIdentifier(ScepRequestMessage.id_pkiStatus);
            value = new DERSet(new DERPrintableString(status.getValue()));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            if (status.equals(ResponseStatus.FAILURE)) {
                oid = new DERObjectIdentifier(ScepRequestMessage.id_failInfo);
                log.debug("Added failInfo: " + failInfo.getValue());
                value = new DERSet(new DERPrintableString(failInfo.getValue()));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // senderNonce
            if (senderNonce != null) {
                oid = new DERObjectIdentifier(ScepRequestMessage.id_senderNonce);
                log.debug("Added senderNonce: " + senderNonce);
                value = new DERSet(new DEROctetString(Base64.decode(senderNonce.getBytes())));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // recipientNonce
            if (recipientNonce != null) {
                oid = new DERObjectIdentifier(ScepRequestMessage.id_recipientNonce);
                log.debug("Added recipientNonce: " + recipientNonce);
                value = new DERSet(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // Add our signer info and sign the message
            log.debug("Signing SCEP message with cert: "+CertTools.getSubjectDN(signCert));
            gen1.addSigner(signKey, (X509Certificate)signCert, digestAlg, new AttributeTable(attributes), null);
            signedData = gen1.generate(msg, true, provider);
            responseMessage = signedData.getEncoded();
            if (responseMessage != null) {
                ret = true;
            }
        } catch (InvalidAlgorithmParameterException e) {
            log.error("Error creating CertStore: ", e);
        } catch (CertStoreException e) {
            log.error("Error creating CertStore: ", e);
        } catch (CMSException e) {
            log.error("Error creating CMS message: ", e);
        }

        return ret;
    }

    /**
     * indicates if this message needs recipients public and private key to sign. If this returns
     * true, setSignKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo() {
        return true;
    }

    /**
     * indicates if this message needs recipients public and private key to encrypt. If this
     * returns true, setEncKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireEncKeyInfo() {
        return false;
    }

    /**
     * Sets the public and private key needed to sign the message. Must be set if
     * requireSignKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireSignKeyInfo()
     */
    public void setSignKeyInfo(Certificate cert, PrivateKey key, String prov) {
        this.signCert = cert;
        this.signKey = key;
        if (prov != null) {
        	this.provider = prov;
        }
    }

    /**
     * Sets the public and private key needed to encrypt the message. Must be set if
     * requireEncKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireEncKeyInfo()
     */
    public void setEncKeyInfo(Certificate cert, PrivateKey key, String provider) {
        // We don't need these.
    }

    /**
     * Sets a senderNonce if it should be present in the response
     *
     * @param senderNonce a string of base64 encoded bytes
     */
    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    /**
     * Sets a recipient if it should be present in the response
     *
     * @param recipientNonce a string of base64 encoded bytes
     */
    public void setRecipientNonce(String recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    /**
     * Sets a transaction identifier if it should be present in the response
     *
     * @param transactionId transaction id
     */
    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    /**
     * Sets recipient key info, key id or similar. This is the requestors self-signed cert from the request message.
     *
     * @param recipientKeyInfo key info
     */
    public void setRecipientKeyInfo(byte[] recipientKeyInfo) {
        this.recipientKeyInfo = recipientKeyInfo;
    }

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setPreferredDigestAlg(String digest) {
    	this.digestAlg = digest;
    }

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setRequestType(int reqtype) {
	}

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setRequestId(int reqid) {
    }

    /** @see org.ejca.core.protocol.IResponseMessage
     */
    public void setProtectionParamsFromRequest(IRequestMessage reqMsg) {
    }
}
