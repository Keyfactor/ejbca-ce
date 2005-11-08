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

package se.anatom.ejbca.protocol;

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
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;

import java.io.IOException;
import java.io.Serializable;
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

/**
 * A response message for scep (pkcs7).
 *
 * @version $Id: ScepResponseMessage.java,v 1.27 2005-11-08 19:04:41 anatom Exp $
 */
public class ScepResponseMessage implements IResponseMessage, Serializable {
    static final long serialVersionUID = 2016710353393853878L;

    private static Logger log = Logger.getLogger(ScepResponseMessage.class);

    /** The encoded response message */
    private byte[] responseMessage = null;

    /** status for the response */
    private ResponseStatus status = ResponseStatus.SUCCESS;

    /** Possible fail information in the response. Defaults to 'badRequest (2)'. */
    private FailInfo failInfo = FailInfo.BAD_REQUEST;

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
    private transient X509Certificate signCert = null;
    private transient PrivateKey signKey = null;
    /** If the CA certificate should be included in the reponse or not, default to true = yes */
    private transient boolean includeCACert = true;

    /** Default digest algorithm for SCEP response message, can be overridden */
    private transient String digestAlg = CMSSignedDataGenerator.DIGEST_MD5;
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

    /** @see se.anatom.ejbca.protocol.IResponseMessage#setIncludeCACert
     * 
     */
    public void setIncludeCACert(boolean incCACert) {
    	this.includeCACert = incCACert;
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
     *
     * @see #setSignKeyInfo
     * @see #setEncKeyInfo
     */
    public boolean create()
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean ret = false;

        try {

            if (status.equals(ResponseStatus.SUCCESS)) {
                log.debug("Creating a STATUS_OK message.");
            } else {
                log.debug("Creating a STATUS_FAILED message.");
            }

            CMSProcessable msg;
            // The signed data to be enveloped
            CMSSignedData s = null;
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
                        certList.add(signCert);                    	
                    }
                }
                CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

                // Create the signed CMS message to be contained inside the envelope
                // this message does not contain any message, and no signerInfo
                CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                gen.addCertificatesAndCRLs(certs);
                s = gen.generate(null, false, "BC");

                // Envelope the CMS message
                if (recipientKeyInfo != null) {
                    try {
                        X509Certificate rec = CertTools.getCertfromByteArray(recipientKeyInfo);
                        log.debug("Added recipient information - issuer: '" + CertTools.getIssuerDN(rec) + "', serno: '" + rec.getSerialNumber().toString(16));
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
                msg = new CMSProcessableByteArray("PrimeKey".getBytes());
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
            gen1.addSigner(signKey, signCert, digestAlg,
                    new AttributeTable(attributes), null);
            signedData = gen1.generate(msg, true, "BC");
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
     *
     * @see #requireSignKeyInfo()
     */
    public void setSignKeyInfo(X509Certificate cert, PrivateKey key) {
        signCert = cert;
        signKey = key;
    }

    /**
     * Sets the public and private key needed to encrypt the message. Must be set if
     * requireEncKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     *
     * @see #requireEncKeyInfo()
     */
    public void setEncKeyInfo(X509Certificate cert, PrivateKey key) {
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

    /** @see se.anatom.ejca.protocol.IResponseMessage
     */
    public void setPreferredDigestAlg(String digest) {
    	this.digestAlg = digest;
    }

}
