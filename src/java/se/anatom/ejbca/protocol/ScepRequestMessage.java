package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.util.Base64;


/**
 * Class to handle SCEP request messages sent to the CA. TODO: don't forget extensions, e.g.
 * KeyUsage requested by end entity  TODO: extract senderNonce  TODO: extract transactionId
 *
 * @version $Id: ScepRequestMessage.java,v 1.26 2003-09-20 11:45:09 anatom Exp $
 */
public class ScepRequestMessage extends PKCS10RequestMessage implements IRequestMessage,
    Serializable {
    private static Logger log = Logger.getLogger(ScepRequestMessage.class);
    public static final String id_Verisign = "2.16.840.1.113733";
    public static final String id_pki = id_Verisign + ".1";
    public static final String id_attributes = id_pki + ".9";
    public static final String id_messageType = id_attributes + ".2";
    public static final String id_pkiStatus = id_attributes + ".3";
    public static final String id_failInfo = id_attributes + ".4";
    public static final String id_senderNonce = id_attributes + ".5";
    public static final String id_recipientNonce = id_attributes + ".6";
    public static final String id_transId = id_attributes + ".7";
    public static final String id_extensionReq = id_attributes + ".8";

    /** Raw form of the Scep message */
    private byte[] scepmsg;

    /**
     * The messageType attribute specify the type of operation performed by the transaction. This
     * attribute is required in all PKI messages. Currently, the following message types are
     * defined:  
     * PKCSReq (19)  -- Permits use of PKCS#10 certificate request  
     * CertRep (3)   -- Response to certificate or CRL request  
     * GetCertInitial (20)  -- Certificate polling in manual enrollment  
     * GetCert (21)  -- Retrieve a certificate  
     * GetCRL  (22)  -- Retrieve a CRL
     */
    private int messageType = 0;

    /**
     * SenderNonce in a request is used as recipientNonce when the server sends back a reply to the
     * client. This is base64 encoded bytes
     */
    private String senderNonce = null;

    /** transaction id */
    private String transactionId = null;

    /**
     * request key info, this is the requestors self-signed certificate used to identify the
     * senders public key
     */
    private byte[] requestKeyInfo = null;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    /** Signed data, the whole enchilada to to speak... */
    private transient SignedData sd = null;

    /** Enveloped data, carrying the 'beef' of the request */
    private transient EnvelopedData envData = null;

    /** Enveloped data, carrying the 'beef' of the request */
    private transient ContentInfo envEncData = null;

    /** Private key used for decryption. */
    private transient PrivateKey privateKey = null;

    /**
     * Constucts a new SCEP/PKCS7 message handler object.
     *
     * @param msg The DER encoded PKCS7 request.
     *
     * @throws IOException if the request can not be parsed.
     */
    public ScepRequestMessage(byte[] msg)
        throws IOException, InvalidKeyException, GeneralSecurityException, CMSException {
        log.debug(">ScepRequestMessage");
        this.scepmsg = msg;
        init();
        log.debug("<ScepRequestMessage");
    }

    private void init() throws IOException {
        log.debug(">init");

        //Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        //int result = Security.addProvider(BCJce);
        // Parse and verify the entegrity of the PKIOperation message PKCS#7

        /* If this would have been done using the newer CMS it would have made me so much happier... */
        ASN1Sequence seq = (ASN1Sequence) new DERInputStream(new ByteArrayInputStream(scepmsg)).readObject();
        ContentInfo ci = new ContentInfo(seq);
        String ctoid = ci.getContentType().getId();

        if (ctoid.equals(CMSObjectIdentifiers.signedData.getId())) {
            // This is SignedData so it is a pkcsCertReqSigned,
            //  pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
            // (could also be pkcsRepSigned or certOnly, but we don't receive them on the server side
            // Try to find out what kind of message this is
            sd = new SignedData((ASN1Sequence) ci.getContent());

            // Get self signed cert to identify the senders public key
            ASN1Set certs = sd.getCertificates();

            if (certs.size() > 0) {
                // There should be only one...
                DEREncodable dercert = certs.getObjectAt(0);

                if (dercert != null) {
                    // Requestors self-signed certificate is requestKeyInfo
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    DEROutputStream dOut = new DEROutputStream(bOut);
                    dOut.writeObject(dercert);

                    if (bOut.size() > 0) {
                        requestKeyInfo = bOut.toByteArray();
                    }
                }
            }

            Enumeration sis = sd.getSignerInfos().getObjects();

            if (sis.hasMoreElements()) {
                SignerInfo si = new SignerInfo((ASN1Sequence) sis.nextElement());
                Enumeration attr = si.getAuthenticatedAttributes().getObjects();

                while (attr.hasMoreElements()) {
                    Attribute a = new Attribute((ASN1Sequence) attr.nextElement());

                    log.debug("Found attribute: " + a.getAttrType().getId());

                    if (a.getAttrType().getId().equals(id_senderNonce)) {
                        Enumeration values = a.getAttrValues().getObjects();
                        ASN1OctetString str = ASN1OctetString.getInstance(values.nextElement());
                        senderNonce = new String(Base64.encode(str.getOctets(), false));
                        log.debug("senderNonce = " + senderNonce);
                    }

                    if (a.getAttrType().getId().equals(id_transId)) {
                        Enumeration values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        transactionId = str.getString();
                        log.debug("transactionId = " + transactionId);
                    }

                    if (a.getAttrType().getId().equals(id_messageType)) {
                        Enumeration values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        messageType = Integer.parseInt(str.getString());
                        log.debug("messagetype = " + messageType);
                    }
                }
            }

            // If this is a PKCSReq
            if (messageType == 19) {
                // Extract the contents, which is an encrypted PKCS10
                ci = sd.getEncapContentInfo();
                ctoid = ci.getContentType().getId();

                if (ctoid.equals(CMSObjectIdentifiers.data.getId())) {
                    DEROctetString content = (DEROctetString) ci.getContent();
                    log.debug("envelopedData is " + content.getOctets().length + " bytes.");

                    ASN1Sequence seq1 = (ASN1Sequence) new DERInputStream(new ByteArrayInputStream(
                                content.getOctets())).readObject();
                    envEncData = new ContentInfo(seq1);
                    ctoid = envEncData.getContentType().getId();

                    if (ctoid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
                        envData = new EnvelopedData((ASN1Sequence) envEncData.getContent());
                    } else {
                        errorText = "EncapsulatedContentInfo does not contain PKCS7 envelopedData: ";
                        log.error(errorText + ctoid);
                        error = 2;
                    }
                } else {
                    errorText = "EncapsulatedContentInfo is not of type 'data': ";
                    log.error(errorText + ctoid);
                    error = 3;
                }
            } else {
                errorText = "This is not a certification request!";
                log.error(errorText);
                error = 4;
            }
        } else {
            errorText = "PKCSReq does not contain 'signedData': ";
            log.error(errorText + ctoid);
            error = 1;
        }

        log.debug("<init");
    }

    // init
    private void decrypt()
        throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, 
            CMSException, NoSuchProviderException, BadPaddingException, 
            InvalidAlgorithmParameterException, GeneralSecurityException, IOException {
        log.debug(">decrypt");

        // Now we are getting somewhere (pheew),
        // Now we just have to get the damn key...to decrypt the PKCS10
        if (privateKey == null) {
            errorText = "Need private key to decrypt!";
            error = 5;
            log.error(errorText);

            return;
        }

        if (envEncData == null) {
            errorText = "No enveloped data to decrypt!";
            error = 6;
            log.error(errorText);

            return;
        }

        CMSEnvelopedData ed = new CMSEnvelopedData(envEncData);
        RecipientInformationStore recipients = ed.getRecipientInfos();
        Collection c = recipients.getRecipients();
        Iterator it = c.iterator();
        byte[] pkcs10Bytes = null;

        while (it.hasNext()) {
            RecipientInformation recipient = (RecipientInformation) it.next();
            pkcs10Bytes = recipient.getContent(privateKey, "BC");

            break;
        }

        DERObject derobj = new DERInputStream(new ByteArrayInputStream(pkcs10Bytes)).readObject();
        ASN1Sequence seq = (ASN1Sequence) derobj;
        pkcs10 = new PKCS10CertificationRequest(seq);
        log.debug("Successfully extracted PKCS10.");
        log.debug("<decrypt");
    }

    // decrypt

    /**
     * Returns the public key from the certificattion request.
     *
     * @return public key from certification request.
     */
    public PublicKey getRequestPublicKey() {
        log.debug(">getRequestPublicKey()");

        PublicKey ret = null;

        try {
            if (envData == null) {
                init();
                decrypt();
            }

            ret = super.getRequestPublicKey();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");

            return null;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);

            return null;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);

            return null;
        }

        log.debug("<getRequestPublicKey()");

        return ret;
    }

    /**
     * Verifies signatures, popo etc on the request message. If verification fails the request
     * should be considered invalid.
     *
     * @return True if verification was successful, false if it failed.
     *
     * @throws InvalidKeyException If the key used for verification is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     */
    public boolean verify() {
        log.debug(">verify()");

        boolean ret = false;

        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }

            ret = super.verify();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");

            return false;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);

            return false;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);

            return false;
        }

        log.debug("<verify()");

        return ret;
    }

    /**
     * Returns the challenge password from the certificattion request.
     *
     * @return challenge password from certification request.
     */
    public String getPassword() {
        log.debug(">getPassword()");

        String ret = null;

        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }

            ret = super.getPassword();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");

            return null;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);

            return null;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);

            return null;
        }

        log.debug("<getPassword()");

        return ret;
    }

    /**
     * Returns the string representation of the CN field from the DN of the certification request,
     * to be used as username.
     *
     * @return username, which is the CN field from the subject DN in certification request.
     */
    public String getUsername() {
        String ret = null;

        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }

            ret = super.getUsername();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");

            return null;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);

            return null;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);

            return null;
        }

        return ret;
    }

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    public String getIssuerDN() {
        // TODO:
        return null;
    }

    /**
     * Returns the string representation of the subject DN from the certification request.
     *
     * @return subject DN from certification request.
     */
    public String getRequestDN() {
        log.debug(">getRequestDN()");

        String ret = null;

        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }

            ret = super.getRequestDN();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");

            return null;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);

            return null;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);

            return null;
        }

        log.debug("<getRequestDN()");

        return ret;
    }

    /**
     * indicates if this message needs recipients public and private key to verify, decrypt etc. If
     * this returns true, setKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireKeyInfo() {
        return true;
    }

    /**
     * Sets the public and private key needed to decrypt/verify the message. Must be set if
     * requireKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     *
     * @see #requireKeyInfo()
     */
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
        // We don't need the public key 
        // this.cert = cert;
        this.privateKey = key;
    }

    /**
     * Returns an error number after an error has occured processing the request
     *
     * @return class specific error number
     */
    public int getErrorNo() {
        return error;
    }

    /**
     * Returns an error message after an error has occured processing the request
     *
     * @return class specific error message
     */
    public String getErrorText() {
        return errorText;
    }

    /**
     * Returns a senderNonce if present in the request
     *
     * @return senderNonce as a string of base64 encoded bytes
     */
    public String getSenderNonce() {
        return senderNonce;
    }

    /**
     * Returns a transaction identifier if present in the request
     *
     * @return transaction id
     */
    public String getTransactionId() {
        return transactionId;
    }

    /**
     * Returns requesters key info, key id or similar
     *
     * @return request key info
     */
    public byte[] getRequestKeyInfo() {
        return requestKeyInfo;
    }

    //
    // Private helper methods
    //
    private static boolean checkKeys(PublicKey pubK, PrivateKey privK) {
        String in = "TheTopSecretTestString";
        byte[] text = in.getBytes();

        try {
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
            cipher1.init(Cipher.ENCRYPT_MODE, pubK);

            byte[] textout = cipher1.doFinal(text);
            Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
            cipher2.init(Cipher.DECRYPT_MODE, privK);

            byte[] out = cipher2.doFinal(textout);
            log.debug("out=" + new String(out));

            return in.equals(new String(out));
        } catch (Exception e) {
            return false;
        }
    }
}


// ScepRequestMessage
