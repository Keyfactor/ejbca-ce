package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;


/**
 * Class to handle PKCS7 request messages sent to the CA.
 *
 * @version $Id: PKCS7RequestMessage.java,v 1.14 2003-09-08 19:02:40 anatom Exp $
 */
public class PKCS7RequestMessage implements IRequestMessage, Serializable {
    private static Logger log = Logger.getLogger(PKCS7RequestMessage.class);

    /** Raw form of the PKCS7 message */
    private byte[] msg;

    /**
     * SenderNonce in a request is used as recipientNonce when the server sends back a reply to the
     * client
     */
    private String senderNonce = null;

    /** transaction id */
    private String transactionId = null;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    /**
     * Constucts a new PKCS7 message handler object.
     *
     * @param msg The DER encoded PKCS7 request.
     *
     * @throws IOException if the request can not be parsed.
     */
    public PKCS7RequestMessage(byte[] msg) throws IOException {
        log.debug(">PKCS7RequestMessage");
        this.msg = msg;
        init();
        log.debug("<PKCS7RequestMessage");
    }

    private void init() throws IOException {
        // Parse and verify the entegrity of the PKCS#7 message
        //TODO: make pkcs7 implementation
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public PublicKey getRequestPublicKey() {
        log.debug(">getRequestPublicKey()");
        log.debug("<getRequestPublicKey()");

        return null;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean verify() {
        log.debug(">verify()");
        log.debug("<verify()");

        return false;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername() {
        return null;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getPassword() {
        return null;
    }

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    public String getIssuerDN() {
        return null;
    }

    /**
     * indicates if this message needs recipients public and private key to verify, decrypt etc. If
     * this returns true, setKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireKeyInfo() {
        return false;
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
     * @return senderNonce
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
        return null;
    }
}


// PKCS7RequestMessage
