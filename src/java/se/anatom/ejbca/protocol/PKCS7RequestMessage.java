package se.anatom.ejbca.protocol;

import org.apache.log4j.Logger;

import java.io.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/**
 * Class to handle PKCS7 request messages sent to the CA.
 *
 * @version $Id: PKCS7RequestMessage.java,v 1.9 2003-06-26 11:43:24 anatom Exp $
 */
public class PKCS7RequestMessage implements IRequestMessage, Serializable {
    private static Logger log = Logger.getLogger(PKCS7RequestMessage.class);

    /** Raw form of the PKCS7 message */
    private byte[] msg;

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
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean requireKeyInfo() {
        return false;
    }

    /**
     * DOCUMENT ME!
     *
     * @param cert DOCUMENT ME!
     * @param key DOCUMENT ME!
     */
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getErrorNo() {
        return error;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getErrorText() {
        return errorText;
    }
}
 // PKCS7RequestMessage
