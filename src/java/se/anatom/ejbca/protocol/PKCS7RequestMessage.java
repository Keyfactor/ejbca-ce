package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.*;

/** Class to handle PKCS7 request messages sent to the CA.
 *
* @version  $Id: PKCS7RequestMessage.java,v 1.5 2003-01-12 17:24:01 anatom Exp $
 */
public class PKCS7RequestMessage implements IRequestMessage, Serializable {

    static private Category cat = Category.getInstance( PKCS7RequestMessage.class.getName() );

    /** Raw form of the PKCS7 message
     */
    private byte[] msg;


    /** Constucts a new PKCS7 message handler object.
     * @param msg The DER encoded PKCS7 request.
     * @throws IOException if the request can not be parsed.
     */
    public PKCS7RequestMessage(byte[] msg) throws IOException {
        cat.debug(">PKCS7RequestMessage");
        this.msg = msg;
        init();
        cat.debug("<PKCS7RequestMessage");
    }

    private void init() throws IOException {
        // Parse and verify the entegrity of the PKCS#7 message
        //TODO:
    }

    public PublicKey getRequestPublicKey() {
        cat.debug(">getRequestPublicKey()");
        cat.debug("<getRequestPublicKey()");
        return null;
    }

    public boolean verify() {
        cat.debug(">verify()");
        cat.debug("<verify()");
        return false;
    }

    public boolean requireKeyInfo() {
        return false;
    }
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
    }

} // PKCS7RequestMessage
