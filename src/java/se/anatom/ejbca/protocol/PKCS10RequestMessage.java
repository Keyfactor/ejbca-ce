package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Class to handle PKCS10 request messages sent to the CA.
 *
 * @version $Id: PKCS10RequestMessage.java,v 1.10 2003-02-17 11:39:22 scop Exp $
 */
public class PKCS10RequestMessage implements IRequestMessage, Serializable {

    private static Logger log = Logger.getLogger(PKCS10RequestMessage.class);

    /**
     * Raw form of the PKCS10 message
     */
    private byte[] msg;

    /**
     * The pkcs10 request message
     */
    private transient PKCS10CertificationRequest pkcs10 = null;

    /**
     * Constructs a new PKCS#10 message handler object.
     * @param msg The DER encoded PKCS#10 request.
     * @throws IOException if the request can not be parsed.
     */
    public PKCS10RequestMessage(byte[] msg) {
        log.debug(">PKCS10RequestMessage(byte[])");
        this.msg = msg;
        init();
        log.debug("<PKCS10RequestMessage(byte[])");
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     * @param p10 the PKCS#10 request
     */
    public PKCS10RequestMessage(PKCS10CertificationRequest p10)
    {
        log.debug(">PKCS10RequestMessage(PKCS10CertificationRequest)");
        msg = p10.getEncoded();
        pkcs10 = p10;
        log.debug("<PKCS10RequestMessage(PKCS10CertificationRequest)");
    }

    private void init() {
        pkcs10 = new PKCS10CertificationRequest(msg);
    }

    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            if (pkcs10 == null)
                init();
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");
            return null;
        }
        return pkcs10.getPublicKey();
    }

    /**
     * Gets the underlying BC <code>PKCS10CertificationRequest</code> object.
     * @return the request object
     */
    public PKCS10CertificationRequest getCertificationRequest()
    {
        if (pkcs10 == null) init();
        return pkcs10;
    }

    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        log.debug(">verify()");
        boolean ret = false;
        try {
            if (pkcs10 == null)
                init();
            ret = pkcs10.verify();
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");
        } catch (InvalidKeyException e) {
            log.error("Error in PKCS10-request:", e);
            throw e;
        } catch (SignatureException e) {
            log.error("Error in PKCS10-signature:", e);
        }
        log.debug("<verify()");
        return ret;
    }

    public boolean requireKeyInfo() {
        return false;
    }

    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
    }

} // PKCS10RequestMessage
