package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/** Class to handle PKCS10 request messages sent to the CA.
 *
 * @version $Id: PKCS10RequestMessage.java,v 1.4 2002-12-17 08:43:23 anatom Exp $
 */
public class PKCS10RequestMessage implements RequestMessage, Serializable {

    static private Category cat = Category.getInstance( PKCS10RequestMessage.class.getName() );

    /** Raw form of the PKCS10 message
     */
    private byte[] msg;
    /** The pkcs10 request message
     */
    private transient PKCS10CertificationRequest pkcs10 = null;

    /** Constucts a new PKCS10 message handler object.
     * @param msg The DER encoded PKCS10 request.
     * @throws IOException if the request can not be parsed.
     */
    public PKCS10RequestMessage(byte[] msg) throws IOException {
        cat.debug(">PKCS10RequestMessage");
        this.msg = msg;
        init();
        cat.debug("<PKCS10RequestMessage");
    }
    private void init() throws IOException {
        DERObject derobj = new DERInputStream(new ByteArrayInputStream(msg)).readObject();
        DERConstructedSequence seq = (DERConstructedSequence)derobj;
        pkcs10 = new PKCS10CertificationRequest(seq);
    }
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            if (pkcs10 == null)
                init();
        } catch (IOException e) {
            cat.error("PKCS10 not inited!");
            return null;
        }
        return pkcs10.getPublicKey();
      }

    public PKCS10CertificationRequest getCertificationRequest()
    {
        return pkcs10;
    }

    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        cat.debug(">verify()");
        boolean ret = false;
        try {
            if (pkcs10 == null)
                init();
            ret = pkcs10.verify();
        } catch (IOException e) {
            cat.error("PKCS10 not inited!");
        } catch (InvalidKeyException e) {
            cat.error("Error in PKCS10-request:", e);
            throw e;
        } catch (SignatureException e) {
            cat.error("Error in PKCS10-signature:", e);
        }
        cat.debug("<verify()");
        return ret;
    }

    public boolean requireKeyInfo() {
        return false;
      }
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
    }

} // PKCS10RequestMessage
