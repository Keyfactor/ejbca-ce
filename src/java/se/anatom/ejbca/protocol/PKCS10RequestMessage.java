package se.anatom.ejbca.protocol;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Name;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.util.CertTools;

import java.io.Serializable;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;


/**
 * Class to handle PKCS10 request messages sent to the CA.
 *
 * @version $Id: PKCS10RequestMessage.java,v 1.15 2003-06-26 11:43:24 anatom Exp $
 */
public class PKCS10RequestMessage implements IRequestMessage, Serializable {
    private static Logger log = Logger.getLogger(PKCS10RequestMessage.class);

    /** Raw form of the PKCS10 message */
    protected byte[] p10msg;

    /** The pkcs10 request message, not serialized. */
    protected transient PKCS10CertificationRequest pkcs10 = null;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    /**
     * Constructs a new empty PKCS#10 message handler object.
     *
     * @throws IOException if the request can not be parsed.
     */
    public PKCS10RequestMessage() {
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     *
     * @param msg The DER encoded PKCS#10 request.
     *
     * @throws IOException if the request can not be parsed.
     */
    public PKCS10RequestMessage(byte[] msg) {
        log.debug(">PKCS10RequestMessage(byte[])");
        this.p10msg = msg;
        init();
        log.debug("<PKCS10RequestMessage(byte[])");
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     *
     * @param p10 the PKCS#10 request
     */
    public PKCS10RequestMessage(PKCS10CertificationRequest p10) {
        log.debug(">PKCS10RequestMessage(PKCS10CertificationRequest)");
        p10msg = p10.getEncoded();
        pkcs10 = p10;
        log.debug("<PKCS10RequestMessage(PKCS10CertificationRequest)");
    }

    private void init() {
        pkcs10 = new PKCS10CertificationRequest(p10msg);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws InvalidKeyException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     * @throws NoSuchProviderException DOCUMENT ME!
     */
    public PublicKey getRequestPublicKey()
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");

            return null;
        }

        return pkcs10.getPublicKey();
    }

    /**
     * Returns the challenge password from the certificattion request.
     *
     * @return challenge password from certification request.
     */
    public String getPassword() {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");

            return null;
        }

        String ret = null;

        // Get attributes
        CertificationRequestInfo info = pkcs10.getCertificationRequestInfo();
        AttributeTable attributes = new AttributeTable(info.getAttributes());
        Attribute attr = attributes.get(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        ASN1Set values = attr.getAttrValues();

        if (values.size() > 0) {
            DERString str = null;

            try {
                str = DERPrintableString.getInstance((values.getObjectAt(0)));
            } catch (IllegalArgumentException ie) {
                // This was not printable string, should be utf8string then according to pkcs#9 v2.0
                str = DERUTF8String.getInstance((values.getObjectAt(0)));
            }

            if (str != null) {
                ret = str.getString();
            }
        }

        return ret;
    }

    /**
     * Returns the string representation of the CN field from the DN of the certification request,
     * to be used as username.
     *
     * @return username, which is the CN field from the subject DN in certification request.
     */
    public String getUsername() {
        return CertTools.getPartFromDN(getRequestDN(), "CN");
    }

    /**
     * Returns the string representation of the subject DN from the certification request.
     *
     * @return subject DN from certification request.
     */
    public String getRequestDN() {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");

            return null;
        }

        String ret = null;

        // Get subject name from request
        CertificationRequestInfo info = pkcs10.getCertificationRequestInfo();

        if (info != null) {
            X509Name name = info.getSubject();
            ret = name.toString();
        }

        return ret;
    }

    /**
     * Gets the underlying BC <code>PKCS10CertificationRequest</code> object.
     *
     * @return the request object
     */
    public PKCS10CertificationRequest getCertificationRequest() {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (IllegalArgumentException e) {
            log.error("PKCS10 not inited!");

            return null;
        }

        return pkcs10;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws InvalidKeyException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     * @throws NoSuchProviderException DOCUMENT ME!
     */
    public boolean verify()
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        log.debug(">verify()");

        boolean ret = false;

        try {
            if (pkcs10 == null) {
                init();
            }

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
 // PKCS10RequestMessage
