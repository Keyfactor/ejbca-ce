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
import java.math.BigInteger;
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
 * @version $Id: PKCS10RequestMessage.java,v 1.27 2005-04-05 07:28:08 anatom Exp $
 */
public class PKCS10RequestMessage implements IRequestMessage, Serializable {
    static final long serialVersionUID = 3597275157018205136L;

    private static Logger log = Logger.getLogger(PKCS10RequestMessage.class);

    /** Raw form of the PKCS10 message */
    protected byte[] p10msg;

    /** manually set password */
    protected String password = null;

    /** manually set username */
    protected String username = null;

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

    /** force a password, i.e. ignore the challenge password in the request
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    /**
     * Returns the challenge password from the certificattion request.
     *
     * @return challenge password from certification request.
     */
    public String getPassword() {
        if (password != null)
            return password;
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

    /** force a username, i.e. ignore the DN/username in the request
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the string representation of the CN field from the DN of the certification request,
     * to be used as username.
     *
     * @return username, which is the CN field from the subject DN in certification request.
     */
    public String getUsername() {
        if (username != null)
            return username;
        String name = CertTools.getPartFromDN(getRequestDN(), "CN");
        // Special if the DN contains unstructiredAddress where it becomes: 
        // CN=pix.primekey.se + 1.2.840.113549.1.9.2=pix.primekey.se
        // We only want the CN and not the oid-part.
        String ret = name;
        if (name != null) {
            int index = name.indexOf(' ');
            if (index > 0) {
                ret = name.substring(0, index);
            }            
        }
        log.debug("UserName='" + ret + "'");
        return ret;
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
     * Gets the issuer DN (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return issuerDN of CA issuing CRL.
     */
    public String getCRLIssuerDN() {
        return null;
    }

    /**
     * Gets the number (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return serial number of CA certificate for CA issuing CRL.
     */
    public BigInteger getCRLSerialNo() {
        return null;
    }

    /**
     * Returns the string representation of the subject DN from the certification request.
     *
     * @return subject DN from certification request or null.
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
        return null;
    }

    /**
     * Returns a transaction identifier if present in the request
     *
     * @return transaction id
     */
    public String getTransactionId() {
        return null;
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

// PKCS10RequestMessage
