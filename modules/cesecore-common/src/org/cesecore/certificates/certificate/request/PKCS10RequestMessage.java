/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.request;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;

/**
 * Class to handle PKCS10 request messages sent to the CA.
 *
 * @version $Id$
 */
public class PKCS10RequestMessage implements RequestMessage {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 3597275157018205137L;

    private static final Logger log = Logger.getLogger(PKCS10RequestMessage.class);

    /** Raw form of the PKCS10 message */
    protected byte[] p10msg;

    /** manually set password */
    protected String password = null;

    /** manually set username */
    protected String username = null;

    protected Date notAfter = null;
    protected Date notBefore = null;

    /** If the CA certificate should be included in the response or not, default to true = yes */
    protected boolean includeCACert = true;

    /** preferred digest algorithm to use in replies, if applicable */
    private transient String preferredDigestAlg = CMSSignedGenerator.DIGEST_SHA1;

    /** The pkcs10 request message, not serialized. */
    protected transient JcaPKCS10CertificationRequest pkcs10 = null;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    /** Private key used for signing/encrypting response, if needed */
    private PrivateKey responsePrivateKey;
    /** Security provider used for the responsePrivateKey */
    private String responseProvider = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * Constructs a new empty PKCS#10 message handler object.
     */
    public PKCS10RequestMessage() {
    	// No constructor
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     *
     * @param msg The DER encoded PKCS#10 request.
     * @throws IOException
     */
    public PKCS10RequestMessage(byte[] msg) {
    	if (log.isTraceEnabled()) {
    		log.trace(">PKCS10RequestMessage(byte[])");
    	}
        this.p10msg = msg;
        init();
    	if (log.isTraceEnabled()) {
    		log.trace("<PKCS10RequestMessage(byte[])");
    	}
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     *
     * @param p10 the PKCS#10 request
     * @throws IOException
     */
    public PKCS10RequestMessage(JcaPKCS10CertificationRequest p10) throws IOException {
    	if (log.isTraceEnabled()) {
    		log.trace(">PKCS10RequestMessage(ExtendedPKCS10CertificationRequest)");
    	}
        p10msg = p10.getEncoded();
        pkcs10 = p10;
    	if (log.isTraceEnabled()) {
    		log.trace("<PKCS10RequestMessage(ExtendedPKCS10CertificationRequest)");
    	}
    }

    private void init() {
        if(p10msg == null) {
            throw new NullPointerException("Cannot initiate with p10msg == null");
        }
        try {
            pkcs10 = new JcaPKCS10CertificationRequest(p10msg);
        } catch (IOException e) {
            log.warn("PKCS10 not initiated! "+e.getMessage());
        }
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException {
        if (pkcs10 == null) {
            if (p10msg != null) {
                init();
            } else {
                return null;
            }
        }
        return pkcs10.getPublicKey();
    }

    /**
     * force a password, i.e. ignore the challenge password in the request
     */
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    @Override
    public String getPassword() {
        if (password != null) {
            return password;
        }
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (NullPointerException e) {
            log.error("PKCS10 not initated! "+e.getMessage());
            return null;
        }

        String ret = null;
        Attribute[] attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        ASN1Encodable obj = null;
        if (attributes.length == 0) {
            // See if we have it embedded in an extension request instead
            attributes = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attributes.length == 0) {
                return null;
            }
            if (log.isDebugEnabled()) {
            	log.debug("got extension request");
            }
            ASN1Set values = attributes[0].getAttrValues();
            if (values.size() == 0) {
                return null;
            }
            Extensions exts = Extensions.getInstance(values.getObjectAt(0));
            Extension ext = exts.getExtension(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (ext == null) {
                if (log.isDebugEnabled()) {
                	log.debug("no challenge password extension");
                }
                return null;
            }
            obj = ext.getExtnValue();
        } else {
            // If it is a challengePassword directly, it's just to grab the value
            ASN1Set values = attributes[0].getAttrValues();
            obj = values.getObjectAt(0);
        }

        if (obj != null) {
            ASN1String str = null;

            try {
                str = DERPrintableString.getInstance((obj));
            } catch (IllegalArgumentException ie) {
                // This was not printable string, should be utf8string then according to pkcs#9 v2.0
                str = DERUTF8String.getInstance((obj));
            }

            if (str != null) {
                ret = str.getString();
            }
        }

        return ret;
    }

    /**
     * force a username, i.e. ignore the DN/username in the request
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Set the date after which the private key no longer will be valid, or null to
     * use the default validity specified in the certificate profile. The value
     * specified here will only be considered if user-defined validity dates are
     * allowed by the certificate profile, e.g. if Validity override" is enabled.
     */
    public void setNotAfter(final Date notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public String getUsername() {
        if (username != null) {
            return username;
        }
        // Special if the DN contains unstructuredAddress where it becomes:
        // CN=pix.primekey.com + unstructuredAddress=pix.primekey.com
        // We only want the CN and not the oid-part.
        // Luckily for us this is handles automatically by BC X500Name class
        X500Name xname = getRequestX500Name();
        String ret = null;
        if (xname == null) {
        	log.info("No requestDN in request, probably we could not read/parse/decrypt request.");
        } else {
            RDN[] cnValues = xname.getRDNs(CeSecoreNameStyle.CN);
            if (cnValues.length == 0) {
            	log.info("No CN in DN: "+xname.toString());
            } else {
                AttributeTypeAndValue[] tavs = cnValues[0].getTypesAndValues();
                for(AttributeTypeAndValue tav : tavs) {
                    if(tav.getType().equals(CeSecoreNameStyle.CN)) {
                        ret = tav.getValue().toString();
                        break;
                    }
                }
                // If we have a CN with a normal name like "Test Testsson" we only want to
                // use the first part as the username
            	int index = ret.indexOf(' ');
            	if (index > 0) {
            		ret = ret.substring(0, index);
            	}
            }
        }
        if (log.isDebugEnabled()) {
        	log.debug("UserName='" + ret + "'");
        }
        return ret;
    }

    @Override
    public String getIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getSerialNo() {
    	return null;
    }

    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    @Override
    public String getRequestDN() {
    	String ret = null;
    	X500Name name = getRequestX500Name();
    	if (name != null) {
    		String dn = name.toString();
    		// We have to make special handling again for Cisco devices.
    		// they will submit requests like: SN=FFFFFF+unstructuredName=Router
    		// EJBCA does not handle this very well so we will change it to: SN=FFFFFF,unstructuredName=Router
    		dn = dn.replace("+unstructuredName=", ",unstructuredName=");
    		dn = dn.replace(" + unstructuredName=", ",unstructuredName=");
    		dn = dn.replace("+unstructuredAddress=", ",unstructuredAddress=");
    		dn = dn.replace(" + unstructuredAddress=", ",unstructuredAddress=");
    		ret = dn;
    	}
        if (log.isDebugEnabled()) {
        	log.debug("getRequestDN: "+ret);
        }
        return ret;
    }

    @Override
    public X500Name getRequestX500Name() {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (NullPointerException e) {
            log.error("PKCS10 not inited: "+e.getMessage());
            return null;
        }
        return X500Name.getInstance(new CeSecoreNameStyle(), pkcs10.getSubject());
    }

    @Override
    public String getRequestAltNames() {
        String ret = null;
        try {
        	Extensions exts = getRequestExtensions();
        	if (exts != null) {
        		Extension ext = exts.getExtension(Extension.subjectAlternativeName);
                if (ext != null) {
                    // Finally read the value
            		ret = CertTools.getAltNameStringFromExtension(ext);
                } else {
                    if (log.isDebugEnabled()) {
                    	log.debug("no subject altName extension");
                    }
                }
        	}
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
            	log.debug("pkcs_9_extensionRequest does not contain Extensions that it should, ignoring invalid encoded extension request.");
            }
        }
        return ret;
    }

    @Override
	public Date getRequestValidityNotBefore() {
        return notBefore;
	}

    @Override
	public Date getRequestValidityNotAfter() {
        return notAfter;
	}

    @Override
	public Extensions getRequestExtensions() {
        try {
            if (pkcs10 == null) {
                init();
            }
        } catch (NullPointerException e) {
            log.error("PKCS10 not inited! "+e.getMessage());
            return null;
        }
        Extensions ret = null;

        // Get attributes
        // The X509 extension is in a a pkcs_9_at_extensionRequest

        // See if we have it embedded in an extension request instead
        Attribute[] attr = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attr.length != 0) {
            if (log.isDebugEnabled()) {
                log.debug("got request extension");
            }
            ASN1Set values = attr[0].getAttrValues();
            if (values.size() > 0) {
                try {
                    ret = Extensions.getInstance(values.getObjectAt(0));
                } catch (IllegalArgumentException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("pkcs_9_extensionRequest does not contain Extensions that it should, ignoring invalid encoded extension request.");
                    }
                }
            }
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
        } catch (NullPointerException e) {
            log.error("PKCS10 not inited! "+e.getMessage());
            return null;
        }

        return pkcs10;
    }

    @Override
    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException {
        return verify(null);
    }

    public boolean verify(PublicKey pubKey) throws InvalidKeyException, NoSuchAlgorithmException {
    	if (log.isTraceEnabled()) {
    		log.trace(">verify()");
    	}
    	 if (pkcs10 == null) {
             init();
         }

        ContentVerifierProvider verifierProvider;
        try {
            if (pubKey == null) {
                verifierProvider = CertTools.genContentVerifierProvider(pkcs10.getPublicKey());
            } else {
                verifierProvider = CertTools.genContentVerifierProvider(pubKey);
            }
            try {
                return pkcs10.isSignatureValid(verifierProvider);
            } catch (PKCSException e) {
                log.error("Signature could not be processed.", e);
            }
        } catch (OperatorCreationException e) {
            log.error("Content verifier provider could not be created.", e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<verify()");
            }
        }
        return false;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String Provider) {
    }

    @Override
    public int getErrorNo() {
        return error;
    }

    @Override
    public String getErrorText() {
        return errorText;
    }

    @Override
    public String getSenderNonce() {
        return null;
    }

    @Override
    public String getTransactionId() {
        return null;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return null;
    }

    @Override
    public String getPreferredDigestAlg() {
    	return preferredDigestAlg;
    }

    @Override
    public boolean includeCACert() {
    	return includeCACert;
    }

    @Override
    public int getRequestType() {
    	return 0;
    }

    @Override
    public int getRequestId() {
    	return 0;
    }

    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {
        this.responsePrivateKey = key;
        if (provider != null) {
            this.responseProvider = provider;
        }
    }

}
