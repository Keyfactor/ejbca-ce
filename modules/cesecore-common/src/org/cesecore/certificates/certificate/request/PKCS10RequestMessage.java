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
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;

/**
 * <p>Class to handle PKCS10 request messages sent to the CA.
 * 
 * <p><b>Implementation note:</b> This class implements {@link Object#equals(Object)} and {@link Object#hashCode()}.
 * Make sure these methods are updated if any new members are added to this class.
 */
public class PKCS10RequestMessage implements RequestMessage {
    private static final long serialVersionUID = 3597275157018205137L;
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
    protected transient JcaPKCS10CertificationRequest pkcs10;

    /** Type of error */
    private int error = 0;

    /** Error text */
    private String errorText = null;

    private List<Certificate> additionalCaCertificates = new ArrayList<>();
    
    private List<Certificate> additionalExtraCertsCertificates = new ArrayList<>();

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (Objects.isNull(p10msg)) {
            return;
        }
        this.pkcs10 = new JcaPKCS10CertificationRequest(p10msg);
    }
    
    /**
     * Constructs a new empty PKCS#10 message handler object.
     */
    public PKCS10RequestMessage() {
    }

    /**
     * Constructs a new PKCS#10 message handler object.
     *
     * @param msg The DER encoded PKCS#10 request.
     */
    public PKCS10RequestMessage(byte[] msg) throws IOException {
    	if (log.isTraceEnabled()) {
    		log.trace(">PKCS10RequestMessage(byte[])");
    	}
        this.p10msg = msg;
        if (!Objects.isNull(p10msg)) {
            this.pkcs10 = new JcaPKCS10CertificationRequest(p10msg);
        }
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

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException {
        return Objects.isNull(pkcs10) ? null : pkcs10.getPublicKey();
    }
    @Override
    public SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo() {
        return Objects.isNull(pkcs10) ? null : pkcs10.getSubjectPublicKeyInfo();
    }

    @Override
    public void setPassword(String pwd) {
        this.password = pwd;
    }

    @Override
    public String getPassword() {
        if (password != null) {
            return password;
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
            	// Should be any DirectoryString according to RFC2985, preferably a PrintableString or UTF8String
                str = DirectoryString.getInstance((obj));
            } catch (IllegalArgumentException ie) {
                // This was not a DirectoryString type, it could then be IA5string, breaking pkcs#9 v2.0
                // but some version of openssl have been known to produce IA5strings
                str = ASN1IA5String.getInstance((obj));
            }

            if (str != null) {
                ret = str.getString();
            }
        }

        return ret;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public void setRequestValidityNotAfter(final Date notAfter) {
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
    public String getCASequence() {
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
        if (pkcs10 == null) {
            log.info("PKCS10 not inited getting requestX500Name, pkcs10 is null");
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
        if (pkcs10 == null) {
            log.info("PKCS10 not inited getting requestExtensions, pkcs10 is null");
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
        return pkcs10;
    }

    @Override
    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException {
        return verify(null);
    }

    public boolean verify(PublicKey pubKey) throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">verify()");
            }
            final ContentVerifierProvider verifierProvider;
            if (pubKey == null) {
                verifierProvider = CertTools.genContentVerifierProvider(pkcs10.getPublicKey());
            } else {
                verifierProvider = CertTools.genContentVerifierProvider(pubKey);
            }
            return pkcs10.isSignatureValid(verifierProvider);
        } catch (OperatorCreationException e) {
            log.error("Content verifier provider could not be created.", e);
            return false;
        } catch (PKCSException e) {
            log.error("Signature could not be processed.", e);
            return false;
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<verify()");
            }
        }
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
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
        // NOOP
    }

    @Override
    public List<Certificate> getAdditionalCaCertificates() {
        return additionalCaCertificates;
    }

    @Override
    public void setAdditionalCaCertificates(final List<Certificate> certificates) {
        this.additionalCaCertificates = certificates;
    }
    
    @Override
    public List<Certificate> getAdditionalExtraCertsCertificates() {
        return additionalExtraCertsCertificates;
    }

    @Override
    public void setAdditionalExtraCertsCertificates(List<Certificate> additionalExtraCertsCertificates) {
        this.additionalExtraCertsCertificates = additionalExtraCertsCertificates;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((additionalCaCertificates == null) ? 0 : additionalCaCertificates.hashCode());
        result = prime * result + ((additionalExtraCertsCertificates == null) ? 0 : additionalExtraCertsCertificates.hashCode());
        result = prime * result + error;
        result = prime * result + ((errorText == null) ? 0 : errorText.hashCode());
        result = prime * result + (includeCACert ? 1231 : 1237);
        result = prime * result + ((notAfter == null) ? 0 : notAfter.hashCode());
        result = prime * result + ((notBefore == null) ? 0 : notBefore.hashCode());
        result = prime * result + Arrays.hashCode(p10msg);
        result = prime * result + ((password == null) ? 0 : password.hashCode());
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PKCS10RequestMessage other = (PKCS10RequestMessage) obj;
        if (additionalCaCertificates == null) {
            if (other.additionalCaCertificates != null)
                return false;
        } else if (!additionalCaCertificates.equals(other.additionalCaCertificates))
            return false;
        if (additionalExtraCertsCertificates == null) {
            if (other.additionalExtraCertsCertificates != null)
                return false;
        } else if (!additionalExtraCertsCertificates.equals(other.additionalExtraCertsCertificates))
            return false;
        if (error != other.error)
            return false;
        if (errorText == null) {
            if (other.errorText != null)
                return false;
        } else if (!errorText.equals(other.errorText))
            return false;
        if (includeCACert != other.includeCACert)
            return false;
        if (notAfter == null) {
            if (other.notAfter != null)
                return false;
        } else if (!notAfter.equals(other.notAfter))
            return false;
        if (notBefore == null) {
            if (other.notBefore != null)
                return false;
        } else if (!notBefore.equals(other.notBefore))
            return false;
        if (!Arrays.equals(p10msg, other.p10msg))
            return false;
        if (password == null) {
            if (other.password != null)
                return false;
        } else if (!password.equals(other.password))
            return false;
        if (username == null) {
            if (other.username != null)
                return false;
        } else if (!username.equals(other.username))
            return false;
        return true;
    }

}
