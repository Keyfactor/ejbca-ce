package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.RespID;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.NotSupportedException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.util.CertTools;

public class OCSPUtil {

	private static final Logger m_log = Logger.getLogger(OCSPUtil.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();


    public static BasicOCSPRespGenerator createOCSPResponse(OCSPReq req, X509Certificate respondercert) throws OCSPException, NotSupportedException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        BasicOCSPRespGenerator res = new BasicOCSPRespGenerator(respondercert.getPublicKey());
        X509Extensions reqexts = req.getRequestExtensions();
        if (reqexts != null) {
        	X509Extension ext = reqexts.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            if (null != ext) {
                //m_log.debug("Found extension AcceptableResponses");
                ASN1OctetString oct = ext.getValue();
                try {
                    ASN1Sequence seq = ASN1Sequence.getInstance(new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
                    Enumeration en = seq.getObjects();
                    boolean supportsResponseType = false;
                    while (en.hasMoreElements()) {
                        DERObjectIdentifier oid = (DERObjectIdentifier) en.nextElement();
                        //m_log.debug("Found oid: "+oid.getId());
                        if (oid.equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                            // This is the response type we support, so we are happy! Break the loop.
                            supportsResponseType = true;
                            m_log.debug("Response type supported: " + oid.getId());
                            continue;
                        }
                    }
                    if (!supportsResponseType) {
                        throw new NotSupportedException("Required response type not supported, this responder only supports id-pkix-ocsp-basic.");
                    }
                } catch (IOException e) {
                }
            }
        }
        return res;
    }
    
    public static BasicOCSPResp generateBasicOCSPResp(OCSPCAServiceRequest serviceReq, String sigAlg, X509Certificate signerCert, PrivateKey signerKey, String provider, X509Certificate[] chain) 
    throws NotSupportedException, OCSPException, NoSuchProviderException, IllegalArgumentException {
    	BasicOCSPResp returnval = null;
    	BasicOCSPRespGenerator basicRes = null;
    	basicRes = OCSPUtil.createOCSPResponse(serviceReq.getOCSPrequest(), signerCert);
    	ArrayList responses = serviceReq.getResponseList();
    	if (responses != null) {
    		Iterator iter = responses.iterator();
    		while (iter.hasNext()) {
        		OCSPResponseItem item = (OCSPResponseItem)iter.next();
            	basicRes.addResponse(item.getCertID(), item.getCertStatus());    			
    		}
    	}
    	X509Extensions exts = serviceReq.getExtensions();
    	if (exts != null) {
    		Enumeration oids = exts.oids();
    		if (oids.hasMoreElements()) {
    	    	basicRes.setResponseExtensions(exts);    			
    		}
    	}

    	returnval = basicRes.generate(sigAlg, signerKey, chain, new Date(), provider );
    	if (m_log.isDebugEnabled()) {
    		m_log.debug("Signing OCSP response with OCSP signer cert: " + signerCert.getSubjectDN().getName());
    		RespID respId = new RespID(signerCert.getPublicKey());
    		if (!returnval.getResponderId().equals(respId)) {
    			m_log.error("Response responderId does not match signer certificate responderId!");
    		}
    		boolean verify = returnval.verify(signerCert.getPublicKey(), "BC");
    		if (verify) {
        		m_log.debug("The OCSP response is verifying.");
    		} else {
    			m_log.error("The response is NOT verifying!");
    		}
    	}
    	return returnval;
    }
    
    /**
     * Returns a signing algorithm to use selecting from a list of possible algorithms.
     * 
     * @param sigalgs the list of possible algorithms, ;-separated. Example "SHA1WithRSA;SHA1WithECDSA".
     * @param pk public key of signer, so we can choose between RSA and ECDSA algorithms
     * @return A singe algorithm to use Example: SHA1WithRSA or SHA1WithECDSA
     */
    public static String getSigningAlgFromAlgSelection(String sigalgs, PublicKey pk) {
    	String sigAlg = null;
        String[] algs = StringUtils.split(sigalgs, ';');
        if ( (algs != null) && (algs.length > 1) ) {
        	if (pk instanceof RSAPublicKey) {
        		if (StringUtils.contains(algs[0], CATokenConstants.KEYALGORITHM_RSA)) {
        			sigAlg = algs[0];
        		}
        		if (StringUtils.contains(algs[1], CATokenConstants.KEYALGORITHM_RSA)) {
        			sigAlg = algs[1];
        		}
        	} else if (pk instanceof JCEECPublicKey) {
        		if (StringUtils.contains(algs[0], CATokenConstants.KEYALGORITHM_ECDSA)) {
        			sigAlg = algs[0];
        		}
        		if (StringUtils.contains(algs[1], CATokenConstants.KEYALGORITHM_ECDSA)) {
        			sigAlg = algs[1];
        		}
        	}
        	m_log.debug("Using signature algorithm for response: "+sigAlg);
        }
        return sigAlg;

    }

    /** Checks the signature on an OCSP request and checks that it is signed by an allowed CA.
     * Does not check for revocation of the signer certificate
     * 
     * @param clientRemoteAddr The ip address or hostname of the remote client that sent the request, can be null.
     * @param req The signed OCSPReq
     * @param cacerts a Collection of X509Certificate, the authorized CA-certificates. The signer certificate must be issued by one of these.
     * @return X509Certificate which is the certificate that signed the OCSP request
     * @throws SignRequestSignatureException if signature verification fail, or if the signing certificate is not ahthorized
     * @throws SignRequestException if there is no signature on the OCSPReq
     * @throws OCSPException if the request can not be parsed to retrieve certificates
     * @throws NoSuchProviderException if the BC provider is not installed
     * @throws CertificateException if the certificate can not be parsed
     * @throws NoSuchAlgorithmException if the certificate contains an unsupported algorithm
     * @throws InvalidKeyException if the certificate, or CA key is invalid
     */
    public static X509Certificate checkRequestSignature(String clientRemoteAddr, OCSPReq req, Collection cacerts)
    throws SignRequestException, OCSPException,
    NoSuchProviderException, CertificateException,
    NoSuchAlgorithmException, InvalidKeyException,
    SignRequestSignatureException {
    	
    	X509Certificate signercert = null;
    	
    	if (!req.isSigned()) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorunsignedreq", clientRemoteAddr);
    		m_log.error(errMsg);
    		throw new SignRequestException(errMsg);
    	}
    	// Get all certificates embedded in the request (probably a certificate chain)
    	X509Certificate[] certs = req.getCerts("BC");
    	// Set, as a try, the signer to be the first certificate, so we have a name to log...
    	String signer = null;
    	if (certs.length > 0) {
    		signer = CertTools.getSubjectDN(certs[0]);
    	}
        // We must find a cert to verify the signature with...
    	boolean verifyOK = false;
    	for (int i = 0; i < certs.length; i++) {
    		if (req.verify(certs[i].getPublicKey(), "BC") == true) {
    			signercert = certs[i];
        		signer = CertTools.getSubjectDN(signercert);
    			String signerissuer = CertTools.getIssuerDN(signercert);
    			String infoMsg = intres.getLocalizedMessage("ocsp.infosigner", signer);
    			m_log.info(infoMsg);
    			verifyOK = true;
    			// Also check that the signer certificate can be verified by one of the CA-certificates
    			// that we answer for
    			Certificate signerca = findCertificateBySubject(CertTools.getIssuerDN(certs[i]), cacerts);
    			if (signerca != null) {
    				try {
    					signercert.verify(signerca.getPublicKey());
    				} catch (SignatureException e) {
    					infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", signer, signerissuer, e.getMessage());
    					m_log.info(infoMsg);
    					verifyOK = false;
    				}                            	
    			} else {
    				infoMsg = intres.getLocalizedMessage("ocsp.infosigner.nocacert", signer, signerissuer);
    				m_log.info(infoMsg);
    				verifyOK = false;
    			}
    			break;
    		}
    	}
    	if (!verifyOK) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorinvalidsignature", signer);
    		m_log.error(errMsg);
    		throw new SignRequestSignatureException(errMsg);
    	}
    	
    	return signercert;
    }

    /** Finds a certificate in a collection.
     * 
     * @param subjectDN the subjectDN to search for in the collection of certificate
     * @param certs Collection of X509Certificate to search in
     * @return Certificate from the certs Collection
     */
    public static X509Certificate findCertificateBySubject(String subjectDN, Collection certs) {
        if (certs == null || null == subjectDN) {
            throw new IllegalArgumentException();
        }

        if (null == certs || certs.isEmpty()) {
    		String iMsg = intres.getLocalizedMessage("ocsp.certcollectionempty");
            m_log.info(iMsg);
            return null;
        }
        String dn = CertTools.stringToBCDNString(subjectDN);
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            Certificate cacert = (Certificate) iter.next();
            // OCSP only supports X509 certificates
        	if (cacert instanceof X509Certificate) {
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Comparing the following certificates:\n"
                            + " CA certificate DN: " + CertTools.getSubjectDN(cacert)
                            + "\n Subject DN: " + dn);
                }
                if (dn.equalsIgnoreCase(CertTools.getSubjectDN(cacert))) {
                    return (X509Certificate)cacert;
                }        		
        	} else {
        		if (m_log.isDebugEnabled()) {
            		m_log.debug("Certificate not an X509 Certificate. Issuer '"+CertTools.getSubjectDN(cacert)+"'");        			
        		}
        	}
        }
		String iMsg = intres.getLocalizedMessage("ocsp.nomatchingcacert", subjectDN);
        m_log.info(iMsg);
        return null;
    }

    /** Finds a certificate in a collection based on the OCSP issuerNameHash and issuerKeyHash
     * 
     * @param certId CertificateId from the OCSP request
     * @param certs the collection of CA certificate to search through
     * @return X509Certificate A CA certificate or null of not found in the collection
     * @throws OCSPException
     */
    public static X509Certificate findCAByHash(CertificateID certId, Collection certs) throws OCSPException {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        if (null == certs || certs.isEmpty()) {
    		String iMsg = intres.getLocalizedMessage("ocsp.certcollectionempty");
            m_log.info(iMsg);
            return null;
        }
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            Certificate cert = (Certificate) iter.next();
            // OCSP only supports X509 certificates
        	if (cert instanceof X509Certificate) {
                X509Certificate cacert = (X509Certificate) cert;
                try {
                    CertificateID issuerId = new CertificateID(certId.getHashAlgOID(), cacert, CertTools.getSerialNumber(cacert));
                    if (m_log.isDebugEnabled()) {
                        m_log.debug("Comparing the following certificate hashes:\n"
                                + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
                                + " CA certificate\n"
                                + "      CA SubjectDN: '" + CertTools.getSubjectDN(cacert) + "'\n"
                                + "      SerialNumber: '" + CertTools.getSerialNumber(cacert).toString(16) + "'\n"
                                + " CA certificate hashes\n"
                                + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
                                + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n"
                                + " OCSP certificate hashes\n"
                                + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
                                + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");
                    }
                    if ((issuerId.toASN1Object().getIssuerNameHash().equals(certId.toASN1Object().getIssuerNameHash()))
                            && (issuerId.toASN1Object().getIssuerKeyHash().equals(certId.toASN1Object().getIssuerKeyHash()))) {
                        if (m_log.isDebugEnabled()) {
                            m_log.debug("Found matching CA-cert with:\n"
                                    + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
                                    + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n");                    
                        }
                        return cacert;
                    }
                } catch (OCSPException e) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errorcomparehash", cacert.getIssuerDN());
                    m_log.error(errMsg, e);
                }        		
        	} else {
        		if (m_log.isDebugEnabled()) {
            		m_log.debug("Certificate not an X509 Certificate. Issuer '"+CertTools.getSubjectDN(cert)+"'");        			
        		}
        	}
        }
        if (m_log.isDebugEnabled()) {
            m_log.debug("Did not find matching CA-cert for:\n"
                    + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
                    + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");            
        }
        return null;
    }

    /** returns an HashTable of responseExtensions to be added to the BacisOCSPResponseGenerator with
     * <code>
     * X509Extensions exts = new X509Extensions(table);
     * basicRes.setResponseExtensions(responseExtensions);
     * </code>
     * 
     * @param req OCSPReq
     * @return a Hashtable, can be empty nut not null
     */
    public static Hashtable getStandardResponseExtensions(OCSPReq req) {
        X509Extensions reqexts = req.getRequestExtensions();
        Hashtable table = new Hashtable();
        if (reqexts != null) {
        	// Table of extensions to include in the response
            X509Extension ext = reqexts.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (null != ext) {
                //m_log.debug("Found extension Nonce");
                table.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
            }
        }
    	return table;
    }
    
}
