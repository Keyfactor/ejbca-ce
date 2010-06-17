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
package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.RespID;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.NotSupportedException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.util.AlgorithmTools;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;

/** Class with common methods used by both Internal and External OCSP responders
 * 
 * @author tomas
 * @version $Id$
 *
 */
public class OCSPUtil {

	private static final Logger m_log = Logger.getLogger(OCSPUtil.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();


    public static BasicOCSPRespGenerator createOCSPResponse(OCSPReq req, X509Certificate respondercert, int respIdType) throws OCSPException, NotSupportedException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        BasicOCSPRespGenerator res = null;
        if (respIdType == OcspConfiguration.RESPONDERIDTYPE_NAME) {
        	res = new BasicOCSPRespGenerator(new RespID(respondercert.getSubjectX500Principal()));
        } else {
        	res = new BasicOCSPRespGenerator(respondercert.getPublicKey());
        }
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
    
    public static BasicOCSPResp generateBasicOCSPResp(OCSPCAServiceRequest serviceReq, String sigAlg, X509Certificate signerCert, PrivateKey signerKey, String provider, X509Certificate[] chain, int respIdType) 
    throws NotSupportedException, OCSPException, NoSuchProviderException, IllegalArgumentException {
    	BasicOCSPResp returnval = null;
    	BasicOCSPRespGenerator basicRes = null;
    	basicRes = OCSPUtil.createOCSPResponse(serviceReq.getOCSPrequest(), signerCert, respIdType);
    	ArrayList responses = serviceReq.getResponseList();
    	if (responses != null) {
    		Iterator iter = responses.iterator();
    		while (iter.hasNext()) {
        		OCSPResponseItem item = (OCSPResponseItem)iter.next();
            	basicRes.addResponse(item.getCertID(), item.getCertStatus(), item.getThisUpdate(), item.getNextUpdate(), null);    			
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
    		RespID respId = null;
    		if (respIdType == OcspConfiguration.RESPONDERIDTYPE_NAME) {
				respId = new RespID(signerCert.getSubjectX500Principal());    			
    		} else {
				respId = new RespID(signerCert.getPublicKey());    			
    		}
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
     * Checks if a certificate is valid
     * Does also print a WARN if the certificate is about to expire.
     * @param signerCert the certificate to be tested
     * @return true if the certificate is valid
     */
    public static boolean isCertificateValid( X509Certificate signerCert ) {
    	try {
    		signerCert.checkValidity();
    	} catch (CertificateExpiredException e) {
    		m_log.error(intres.getLocalizedMessage("ocsp.errorcerthasexpired",
    		                                       signerCert.getSerialNumber(), signerCert.getIssuerDN()));
    		return false;
    	} catch (CertificateNotYetValidException e) {
    		m_log.error(intres.getLocalizedMessage("ocsp.errornotyetvalid",
    		                                       signerCert.getSerialNumber(), signerCert.getIssuerDN()));
    		return false;
    	}
    	final long warnBeforeExpirationTime = OcspConfiguration.getWarningBeforeExpirationTime();
    	if ( warnBeforeExpirationTime<1 ) {
    		return true;
    	}
    	final Date warnDate = new Date(new Date().getTime()+warnBeforeExpirationTime);
    	try {
    		signerCert.checkValidity( warnDate );
    	} catch (CertificateExpiredException e) {
    		m_log.warn(intres.getLocalizedMessage("ocsp.warncertwillexpire", signerCert.getSerialNumber(),
    		                                      signerCert.getIssuerDN(), signerCert.getNotAfter()));
    	} catch (CertificateNotYetValidException e) {
    		throw new Error("This should never happen.", e);
    	}
		if ( m_log.isDebugEnabled() ) {
			m_log.debug("Time for \"certificate will soon expire\" not yet reached. You will be warned after: "+
		            new Date(signerCert.getNotAfter().getTime()-warnBeforeExpirationTime));
		}
    	return true;
    }
    /**
     * Method generates an ExtendedCAServiceResponse which is a OCSPCAServiceResponse wrapping the BasicOCSPRespfor usage 
     * internally in EJBCA.
     *  
     * @param ocspServiceReq OCSPCAServiceRequest
     * @param privKey PrivateKey used to sign the OCSP response
     * @param providerName Provider for the private key, can be on HSM
     * @param certChain Certificate chain for signing the OCSP response
     * @return OCSPCAServiceResponse
     * @throws IllegalExtendedCAServiceRequestException
     * @throws ExtendedCAServiceRequestException
     */
    public static OCSPCAServiceResponse createOCSPCAServiceResponse(OCSPCAServiceRequest ocspServiceReq, PrivateKey privKey, String providerName, X509Certificate[] certChain)
    throws IllegalExtendedCAServiceRequestException, ExtendedCAServiceRequestException {
    	final X509Certificate signerCert = certChain[0];
    	final String sigAlgs = ocspServiceReq.getSigAlg();
    	final PublicKey pk = signerCert.getPublicKey();
    	final String sigAlg = OCSPUtil.getSigningAlgFromAlgSelection(sigAlgs, pk);
    	m_log.debug("Signing algorithm: "+sigAlg);
    	final boolean includeChain = ocspServiceReq.includeChain();
    	m_log.debug("Include chain: "+includeChain);
    	final X509Certificate[] chain;
    	if (includeChain) {
    		chain = certChain;
    	} else {
    		chain = new X509Certificate[1];
    		chain[0] = signerCert;
    	}
    	try {
    		final int respIdType = ocspServiceReq.getRespIdType();
    		final BasicOCSPResp ocspresp = OCSPUtil.generateBasicOCSPResp(ocspServiceReq, sigAlg, signerCert, privKey, providerName, chain, respIdType);
    		final OCSPCAServiceResponse result = new OCSPCAServiceResponse(ocspresp, Arrays.asList(chain));
    		isCertificateValid(signerCert);
    		return result;
    	} catch (OCSPException ocspe) {
    		throw new ExtendedCAServiceRequestException(ocspe);
    	} catch (NoSuchProviderException nspe) {
    		throw new ExtendedCAServiceRequestException(nspe);            
    	} catch (NotSupportedException e) {
    		m_log.info("OCSP Request type not supported: ", e);
    		throw new IllegalExtendedCAServiceRequestException(e);
    	} catch (IllegalArgumentException e) {
    		m_log.error("IllegalArgumentException: ", e);
    		throw new IllegalExtendedCAServiceRequestException(e);
    	}
    } // createOCSPCAServiceResponse


    /**
     * Returns a signing algorithm to use selecting from a list of possible algorithms.
     * 
     * @param sigalgs the list of possible algorithms, ;-separated. Example "SHA1WithRSA;SHA1WithECDSA".
     * @param pk public key of signer, so we can choose between RSA, DSA and ECDSA algorithms
     * @return A single algorithm to use Example: SHA1WithRSA, SHA1WithDSA or SHA1WithECDSA
     */
    public static String getSigningAlgFromAlgSelection(String sigalgs, PublicKey pk) {
    	String sigAlg = null;
    	String[] algs = StringUtils.split(sigalgs, ';');
    	for(int i = 0; i < algs.length; i++) {
    		if ( AlgorithmTools.isCompatibleSigAlg(pk, algs[i]) ) {
    			sigAlg = algs[i];
    			break;
    		}
    	}
        m_log.debug("Using signature algorithm for response: "+sigAlg);
        return sigAlg;
    }

    /** Checks the signature on an OCSP request and checks that it is signed by an allowed CA.
     * Does not check for revocation of the signer certificate
     * 
     * @param clientRemoteAddr The ip address or hostname of the remote client that sent the request, can be null.
     * @param req The signed OCSPReq
     * @param cacerts a CertificateCache of Certificates, the authorized CA-certificates. The signer certificate must be issued by one of these.
     * @return X509Certificate which is the certificate that signed the OCSP request
     * @throws SignRequestSignatureException if signature verification fail, or if the signing certificate is not authorized
     * @throws SignRequestException if there is no signature on the OCSPReq
     * @throws OCSPException if the request can not be parsed to retrieve certificates
     * @throws NoSuchProviderException if the BC provider is not installed
     * @throws CertificateException if the certificate can not be parsed
     * @throws NoSuchAlgorithmException if the certificate contains an unsupported algorithm
     * @throws InvalidKeyException if the certificate, or CA key is invalid
     */
    public static X509Certificate checkRequestSignature(String clientRemoteAddr, OCSPReq req, CertificateCache cacerts)
    throws SignRequestException, OCSPException,
    NoSuchProviderException, CertificateException,
    NoSuchAlgorithmException, InvalidKeyException,
    SignRequestSignatureException {
    	
    	X509Certificate signercert = null;
    	
    	if (!req.isSigned()) {
    		String infoMsg = intres.getLocalizedMessage("ocsp.errorunsignedreq", clientRemoteAddr);
    		m_log.info(infoMsg);
    		throw new SignRequestException(infoMsg);
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
        		Date now = new Date();
    			String signerissuer = CertTools.getIssuerDN(signercert);
    			String infoMsg = intres.getLocalizedMessage("ocsp.infosigner", signer);
    			m_log.info(infoMsg);
    			verifyOK = true;
    			// Also check that the signer certificate can be verified by one of the CA-certificates
    			// that we answer for
    			Certificate signerca = cacerts.findLatestBySubjectDN(CertTools.getIssuerDN(certs[i]));
    			String subject = signer;
    			String issuer = signerissuer;
    			if (signerca != null) {
    				try {
    					signercert.verify(signerca.getPublicKey());
    	        		if (m_log.isDebugEnabled()) {
    	            		m_log.debug("Checking validity. Now: "+now+", signerNotAfter: "+signercert.getNotAfter());        			
    	        		}
    	        		CertTools.checkValidity(signercert, now);
    	        		// Move the error message string to the CA cert
    	    			subject = CertTools.getSubjectDN(signerca);
    	    			issuer = CertTools.getIssuerDN(signerca);
    	        		CertTools.checkValidity(signerca, now);
    				} catch (SignatureException e) {
    					infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
    					m_log.info(infoMsg);
    					verifyOK = false;
    				} catch (InvalidKeyException e) {
    					infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
    					m_log.info(infoMsg);
    					verifyOK = false;
    				} catch (CertificateNotYetValidException e) {
    					infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certnotyetvalid", subject, issuer, e.getMessage());
    					m_log.info(infoMsg);
    					verifyOK = false;
    				} catch (CertificateExpiredException e) {
    					infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certexpired", subject, issuer, e.getMessage());
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
    		m_log.info(errMsg);
    		throw new SignRequestSignatureException(errMsg);
    	}
    	
    	return signercert;
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
    
    public static Hashtable getCertificatesFromDirectory(String certificateDir) throws IOException {
    	// read all files from trustDir, expect that they are PEM formatted certificates
    	CertTools.installBCProvider();
    	File dir = new File(certificateDir);
    	Hashtable trustedCerts  = new Hashtable();
    	if (dir == null || dir.isDirectory() == false) {
    		m_log.error(dir.getCanonicalPath()+ " is not a directory.");
    		throw new IllegalArgumentException(dir.getCanonicalPath()+ " is not a directory.");                
    	}
    	File files[] = dir.listFiles();
    	if (files == null || files.length == 0) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornotrustfiles", dir.getCanonicalPath());
    		m_log.error(errMsg);                
    	}
    	for ( int i=0; i<files.length; i++ ) {
    		final String fileName = files[i].getCanonicalPath();
    		// Read the file, don't stop completely if one file has errors in it
    		try {
    			byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(fileName),
    					CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
    			X509Certificate  cert = (X509Certificate) CertTools.getCertfromByteArray(bytes);
    			String key =  cert.getIssuerDN()+";"+cert.getSerialNumber().toString(16);
    			trustedCerts.put(key,cert);
    		} catch (CertificateException e) {
    			String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
    			m_log.error(errMsg, e);
    		} catch (IOException e) {
    			String errMsg = intres.getLocalizedMessage("ocsp.errorreadingfile", fileName, "trustDir", e.getMessage());
    			m_log.error(errMsg, e);
    		}
    	}
    	return trustedCerts;
    }
    
    boolean checkAuthorization(HttpServletRequest request, Hashtable trustedCerts) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoclientauth", request.getRemoteAddr(), request.getRemoteHost());
            m_log.error(errMsg);
            return false;
        }
        // The entitys certificate is nr 0
        X509Certificate cert = certs[0];
        if (cert == null) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errornoclientauth", request.getRemoteAddr(), request.getRemoteHost());
            m_log.error(errMsg);
            return false;
        }
        if (checkCertInList(cert, trustedCerts)) {
        	return true;
        }
    	String errMsg = intres.getLocalizedMessage("ocsp.erroruntrustedclientauth", request.getRemoteAddr(), request.getRemoteHost());
        m_log.error(errMsg);
		return false;
	}
    
    /**
     * Checks to see if a certificate is in a list of certificate.
     * Comparison is made on SerialNumber
     * @param cert the certificate to look for
     * @param trustedCerts the list (Hashtable) to look in
     * @return true if cert is in trustedCerts, false otherwise
     */
    public static boolean checkCertInList(X509Certificate cert, Hashtable trustedCerts) {
    	//String key = CertTools.getIssuerDN(cert)+";"+cert.getSerialNumber().toString(16);
    	String key =  cert.getIssuerDN()+";"+cert.getSerialNumber().toString(16);
    	Object found = trustedCerts.get(key);
        if (found != null) {
            return true;
        }
        return false;
    }
}
