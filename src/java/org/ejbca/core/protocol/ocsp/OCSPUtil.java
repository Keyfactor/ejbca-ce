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
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.RespID;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.ocsp.exception.NotSupportedException;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.OcspConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;

/** Class with common methods used by both Internal and External OCSP responders
 * 
 * @author tomas
 * @version $Id$
 *
 */
public class OCSPUtil {

	private static final Logger m_log = Logger.getLogger(OCSPUtil.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();


    private static BasicOCSPRespGenerator createOCSPResponse(OCSPReq req, X509Certificate respondercert, int respIdType) throws OCSPException, NotSupportedException {
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
                    @SuppressWarnings("unchecked")
                    Enumeration<ASN1ObjectIdentifier> en = seq.getObjects();
                    boolean supportsResponseType = false;
                    while (en.hasMoreElements()) {
                        ASN1ObjectIdentifier oid = en.nextElement();
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
    
    private static BasicOCSPResp generateBasicOCSPResp(OCSPCAServiceRequest serviceReq, String sigAlg, X509Certificate signerCert, PrivateKey signerKey, String provider, X509Certificate[] chain, int respIdType) 
    throws NotSupportedException, OCSPException, NoSuchProviderException, IllegalArgumentException {
    	BasicOCSPResp returnval = null;
    	BasicOCSPRespGenerator basicRes = null;
    	basicRes = createOCSPResponse(serviceReq.getOCSPrequest(), signerCert, respIdType);
    	ArrayList<OCSPResponseItem> responses = serviceReq.getResponseList();
    	if (responses != null) {
    		Iterator<OCSPResponseItem> iter = responses.iterator();
    		while (iter.hasNext()) {
        		OCSPResponseItem item = (OCSPResponseItem)iter.next();
            	basicRes.addResponse(item.getCertID(), item.getCertStatus(), item.getThisUpdate(), item.getNextUpdate(), null);    			
    		}
    	}
    	X509Extensions exts = serviceReq.getExtensions();
    	if (exts != null) {
    		@SuppressWarnings("unchecked")
            Enumeration<ASN1ObjectIdentifier> oids = exts.oids();
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
		if ( !m_log.isDebugEnabled() ) {
			return true;
		}
		m_log.debug("Time for \"certificate will soon expire\" not yet reached. You will be warned after: "+
		            new Date(signerCert.getNotAfter().getTime()-warnBeforeExpirationTime));
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
    		final BasicOCSPResp ocspresp = generateBasicOCSPResp(ocspServiceReq, sigAlg, signerCert, privKey, providerName, chain, respIdType);
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


}
