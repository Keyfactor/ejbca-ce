package org.ejbca.core.protocol.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
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
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.RespID;
import org.ejbca.core.model.ca.NotSupportedException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.catoken.CATokenConstants;

public class OCSPUtil {

	private static final Logger m_log = Logger.getLogger(OCSPUtil.class);

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


}
