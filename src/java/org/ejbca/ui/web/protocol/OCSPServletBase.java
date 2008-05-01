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

package org.ejbca.ui.web.protocol;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.UnknownStatus;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.MalformedRequestException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.IOCSPExtension;
import org.ejbca.core.protocol.ocsp.OCSPResponseItem;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.util.CertTools;

/**
 * @web.servlet-init-param description="Algorithm used by server to generate signature on OCSP responses"
 *   name="SignatureAlgorithm"
 *   value="${ocsp.signaturealgorithm}"
 *   
 * @web.servlet-init-param description="The interval on which new OCSP signing certs are loaded in seconds"
 *   name="ocspSigningCertsValidTime"
 *   value="${ocsp.signingCertsValidTime}"
 *
 * @web.servlet-init-param description="If set to true the servlet will enforce OCSP request signing"
 *   name="enforceRequestSigning"
 *   value="${ocsp.signaturerequired}"
 *   
 * @web.servlet-init-param description="If set to true the certificate chain will be returned with the OCSP response"
 *   name="includeCertChain"
 *   value="true"
 *   
 * @web.servlet-init-param description="If set to true the OCSP responses will be signed directly by the CAs certificate instead of the CAs OCSP responder"
 *   name="useCASigningCert"
 *   value="${ocsp.usecasigningcert}"
 *   
 * @web.servlet-init-param description="If true a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as not revoked."
 *   name="nonExistingIsGood"
 *   value="${ocsp.nonexistingisgood}"
 *   
 * @web.servlet-init-param description="Specifies the subject of a certificate which is used to identify the responder which will generate responses when no real CA can be found from the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this server"
 *   name="defaultResponderID"
 *   value="${ocsp.defaultresponder}"
 *   
 * @web.servlet-init-param description="Specifies OCSP extension oids that will result in a call to an extension class, separate multiple entries with ;"
 *   name="extensionOid"
 *   value="${ocsp.extensionoid}"
 *   
 * @web.servlet-init-param description="Specifies classes implementing OCSP extensions matching oids above, separate multiple entries with ;"
 *   name="extensionClass"
 *   value="${ocsp.extensionclass}"
 *   
 * @web.servlet-init-param description="Specifies classes implementing OCSP extensions matching oids above, separate multiple entries with ;"
 *   name="unidDataSource"
 *   value="${ocsp.uniddatsource}"
 *   
 * @web.servlet-init-param description="Directory containing certificates of trusted entities allowed to query for Fnrs."
 *   name="unidTrustDir"
 *   value="${ocsp.unidtrustdir}"
 *   
 * @web.servlet-init-param description="File containing the CA-certificate, in PEM format, that signed the trusted clients."
 *   name="unidCACert"
 *   value="${ocsp.unidcacert}"
 *   
 * @author Thomas Meckel (Ophios GmbH), Tomas Gustavsson, Lars Silven
 * @version  $Id$
 */
abstract class OCSPServletBase extends HttpServlet {

    private static final Logger m_log = Logger.getLogger(OCSPServletBase.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private Admin m_adm;

    private String m_sigAlg;
    private boolean m_reqMustBeSigned;
    Collection m_cacerts = null;
    /** Cache time counter */
    private long m_certValidTo = 0;
    /** String used to identify default responder id, used to generatwe responses when a request
     * for a certificate not signed by a CA on this server is received.
     */
    private String m_defaultResponderId;
    /** Marks if the CAs certificate or the CAs OCSP responder certificate should be used for 
     * signing the OCSP response. Defined in web.xml
     */
    private boolean m_useCASigningCert;
    /** Marks if the CAs certificate chain shoudl be included in the OCSP response or not 
     * Defined in web.xml
     */
    private boolean m_includeChain;
    /** If true a certificate that does not exist in the database, but is issued by a CA the responder handles
     * will be treated as not revoked. Default (when value is true) is to treat is as "unknown".
     */
    private boolean m_nonExistingIsGood = false;
    /** Configures OCSP extensions, these init-params are optional
     */
    private Collection m_extensionOids = new ArrayList();
    private Collection m_extensionClasses = new ArrayList();
    private HashMap m_extensionMap = null;
    /**
     * The interval on which new OCSP signing certs are loaded in seconds.
     */
    private int m_valid_time;
    

    /** Loads cacertificates but holds a cache so it's reloaded only every five minutes is needed.
     */
    protected synchronized void loadCertificates() throws Exception {
        // Kolla om vi har en cachad collection och om den inte ?r f?r gammal
        if (m_cacerts != null && m_certValidTo > new Date().getTime()) {
            return;
        }
        m_cacerts = findCertificatesByType(m_adm, CertificateDataBean.CERTTYPE_SUBCA + CertificateDataBean.CERTTYPE_ROOTCA, null);
        if (m_log.isDebugEnabled()) {
            m_log.debug("Loaded "+m_cacerts == null ? "0":m_cacerts.size()+" ca certificates");        	
        }
        loadPrivateKeys(m_adm);
        m_certValidTo = m_valid_time>0 ? new Date().getTime()+m_valid_time : Long.MAX_VALUE;
    }
    abstract protected void loadPrivateKeys(Admin adm) throws Exception;

    abstract protected Collection findCertificatesByType(Admin adm, int i, String issuerDN);

    abstract protected Certificate findCertificateByIssuerAndSerno(Admin adm, String issuerDN, BigInteger serno);

    abstract protected OCSPCAServiceResponse extendedService(Admin m_adm2, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

    abstract protected RevokedCertInfo isRevoked(Admin m_adm2, String name, BigInteger serialNumber);

    
    /** Generates an EJBCA caid from a CA certificate, or looks up the default responder certificate.
     * 
     * @param cacert the CA certificate to get the CAid from. If this is null, the default responder CA cert  is looked up and used
     * @return int 
     */
    protected int getCaid( X509Certificate cacert ) {
    	X509Certificate cert = cacert;
    	if (cacert == null) {
    		m_log.debug("No correct CA-certificate available to sign response, signing with default CA: "+m_defaultResponderId);
            cert = OCSPUtil.findCertificateBySubject(m_defaultResponderId, m_cacerts);    		
    	}

        int result = CertTools.stringToBCDNString(cert.getSubjectDN().toString()).hashCode();
        m_log.debug( cert.getSubjectDN() + " has caid: " + result );
        return result;
    }


    private BasicOCSPResp signOCSPResponse(OCSPReq req, ArrayList responseList, X509Extensions exts, X509Certificate cacert)
            throws CADoesntExistsException, ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        // Find the OCSP signing key and cert for the issuer
        BasicOCSPResp retval = null;
        {
            // Call extended CA services to get our OCSP stuff
            OCSPCAServiceResponse caserviceresp = extendedService(m_adm, getCaid(cacert), new OCSPCAServiceRequest(req, responseList, exts, m_sigAlg, m_useCASigningCert, m_includeChain));
            // Now we can use the returned OCSPServiceResponse to get private key and cetificate chain to sign the ocsp response
            if (m_log.isDebugEnabled()) {
                Collection coll = caserviceresp.getOCSPSigningCertificateChain();
                m_log.debug("Cert chain for OCSP signing is of size " + coll.size());            	
            }
            retval = caserviceresp.getBasicOCSPResp();
        }
        return retval;
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        CertTools.installBCProvider();
        m_adm = new Admin(Admin.TYPE_INTERNALUSER);
        {
            final String sValue = config.getInitParameter("ocspSigningCertsValidTime");
            if (StringUtils.isEmpty(sValue)) {
                final String errorMessage = "Servlet param ocspSigningCertsValidTime missing";
                m_log.error(errorMessage);
                throw new ServletException(errorMessage);
            }
            try {
                m_valid_time = Integer.parseInt(sValue)*1000;
            } catch( NumberFormatException e ) {
                final String errorMessage = "Servlet param ocspSigningCertsValidTime not an integer: "+sValue;
                m_log.error(errorMessage);
                throw new ServletException(errorMessage);
            }
        }
        // Parameters for OCSP signing (private) key
        m_sigAlg = config.getInitParameter("SignatureAlgorithm");
        if (StringUtils.isEmpty(m_sigAlg)) {
            m_log.error("Signature algorithm not defined in initialization parameters.");
            throw new ServletException("Missing signature algorithm in initialization parameters.");
        }
        m_defaultResponderId = config.getInitParameter("defaultResponderID");
        if (StringUtils.isEmpty(m_defaultResponderId)) {
            m_log.error("Default responder id not defined in initialization parameters.");
            throw new ServletException("Missing default responder id in initialization parameters.");
        }
        String initparam = config.getInitParameter("enforceRequestSigning");
        if (m_log.isDebugEnabled()) {
            m_log.debug("Enforce request signing : '"
                        + (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
                        + "'");
        }
        m_reqMustBeSigned = true;
        if (!StringUtils.isEmpty(initparam)) {
            if (initparam.equalsIgnoreCase("false")
                    || initparam.equalsIgnoreCase("no")) {
                m_reqMustBeSigned = false;
            }
        }
        initparam = config.getInitParameter("useCASigningCert");
        if (m_log.isDebugEnabled()) {
            m_log.debug("Use CA signing cert : '"
                        + (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
                        + "'");
        }
        m_useCASigningCert = false;
        if (!StringUtils.isEmpty(initparam)) {
            if (initparam.equalsIgnoreCase("true")
                    || initparam.equalsIgnoreCase("yes")) {
                m_useCASigningCert = true;
            }
        }
        initparam = config.getInitParameter("includeCertChain");
        if (m_log.isDebugEnabled()) {
            m_log.debug("Include certificate chain: '"
                        + (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
                        + "'");
        }
        m_includeChain = true;
        if (!StringUtils.isEmpty(initparam)) {
            if (initparam.equalsIgnoreCase("false")
                    || initparam.equalsIgnoreCase("no")) {
                m_includeChain = false;
            }
        }
        initparam = config.getInitParameter("nonExistingIsGood");
        if (m_log.isDebugEnabled()) {
            m_log.debug("Non existing certificates are good: '"
                        + (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
                        + "'");
        }
        m_nonExistingIsGood = false;
        if (!StringUtils.isEmpty(initparam)) {
            if (initparam.equalsIgnoreCase("true")
                    || initparam.equalsIgnoreCase("yes")) {
            	m_nonExistingIsGood = true;
            }
        }

        String extensionOid = null;
        String extensionClass = null;
		extensionOid = config.getInitParameter("extensionOid");
        if (StringUtils.isEmpty(extensionOid)) {
            m_log.info("ExtensionOid not defined in initialization parameters.");
        } else {
        	String[] oids = extensionOid.split(";");
        	m_extensionOids = Arrays.asList(oids);
        	
        }
        extensionClass = config.getInitParameter("extensionClass");
        if (StringUtils.isEmpty(extensionClass)) {
            m_log.info("ExtensionClass not defined in initialization parameters.");
        } else {
        	String[] classes = extensionClass.split(";");
        	m_extensionClasses = Arrays.asList(classes);        	
        }
        // Check that we have the same amount of extension oids as classes
        if (m_extensionClasses.size() != m_extensionOids.size()) {
            throw new ServletException("Number of extension classes does not match no of extension oids.");        	
        }
        // Init extensions
        Iterator iter = m_extensionClasses.iterator();
        Iterator iter2 = m_extensionOids.iterator();
        m_extensionMap = new HashMap();
        while (iter.hasNext()) {
        	String clazz = (String)iter.next();
        	String oid = (String)iter2.next();
        	IOCSPExtension ext = null;
        	try {
        		 ext = (IOCSPExtension)Class.forName(clazz).newInstance();
        		 ext.init(config);
        	} catch (Exception e) {
        		m_log.error("Can not create extension with class "+clazz, e);
        		continue;
        	}
        	m_extensionMap.put(oid,ext);
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        m_log.debug(">doPost()");
        String contentType = request.getHeader("Content-Type");
        if (!contentType.equalsIgnoreCase("application/ocsp-request")) {
            m_log.debug("Content type is not application/ocsp-request");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Content type is not application/ocsp-request");
            return;
        }
        // Get the request data
        BufferedReader in = request.getReader();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and OCSP requests are small
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] reqBytes = baos.toByteArray();
        // Do it...
        service(request, response, reqBytes);
        m_log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        m_log.debug(">doGet()");
        /**
         * We only support POST operation, so return
         * an appropriate HTTP error code to caller.
         */
        // We have one command though, to force reloading of keys, can only be run from localhost
        String reloadCAKeys = request.getParameter("reloadkeys");
        if (StringUtils.equals(reloadCAKeys, "true")) {
        	String remote = request.getRemoteAddr();
            if (StringUtils.equals(remote, "127.0.0.1")) {
        		String iMsg = intres.getLocalizedMessage("ocsp.reloadkeys", remote);
            	m_log.info(iMsg);
            	m_certValidTo = 0;
            } else {
            	m_log.info("Got reloadKeys command from unauthorized ip: "+remote);
            }
        }
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "OCSP only supports POST");
        m_log.debug("<doGet()");
    } // doGet

    public void service(HttpServletRequest request, HttpServletResponse response, byte[] reqBytes)
            throws IOException, ServletException {
        if (m_log.isDebugEnabled()) {
        	m_log.debug(">service()");
        }
        if ((reqBytes == null) || (reqBytes.length == 0)) {
            m_log.info("No request bytes from ip: "+request.getRemoteAddr());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No request bytes.");
            return;
        }
        // Don't allow requests larger than 1 million bytes
        if (reqBytes.length > 1000000) {
            m_log.info("Too large request, max size is 1000000, from ip: "+request.getRemoteAddr());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Too large request");
            return;
        }
        try {
            OCSPResp ocspresp = null;
            OCSPRespGenerator res = new OCSPRespGenerator();
            X509Certificate cacert = null; // CA-certificate used to sign response
            OCSPReq req = new OCSPReq(reqBytes);
            try {
                //m_log.debug("OCSPReq: "+new String(Base64.encode(req.getEncoded())));

                loadCertificates();

                if (m_log.isDebugEnabled()) {
                    StringBuffer certInfo = new StringBuffer();
                    Iterator iter = m_cacerts.iterator();
                    while (iter.hasNext()) {
                        X509Certificate cert = (X509Certificate) iter.next();
                        certInfo.append(cert.getSubjectDN().getName());
                        certInfo.append(',');
                        certInfo.append(cert.getSerialNumber().toString(16));
                        certInfo.append('\n');
                    }
                    m_log.debug("Found the following CA certificates : \n"
                            + certInfo.toString());
                }

            
                /**
                 * check the signature if contained in request.
                 * if the request does not contain a signature
                 * and the servlet is configured in the way 
                 * the a signature is required we send back
                 * 'sigRequired' response.
                 */
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Incoming OCSP request is signed : " + req.isSigned());
                }
                if (m_reqMustBeSigned) {
                    X509Certificate signercert = OCSPUtil.checkRequestSignature(request.getRemoteAddr(), req, m_cacerts);
					// If it verifies OK, check if it is revoked
					RevokedCertInfo rci = isRevoked(m_adm, signercert.getIssuerDN().getName(), signercert.getSerialNumber());
					// If rci == null it means the certificate does not exist in database, we then treat it as ok,
					// because it may be so that only revoked certificates is in the (external) OCSP database.
					if ((rci != null) && rci.isRevoked()) {
						String serno = signercert.getSerialNumber().toString(16);
						String errMsg = intres.getLocalizedMessage("ocsp.infosigner.revoked", signercert.getSubjectDN().getName(), signercert.getIssuerDN().getName(), serno);
						m_log.error(errMsg);
			    		throw new SignRequestSignatureException(errMsg);
					}
                }

                // Get the certificate status requests that are inside this OCSP req
                Req[] requests = req.getRequestList();
                if (requests.length <= 0) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errornoreqentities");
                    m_log.error(errMsg);
                    {
                        // All this just so we can create an error response
                        cacert = OCSPUtil.findCertificateBySubject(m_defaultResponderId, m_cacerts);
                    }
                    throw new MalformedRequestException(errMsg);
                }
                int maxRequests = 100;
                if (requests.length > maxRequests) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errortoomanyreqentities", maxRequests);
                    m_log.error(errMsg);
                    {
                        // All this just so we can create an error response
                        cacert = OCSPUtil.findCertificateBySubject(m_defaultResponderId, m_cacerts);
                    }
                    throw new MalformedRequestException(errMsg);
                }
                
                if (m_log.isDebugEnabled()) {
                	m_log.debug("The OCSP request contains " + requests.length + " simpleRequests.");
                }
                
                // Add standard response extensions
                Hashtable responseExtensions = OCSPUtil.getStandardResponseExtensions(req);

                // Look over the status requests
                ArrayList responseList = new ArrayList();
                for (int i = 0; i < requests.length; i++) {
                    CertificateID certId = requests[i].getCertID();
                    byte[] hashbytes = certId.getIssuerNameHash();
                    String hash = null;
                    if (hashbytes != null) {
                    	hash = new String(Hex.encode(hashbytes));                    	
                    }
            		String infoMsg = intres.getLocalizedMessage("ocsp.inforeceivedrequest", certId.getSerialNumber().toString(16), hash, request.getRemoteAddr());
                    m_log.info(infoMsg);
                    boolean unknownCA = false; // if the certId was issued by an unknown CA
                    // The algorithm here:
                    // We will sign the response with the CA that issued the first 
                    // certificate(certId) in the request. If the issuing CA is not available
                    // on this server, we sign the response with the default responderId (from params in web.xml).
                    // We have to look up the ca-certificate for each certId in the request though, as we will check
                    // for revocation on the ca-cert as well when checking for revocation on the certId. 
                    try {
                        cacert = OCSPUtil.findCAByHash(certId, m_cacerts);
                        if (cacert == null) {
                            // We could not find certificate for this request so get certificate for default responder
                            cacert = OCSPUtil.findCertificateBySubject(m_defaultResponderId, m_cacerts);
                            unknownCA = true;
                        }
                    } catch (OCSPException e) {
                		String errMsg = intres.getLocalizedMessage("ocsp.errorgencerthash");
                        m_log.error(errMsg, e);
                        cacert = null;
                        continue;
                    }
                    if (cacert == null) {
                		String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacert", new String(Hex.encode(certId.getIssuerNameHash())), m_defaultResponderId);
                        m_log.error(errMsg);
                        continue;
                    }
                    if (unknownCA == true) {
                		String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacertusedefault", new String(Hex.encode(certId.getIssuerNameHash())));
                        m_log.info(errMsg);
                        // If we can not find the CA, answer UnknowStatus
                        responseList.add(new OCSPResponseItem(certId, new UnknownStatus()));
                        continue;
                    }

                    /*
                     * Implement logic according to
                     * chapter 2.7 in RFC2560
                     * 
                     * 2.7  CA Key Compromise
                     *    If an OCSP responder knows that a particular CA's private key has
                     *    been compromised, it MAY return the revoked state for all
                     *    certificates issued by that CA.
                     */
                    RevokedCertInfo rci;
                    rci = isRevoked(m_adm, cacert.getIssuerDN().getName(), cacert.getSerialNumber());
                    if (null != rci && rci.getReason() == RevokedCertInfo.NOT_REVOKED) {
                        rci = null;
                    }
                    CertificateStatus certStatus = null; // null mean good
                    if (null == rci) {
                        rci = isRevoked(m_adm, cacert.getSubjectDN().getName(), certId.getSerialNumber());
                        if (null == rci) {
                            if (m_log.isDebugEnabled()) {
                                m_log.debug("Unable to find revocation information for certificate with serial '"
                                        + certId.getSerialNumber().toString(16) + "'"
                                        + " from issuer '" + cacert.getSubjectDN().getName() + "'");                                
                            }
                            String status = "good";
                            certStatus = null; // null means "good" in OCSP
                            // If we do not treat non existing certificateas as good 
                            // OR
                            // we don't actually handle requests for the CA issuing the certificate asked about
                            // then we return unknown
                            if ( (!m_nonExistingIsGood) || (OCSPUtil.findCAByHash(certId, m_cacerts) == null) ) {
                            	status = "unknown";
                            	certStatus = new UnknownStatus();
                            } 
                    		infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
                            m_log.info(infoMsg);
                            responseList.add(new OCSPResponseItem(certId, certStatus));
                        } else {
                        	BigInteger rciSerno = rci.getUserCertificate(); 
                        	if (rciSerno.compareTo(certId.getSerialNumber()) == 0) {
                                if (rci.getReason() != RevokedCertInfo.NOT_REVOKED) {
                                    certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
                                            new CRLReason(rci.getReason())));
                                } else {
                                    certStatus = null;
                                }
                                String status = "good";
                                if (certStatus != null) {
                                	status ="revoked";
                                }
                                infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
                                m_log.info(infoMsg);
                                responseList.add(new OCSPResponseItem(certId, certStatus));                        		
                        	} else {
                        		m_log.error("ERROR: Certificate serialNumber ("+rciSerno.toString(16)+") in response from database does not match request ("
                        				+certId.getSerialNumber().toString(16)+").");
                        		infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "unknown", certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
                                m_log.info(infoMsg);
                                responseList.add(new OCSPResponseItem(certId, new UnknownStatus()));                        		
                        	}
                        }
                    } else {
                        certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
                                new CRLReason(rci.getReason())));
                		infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "revoked", certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
                        m_log.info(infoMsg);
                        responseList.add(new OCSPResponseItem(certId, certStatus));
                    }

                    // Look for extension OIDs
                    Iterator iter = m_extensionOids.iterator();
                    while (iter.hasNext()) {
                    	String oidstr = (String)iter.next();
                    	DERObjectIdentifier oid = new DERObjectIdentifier(oidstr);
                        X509Extensions reqexts = req.getRequestExtensions();
                        if (reqexts != null) {
                            X509Extension ext = reqexts.getExtension(oid);
                            if (null != ext) {
                            	// We found an extension, call the extenstion class
                            	if (m_log.isDebugEnabled()) {
                            		m_log.debug("Found OCSP extension oid: "+oidstr);
                            	}
                            	IOCSPExtension extObj = (IOCSPExtension)m_extensionMap.get(oidstr);
                            	if (extObj != null) {
                            		// Find the certificate from the certId
                            		X509Certificate cert = null;
                            		cert = (X509Certificate)findCertificateByIssuerAndSerno(m_adm, cacert.getSubjectDN().getName(), certId.getSerialNumber());
                            		if (cert != null) {
                            			// Call the OCSP extension
                                    	Hashtable retext = extObj.process(request, cert, certStatus);
                                    	if (retext != null) {
                                    		// Add the returned X509Extensions to the responseExtension we will add to the basic OCSP response
                                    		responseExtensions.putAll(retext);
                                    	} else {
                                    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessextension", extObj.getClass().getName(),  new Integer(extObj.getLastErrorCode()));
                                    		m_log.error(errMsg);
                                    	}
                            		}
                            	}
                            }                        	
                        }
                    }
                    
                }
                if ((req != null) && (cacert != null)) {
                	// Add responseExtensions
                	X509Extensions exts = new X509Extensions(responseExtensions);
                	// generate the signed response object
                    BasicOCSPResp basicresp = signOCSPResponse(req, responseList, exts, cacert);
                    ocspresp = res.generate(OCSPRespGenerator.SUCCESSFUL, basicresp);
                } else {
            		String errMsg = intres.getLocalizedMessage("ocsp.errornocacreateresp");
                    m_log.error(errMsg);
                    throw new ServletException(errMsg);
                }
            } catch (MalformedRequestException e) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
                m_log.info(errMsg, e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(req, null, null, cacert);
                ocspresp = res.generate(OCSPRespGenerator.MALFORMED_REQUEST, basicresp);
            } catch (SignRequestException e) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
                m_log.info(errMsg, e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(req, null, null, cacert);
                ocspresp = res.generate(OCSPRespGenerator.SIG_REQUIRED, basicresp);
            } catch (SignRequestSignatureException e) {
        		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
                m_log.info(errMsg, e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(req, null, null, cacert);
                ocspresp = res.generate(OCSPRespGenerator.UNAUTHORIZED, basicresp);
            } catch (Exception e) {
                if (e instanceof ServletException)
                    throw (ServletException) e;
        		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
                m_log.error(errMsg, e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(req, null, null, cacert);
                ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, basicresp);
            }
            byte[] respBytes = ocspresp.getEncoded();
            response.setContentType("application/ocsp-response");
            //response.setHeader("Content-transfer-encoding", "binary");
            response.setContentLength(respBytes.length);
            response.getOutputStream().write(respBytes);
            response.getOutputStream().flush();
        } catch (OCSPException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        } catch (IllegalExtendedCAServiceRequestException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        } catch (CADoesntExistsException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        } catch (ExtendedCAServiceNotActiveException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        } catch (ExtendedCAServiceRequestException e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        }
        if (m_log.isDebugEnabled()) {
        	m_log.debug("<service()");
        }
    }

} // OCSPServlet
