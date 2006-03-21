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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
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
import org.ejbca.core.model.ca.MalformedRequestException;
import org.ejbca.core.model.ca.NotSupportedException;
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
import org.ejbca.util.CertTools;

/**
 * @web.servlet-init-param description="Algorithm used by server to generate signature on OCSP responses"
 *   name="SignatureAlgorithm"
 *   value="SHA1WithRSA"
 *   
 * @web.servlet-init-param description="If set to true the servlet will enforce OCSP request signing"
 *   name="enforceRequestSigning"
 *   value="false"
 *   
 * @web.servlet-init-param description="If set to true the certificate chain will be returned with the OCSP response"
 *   name="includeCertChain"
 *   value="true"
 *   
 * @web.servlet-init-param description="If set to true the OCSP reponses will be signed directly by the CAs certificate instead of the CAs OCSP responder"
 *   name="useCASigningCert"
 *   value="${ocsp.usecasigningcert}"
 *   
 * @web.servlet-init-param description="Specifies the subject of a certificate which is used to identifiy the responder which will generate responses when no real CA can be found from the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this server"
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
 * @author Thomas Meckel (Ophios GmbH)
 * @author Tomas Gustavsson
 * @version  $Id: OCSPServletBase.java,v 1.13 2006-03-21 08:58:22 anatom Exp $
 */
abstract class OCSPServletBase extends HttpServlet {

    static private Logger m_log = Logger.getLogger(OCSPServletBase.class);

    private Admin m_adm;

    private String m_sigAlg;
    private boolean m_reqMustBeSigned;
    Collection m_cacerts = null;
    /** Cache time counter */
    private long m_certValidTo = 0;
    /** Cached list of cacerts is valid 5 minutes */
    private static final long VALID_TIME = 5 * 60 * 1000;
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
    /** Configures OCSP extensions, these init-params are optional
     */
    private Collection m_extensionOids = new ArrayList();
    private Collection m_extensionClasses = new ArrayList();
    private HashMap m_extensionMap = null;
    
    /** Loads cacertificates but holds a cache so it's reloaded only every five minutes is needed.
     */
    protected synchronized void loadCertificates() throws IOException, ServletException {
        // Kolla om vi har en cachad collection och om den inte ?r f?r gammal
        if (m_cacerts != null && m_certValidTo > new Date().getTime()) {
            return;
        }
        m_cacerts = findCertificatesByType(m_adm, CertificateDataBean.CERTTYPE_SUBCA + CertificateDataBean.CERTTYPE_ROOTCA, null);
        loadPrivateKeys(m_adm);
        m_certValidTo = new Date().getTime() + VALID_TIME;
    }
    abstract protected void loadPrivateKeys(Admin adm) throws ServletException, IOException;

    abstract protected Collection findCertificatesByType(Admin adm, int i, String issuerDN);

    abstract protected Certificate findCertificateByIssuerAndSerno(Admin adm, String issuerDN, BigInteger serno);

    abstract protected OCSPCAServiceResponse extendedService(Admin m_adm2, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

    abstract protected RevokedCertInfo isRevoked(Admin m_adm2, String name, BigInteger serialNumber);

    protected X509Certificate findCAByHash(CertificateID certId, Collection certs) throws OCSPException {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        if (null == certs || certs.isEmpty()) {
            m_log.info("The passed certificate collection is empty.");
            return null;
        }
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate cacert = (X509Certificate) iter.next();
            CertificateID issuerId = new CertificateID(certId.getHashAlgOID(), cacert, cacert.getSerialNumber());
            if (m_log.isDebugEnabled()) {
                m_log.debug("Comparing the following certificate hashes:\n"
                        + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
                        + " CA certificate\n"
                        + "      CA SubjectDN: '" + cacert.getSubjectDN().getName() + "'\n"
                        + "      SerialNumber: '" + cacert.getSerialNumber().toString(16) + "'\n"
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
        }
        if (m_log.isDebugEnabled()) {
            m_log.debug("Did not find matching CA-cert for:\n"
                    + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
                    + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");            
        }
        return null;
    }

    protected X509Certificate findCertificateBySubject(String subjectDN, Collection certs) {
        if (certs == null || null == subjectDN) {
            throw new IllegalArgumentException();
        }

        if (null == certs || certs.isEmpty()) {
            m_log.info("The passed certificate collection is empty.");
            return null;
        }
        String dn = CertTools.stringToBCDNString(subjectDN);
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
            X509Certificate cacert = (X509Certificate) iter.next();
            if (m_log.isDebugEnabled()) {
                m_log.debug("Comparing the following certificates:\n"
                        + " CA certificate DN: " + cacert.getSubjectDN()
                        + "\n Subject DN: " + dn);
            }
            if (dn.equalsIgnoreCase(CertTools.stringToBCDNString(cacert.getSubjectDN().getName()))) {
                return cacert;
            }
        }
        m_log.info("Did not find matching CA-cert for DN: " + subjectDN);
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
    private Hashtable getStandardResponseExtensions(OCSPReq req) {
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
    protected BasicOCSPRespGenerator createOCSPResponse(OCSPReq req, X509Certificate cacert) throws OCSPException, NotSupportedException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        BasicOCSPRespGenerator res = new BasicOCSPRespGenerator(cacert.getPublicKey());
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
    
    protected int getCaid( X509Certificate cacert ) {
        int result = CertTools.stringToBCDNString(cacert.getSubjectDN().toString()).hashCode();
        m_log.debug( cacert.getSubjectDN() + " has caid: " + result );
        return result;
    }

    private BasicOCSPResp signOCSPResponse(BasicOCSPRespGenerator basicRes, X509Certificate cacert)
            throws CADoesntExistsException, ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        // Find the OCSP signing key and cert for the issuer
        BasicOCSPResp retval = null;
        {
            // Call extended CA services to get our OCSP stuff
            OCSPCAServiceResponse caserviceresp = extendedService(m_adm, getCaid(cacert), new OCSPCAServiceRequest(basicRes, m_sigAlg, m_useCASigningCert, m_includeChain));
            // Now we can use the returned OCSPServiceResponse to get private key and cetificate chain to sign the ocsp response
            Collection coll = caserviceresp.getOCSPSigningCertificateChain();
            m_log.debug("Cert chain for OCSP signing is of size " + coll.size());
            retval = caserviceresp.getBasicOCSPResp();
        }
        return retval;
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        
        m_adm = new Admin(Admin.TYPE_INTERNALUSER);
        
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
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "OCSP only supports POST");
        m_log.debug("<doGet()");
    } // doGet

    public void service(HttpServletRequest request, HttpServletResponse response, byte[] reqBytes)
            throws IOException, ServletException {
        m_log.debug(">service()");
        if ((reqBytes == null) || (reqBytes.length == 0)) {
            m_log.debug("No request bytes");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No request bytes.");
            return;
        }
        try {
            OCSPResp ocspresp = null;
            BasicOCSPRespGenerator basicRes = null;
            OCSPRespGenerator res = new OCSPRespGenerator();
            X509Certificate cacert = null; // CA-certificate used to sign response
            try {
                OCSPReq req = new OCSPReq(reqBytes);
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
                    if (!req.isSigned()) {
                        m_log.info("OCSP request unsigned. Servlet enforces signing.");
                        throw new SignRequestException("OCSP request unsigned. Servlet enforces signing.");
                    }
                    //GeneralName requestor = req.getRequestorName();
                    X509Certificate[] certs = req.getCerts("BC");
                    // We must find a cert to verify the signature with...
                    boolean verifyOK = false;
                    for (int i = 0; i < certs.length; i++) {
                        if (req.verify(certs[i].getPublicKey(), "BC") == true) {
                            verifyOK = true;
                            break;
                        }
                    }
                    if (!verifyOK) {
                        m_log.info("Signature of incoming OCSPRequest is invalid.");
                        throw new SignRequestSignatureException("Signature invalid.");
                    }
                }

                Req[] requests = req.getRequestList();
                if (requests.length <= 0) {
                    String msg = "The OCSP request does not contain any simpleRequest entities.";
                    m_log.error(msg);
                    {
                        // All this just so we can create an error response
                        cacert = findCertificateBySubject(m_defaultResponderId, m_cacerts);
                        // Create a basicRes, just to create an error response 
                        basicRes = createOCSPResponse(req, cacert);
                    }
                    throw new MalformedRequestException(msg);
                }
                m_log.debug("The OCSP request contains " + requests.length + " simpleRequests.");
                Hashtable responseExtensions = null; 
                for (int i = 0; i < requests.length; i++) {
                    CertificateID certId = requests[i].getCertID();
                    boolean unknownCA = false; // if the certId was issued by an unknown CA
                    // The algorithm here:
                    // We will sign the response with the CA that issued the first 
                    // certificate(certId) in the request. If the issuing CA is not available
                    // on this server, we sign the response with the default responderId (from params in web.xml).
                    // We have to look up the ca-certificate for each certId in the request though, as we will check
                    // for revocation on the ca-cert as well when checking for revocation on the certId. 
                    try {
                        cacert = findCAByHash(certId, m_cacerts);
                        if (cacert == null) {
                            // We could not find certificate for this request so get certificate for default responder
                            cacert = findCertificateBySubject(m_defaultResponderId, m_cacerts);
                            unknownCA = true;
                        }
                    } catch (OCSPException e) {
                        m_log.error("Unable to generate CA certificate hash.", e);
                        cacert = null;
                        continue;
                    }
                    // Create a basic response (if we haven't done it already) using the first issuer we find, or the default one
                    if ((cacert != null) && (basicRes == null)) {
                        basicRes = createOCSPResponse(req, cacert);
                        if (m_log.isDebugEnabled()) {
                            if (m_useCASigningCert) {
                                m_log.debug("Signing OCSP response directly with CA: " + cacert.getSubjectDN().getName());
                            } else {
                                m_log.debug("Signing OCSP response with OCSP signer of CA: " + cacert.getSubjectDN().getName());
                            }
                        }
                        // Add standard response extensions
                        responseExtensions = getStandardResponseExtensions(req);
                    } else if (cacert == null) {
                        final String msg = "Unable to find CA certificate by issuer name hash: " + new String(Hex.encode(certId.getIssuerNameHash())) + ", or even the default responder: " + m_defaultResponderId;
                        m_log.error(msg);
                        continue;
                    }
                    if (unknownCA == true) {
                        final String msg = "Unable to find CA certificate by issuer name hash: " + new String(Hex.encode(certId.getIssuerNameHash())) + ", using the default reponder to send 'UnknownStatus'";
                        m_log.info(msg);
                        // If we can not find the CA, answer UnknowStatus
                        basicRes.addResponse(certId, new UnknownStatus());
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
                                        + certId.getSerialNumber() + "'"
                                        + " from issuer '" + cacert.getSubjectDN().getName() + "'");                                
                            }
                            basicRes.addResponse(certId, new UnknownStatus());
                        } else {
                            if (rci.getReason() != RevokedCertInfo.NOT_REVOKED) {
                                certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
                                        new CRLReason(rci.getReason())));
                            } else {
                                certStatus = null;
                            }
                            if (m_log.isDebugEnabled()) {
                                m_log.debug("Adding status information for certificate with serial '"
                                        + certId.getSerialNumber() + "'"
                                        + " from issuer '" + cacert.getSubjectDN().getName() + "'");
                            }
                            basicRes.addResponse(certId, certStatus);
                        }
                    } else {
                        certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
                                new CRLReason(rci.getReason())));
                        basicRes.addResponse(certId, certStatus);
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
                                    		m_log.error("En error occured when processing OCSP extensions class: "+extObj.getClass().getName()+", error code="+extObj.getLastErrorCode());
                                    	}
                            		}
                            	}
                            }                        	
                        }
                    }
                    
                }
                if ((basicRes != null) && (cacert != null)) {
                	// Add responseExtensions
                	X509Extensions exts = new X509Extensions(responseExtensions);
                	basicRes.setResponseExtensions(exts);
                	// generate the signed response object
                    BasicOCSPResp basicresp = signOCSPResponse(basicRes, cacert);
                    ocspresp = res.generate(OCSPRespGenerator.SUCCESSFUL, basicresp);
                } else {
                    final String msg = "Unable to find CA certificate and key to generate OCSP response!";
                    m_log.error(msg);
                    throw new ServletException(msg);
                }
            } catch (MalformedRequestException e) {
                m_log.info("MalformedRequestException caught : ", e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(basicRes, cacert);
                ocspresp = res.generate(OCSPRespGenerator.MALFORMED_REQUEST, basicresp);
            } catch (SignRequestException e) {
                m_log.info("SignRequestException caught : ", e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(basicRes, cacert);
                ocspresp = res.generate(OCSPRespGenerator.SIG_REQUIRED, basicresp);
            } catch (Exception e) {
                if (e instanceof ServletException)
                    throw (ServletException) e;
                m_log.error("Unable to handle OCSP request.", e);
                // generate the signed response object
                BasicOCSPResp basicresp = signOCSPResponse(basicRes, cacert);
                ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, basicresp);
            }
            byte[] respBytes = ocspresp.getEncoded();
            response.setContentType("application/ocsp-response");
            //response.setHeader("Content-transfer-encoding", "binary");
            response.setContentLength(respBytes.length);
            response.getOutputStream().write(respBytes);
            response.getOutputStream().flush();
        } catch (OCSPException e) {
            m_log.error("OCSPException caught, fatal error : ", e);
            throw new ServletException(e);
        } catch (IllegalExtendedCAServiceRequestException e) {
            m_log.error("Can't generate any type of OCSP response: ", e);
            throw new ServletException(e);
        } catch (CADoesntExistsException e) {
            m_log.error("CA used to sign OCSP response does not exist: ", e);
            throw new ServletException(e);
        } catch (ExtendedCAServiceNotActiveException e) {
            m_log.error("Error in CAs extended service: ", e);
            throw new ServletException(e);
        } catch (ExtendedCAServiceRequestException e) {
            m_log.error("Error in CAs extended service: ", e);
            throw new ServletException(e);
        }
        m_log.debug("<service()");
    }

} // OCSPServlet
