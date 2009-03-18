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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
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
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.bouncycastle.util.encoders.Hex;
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
import org.ejbca.core.protocol.ocsp.AuditLogger;
import org.ejbca.core.protocol.ocsp.CertificateCache;
import org.ejbca.core.protocol.ocsp.DummyAuditLogger;
import org.ejbca.core.protocol.ocsp.DummyTransactionLogger;
import org.ejbca.core.protocol.ocsp.IAuditLogger;
import org.ejbca.core.protocol.ocsp.IOCSPExtension;
import org.ejbca.core.protocol.ocsp.ISaferAppenderListener;
import org.ejbca.core.protocol.ocsp.ITransactionLogger;
import org.ejbca.core.protocol.ocsp.OCSPResponseItem;
import org.ejbca.core.protocol.ocsp.OCSPUnidResponse;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.core.protocol.ocsp.TransactionLogger;
import org.ejbca.util.CertTools;
import org.ejbca.util.GUIDGenerator;

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
 * @web.servlet-init-param description="If set to true the servlet will restrict OCSP request signing"
 *   name="restrictSignatures"
 *   value="${ocsp.restrictsignatures}"
 *   
 * @web.servlet-init-param description="Set this to issuer or signer depending on how you want to restrict allowed signatures for OCSP request signing"
 *   name="restrictSignaturesByMethod"
 *   value="${ocsp.restrictsignaturesbymethod}"
 *   
 * @web.servlet-init-param description="If restrictSignatures is true the servlet will look in this directory for allowed signer certificates or issuers"
 *   name="signTrustDir"
 *   value="${ocsp.signtrustdir}"
 *   
 * @web.servlet-init-param description="The interval on which list of allowed OCSP request signing certs are loaded from signTrustDir in seconds"
 *   name="signTrustValidTime"
 *   value="${ocsp.signtrustvalidtime}"
 *   
 * @web.servlet-init-param description="If set to true the certificate chain will be returned with the OCSP response"
 *   name="includeCertChain"
 *   value="${ocsp.includecertchain}"
 *   
 * @web.servlet-init-param description="If set to true the OCSP responses will be signed directly by the CAs certificate instead of the CAs OCSP responder"
 *   name="useCASigningCert"
 *   value="${ocsp.usecasigningcert}"
 *   
 * @web.servlet-init-param description="If set to name the OCSP responses will use the Name ResponseId type, if set to keyhash the KeyHash type will be used."
 *   name="responderIdType"
 *   value="${ocsp.responderidtype}"
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
 *  @web.servlet-init-param description="When true, an audit log will be created."
 *   name="auditLog"
 *   value="${ocsp.audit-log}"
 *   
 *  @web.servlet-init-param description="A format string for logging of dates in auditLog and accountLog"
 *   name="logDateFormat"
 *   value="${ocsp.log-date}"
 *   
 *  @web.servlet-init-param description="A format string for TimeZone auditLog and accountLog"
 *   name="logTimeZone"
 *   value="${ocsp.log-timezone}"
 *   
 *  @web.servlet-init-param description="Set to true if you want transactions to be aborted when logging fails"
 *   name="logSafer"
 *   value="${ocsp.log-safer}"
 *   
 *  @web.servlet-init-param description="A String to create a java Pattern to format the audit Log"
 *   name="auditLogPattern"
 *   value="${ocsp.audit-log-pattern}"
 *   
 *  @web.servlet-init-param description="A String which combined with auditLogPattern determines how auditLog output is formatted."
 *   name="auditLogOrder"
 *   value="${ocsp.audit-log-order}"
 *   
 *  @web.servlet-init-param description="When true, a transaction log will be created."
 *   name="transactionLog"
 *   value="${ocsp.trx-log}"
 *   
 *  @web.servlet-init-param description="A String to create a java Pattern to format the transaction Log."
 *   name="transactionLogPattern"
 *   value="${ocsp.trx-log-pattern}"
 *   
 *  @web.servlet-init-param description="A String which combined with transactionLogPattern determines how transaction Log output is formatted."
 *   name="transactionLogOrder"
 *   value="${ocsp.trx-log-order}"
 *   
 *  @web.servlet-init-param description="The default number of seconds a request is valid or 0 to disable."
 *   name="untilNextUpdate"
 *   value="${ocsp.untilNextUpdate}"
 *   
 *  @web.servlet-init-param description="The default number of seconds a HTTP-response should be cached."
 *   name="maxAge"
 *   value="${ocsp.maxAge}"
 *   
 * @author Thomas Meckel (Ophios GmbH), Tomas Gustavsson, Lars Silven
 * @version  $Id$
 */
public abstract class OCSPServletBase extends HttpServlet implements ISaferAppenderListener { 

	private static final Logger m_log = Logger.getLogger(OCSPServletBase.class);
	
	private static final int RESTRICTONISSUER = 0;
	private static final int RESTRICTONSIGNER = 1;
	
	/** Max size of an OCSP request is 100000 bytes */
	private static final int MAX_OCSP_REQUEST_SIZE = 100000;
	
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();
	private  boolean canlog =true;
	protected Admin m_adm;
	private String m_sigAlg;
	private boolean m_reqMustBeSigned;
	/** True if requests must be signed by a certificate issued by a list of trusted CA's*/
	private boolean m_reqRestrictSignatures;
	private int m_reqRestrictMethod;
	private int m_signTrustValidTime = 180*1000; // 180 seconds calculated as milliseconds
	/** A list of CA's trusted for issuing certificates for signing requests */
	private Hashtable mTrustedReqSigIssuers;
	private Hashtable mTrustedReqSigSigners;
	/** String used to identify default responder id, used to generate responses when a request
	 * for a certificate not signed by a CA on this server is received.
	 */
	private String m_defaultResponderId;
	/** Marks if the CAs certificate or the CAs OCSP responder certificate should be used for 
	 * signing the OCSP response. Defined in web.xml
	 */
	private boolean m_useCASigningCert;
	/** Marks if the CAs certificate chain should be included in the OCSP response or not 
	 * Defined in web.xml
	 */
	private boolean m_includeChain;
	/** If true a certificate that does not exist in the database, but is issued by a CA the responder handles
	 * will be treated as not revoked. Default (when value is true) is to treat is as "unknown".
	 */
	private boolean m_nonExistingIsGood = false;
	/** Controls which of the two possible types of responderId should be used. See RFC2560 for details.
	 * Default is to use KeyId, the other possible type is X500name.
	 */
	private int	m_respIdType = OCSPUtil.RESPONDERIDTYPE_KEYHASH;

	/** The interval on which new OCSP signing certs and keys are loaded in seconds. */
	protected int m_valid_time;
	/** Cache time counter, set and used by loadPrivateKeys (external responder) */
	protected long mKeysValidTo = 0;

	/** Cache of CA certificates (and chain certs) for CAs handles by this responder */
	protected CertificateCache m_caCertCache = null;
	
	/** Configures OCSP extensions, these init-params are optional
	 */
	private Collection m_extensionOids = new ArrayList();
	private Collection m_extensionClasses = new ArrayList();
	private HashMap m_extensionMap = null;
	private boolean mDoAuditLog=false; //Default is no audit logging
	private boolean mDoTransactionLog=false; //Default is no account logging

	/**
	 * The interval on which new OCSP signing certs are loaded in seconds.
	 */
	private long m_trustDirValidTo;
	private String m_signTrustDir;
	private int mTransactionID = 0;
	private String m_SessionID;
	private boolean mDoSaferLogging;
	/** Method gotten through reflection, we put it in a variable so we don't have to use
	 * reflection every time we use the audit or transaction log */
	private Method m_errorHandlerMethod = null;
	private static final String PROBEABLE_ERRORHANDLER_CLASS = "org.ejbca.appserver.jboss.ProbeableErrorHandler";
	private static final String SAFER_LOG4JAPPENDER_CLASS = "org.ejbca.appserver.jboss.SaferDailyRollingFileAppender";
	
	/** The interval in milliseconds which a OCSP result is valid. */
	private long untilNextUpdate;
	private long maxAge;
	
	protected synchronized void loadTrustDir() throws Exception {
		// Check if we have a cached collection that is not too old
		if(m_reqRestrictMethod == RESTRICTONISSUER) {
			if (mTrustedReqSigIssuers != null && m_trustDirValidTo > new Date().getTime()) {
				return;
			}
			mTrustedReqSigIssuers = OCSPUtil.getCertificatesFromDirectory(m_signTrustDir);
			if (m_log.isDebugEnabled()) {
				m_log.debug("Loaded "+mTrustedReqSigIssuers == null ? "0":mTrustedReqSigIssuers.size()+" CA-certificates as trusted for OCSP-request signing");        	
			}
			m_trustDirValidTo = m_signTrustValidTime>0 ? new Date().getTime()+m_signTrustValidTime : Long.MAX_VALUE;;
		}
		if(m_reqRestrictMethod == RESTRICTONSIGNER) {
			if (mTrustedReqSigSigners != null && m_trustDirValidTo > new Date().getTime()) {
				return;
			}
			mTrustedReqSigSigners = OCSPUtil.getCertificatesFromDirectory(m_signTrustDir);
			if (m_log.isDebugEnabled()) {
				m_log.debug("Loaded "+mTrustedReqSigSigners == null ? "0":mTrustedReqSigSigners.size()+" Signer-certificates as trusted for OCSP-request signing");        	
			}
			m_trustDirValidTo = m_signTrustValidTime>0 ? new Date().getTime()+m_signTrustValidTime : Long.MAX_VALUE;;
		}
	}

	abstract void loadPrivateKeys(Admin adm) throws Exception;

	abstract Certificate findCertificateByIssuerAndSerno(Admin adm, String issuerDN, BigInteger serno);

	abstract OCSPCAServiceResponse extendedService(Admin m_adm2, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

	abstract RevokedCertInfo isRevoked(Admin m_adm2, String name, BigInteger serialNumber);

	/** returns a CertificateCache of appropriate type */
	abstract CertificateCache createCertificateCache(Properties prop);

	/** Generates an EJBCA caid from a CA certificate, or looks up the default responder certificate.
	 * 
	 * @param cacert the CA certificate to get the CAid from. If this is null, the default responder CA cert  is looked up and used
	 * @return int 
	 */
	 int getCaid( X509Certificate cacert ) {
		X509Certificate cert = cacert;
		if (cacert == null) {
			m_log.debug("No correct CA-certificate available to sign response, signing with default CA: "+m_defaultResponderId);
			cert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);    		
		}

		int result = CertTools.stringToBCDNString(cert.getSubjectDN().toString()).hashCode();
		if (m_log.isDebugEnabled()) {
			m_log.debug( cert.getSubjectDN() + " has caid: " + result );
		}
		return result;
	}


	private BasicOCSPResp signOCSPResponse(OCSPReq req, ArrayList responseList, X509Extensions exts, X509Certificate cacert)
	throws CADoesntExistsException, ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {

	    // Call extended CA services to get our OCSP stuff
	    OCSPCAServiceRequest ocspservicerequest = new OCSPCAServiceRequest(req, responseList, exts, m_sigAlg, m_useCASigningCert, m_includeChain);
	    ocspservicerequest.setRespIdType(m_respIdType);
	    OCSPCAServiceResponse caserviceresp = extendedService(m_adm, getCaid(cacert), ocspservicerequest);
	    // Now we can use the returned OCSPServiceResponse to get private key and cetificate chain to sign the ocsp response
	    if (m_log.isDebugEnabled()) {
	        Collection coll = caserviceresp.getOCSPSigningCertificateChain();
	        m_log.debug("Cert chain for OCSP signing is of size " + coll.size());            	
	    }
	    return caserviceresp.getBasicOCSPResp();
	}

	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		CertTools.installBCProvider();
        m_SessionID = GUIDGenerator.generateGUID(this);
		m_adm = new Admin(Admin.TYPE_INTERNALUSER);
		

		{
			final String sValue = config.getInitParameter("signTrustValidTime");
			if (StringUtils.isNotEmpty(sValue)) {
				try {
					m_signTrustValidTime = Integer.parseInt(sValue)*1000;
				} catch( NumberFormatException e ) {
					final String errorMessage = "Servlet param signTrustValidTime not an integer: "+sValue+", using default value: "+m_signTrustValidTime;
					m_log.warn(errorMessage);
				}
			}
			// If it is empty we'll use the default value of 180
			m_log.debug("signTrustValidTime is: "+m_signTrustValidTime);
		}
		
		// Parameters for OCSP signing (private) key
		m_sigAlg = config.getInitParameter("SignatureAlgorithm");
		if (StringUtils.isEmpty(m_sigAlg)) {
			m_log.error("Signature algorithm not defined in initialization parameters.");
			throw new ServletException("Missing signature algorithm in initialization parameters.");
		}
		m_log.debug("SignatureAlgorithm is: "+m_sigAlg);
		
		m_defaultResponderId = config.getInitParameter("defaultResponderID");
		if (StringUtils.isEmpty(m_defaultResponderId)) {
			m_log.error("Default responder id not defined in initialization parameters.");
			throw new ServletException("Missing default responder id in initialization parameters.");
		}
		m_log.debug("defaultResponderID is: "+m_defaultResponderId);
		
		String initparam = config.getInitParameter("enforceRequestSigning");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Enforce request signing: '"
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
		
		initparam = config.getInitParameter("restrictSignatures");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Restrict request signing: '"
					+ (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
					+ "'");
		}
		m_reqRestrictSignatures = false;
		if (!StringUtils.isEmpty(initparam)) {
			if ((initparam.equalsIgnoreCase("true")) || (initparam.equalsIgnoreCase("yes"))) {
				m_reqRestrictSignatures = true;
			}
		}
		if (m_reqRestrictSignatures) {
			m_reqRestrictMethod=RESTRICTONISSUER; // default = issuer
			// find out method for restricting request signatures
			String restrictMethod = config.getInitParameter("restrictSignaturesByMethod");
			m_signTrustDir = config.getInitParameter("signTrustDir");
			if (m_log.isDebugEnabled()) {
				m_log.debug("Directory containing trusted CA's for request Signing: '"
						+ (StringUtils.isEmpty(initparam) ? "<not set>" : m_signTrustDir)
						+ "'");
			}
			if ( restrictMethod.equalsIgnoreCase("issuer") ) {
				try {
					mTrustedReqSigIssuers = OCSPUtil.getCertificatesFromDirectory(m_signTrustDir);
					m_reqRestrictMethod = RESTRICTONISSUER;
				} catch (IOException e1) {
					m_log.error("OCSP request signatures are restricted but allowed signatures could not be read from file, check ocsp.properties." +e1);
				} 
			} else if ( restrictMethod.equalsIgnoreCase("signer") ) {
				try {
					mTrustedReqSigSigners = OCSPUtil.getCertificatesFromDirectory(m_signTrustDir);
					m_reqRestrictMethod = RESTRICTONSIGNER;
				} catch (IOException e1) {
					m_log.error("OCSP request signatures are restricted but allowed signatures could not be read from file, check ocsp.properties." +e1);
				} 
			} else {
				m_log.error("OCSP request signatures are restricted but allowed signatures could not be read from file, check ocsp.properties.");
			}
		}
		initparam = config.getInitParameter("useCASigningCert");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Use CA signing cert: '"
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
		
		initparam = config.getInitParameter("responderIdType");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Responder Id type: '"
					+ (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
					+ "'");
		}
		m_respIdType = OCSPUtil.RESPONDERIDTYPE_KEYHASH;
		if (!StringUtils.isEmpty(initparam)) {
			if (initparam.equalsIgnoreCase("name")) {
				m_respIdType = OCSPUtil.RESPONDERIDTYPE_NAME;
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

		/**
		 * Set up Audit and Transaction Logging
		 */
		initparam = config.getInitParameter("auditLog");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Are we doing auditLogging?: '"
					+ (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
					+ "'");
		}
		if (!StringUtils.isEmpty(initparam)) {
			if (initparam.equalsIgnoreCase("true")
					|| initparam.equalsIgnoreCase("yes")) {
				mDoAuditLog = true;
			}
		}
				
		String timezone = config.getInitParameter("logTimeZone");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Is time zone set??: '"
					+ (StringUtils.isEmpty(timezone) ? "<not set>" : timezone)
					+ "'");
		}

		String logDateFormat = config.getInitParameter("logDateFormat");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Is date format set??: '"
					+ (StringUtils.isEmpty(logDateFormat) ? "<not set>" : logDateFormat)
					+ "'");
		}

		if (mDoAuditLog==true) { // If we are not going to do any logging we wont bother setting it up
			String auditLogPattern = config.getInitParameter("auditLogPattern");
			if (m_log.isDebugEnabled()) {
				m_log.debug("Pattern used for auditLogPattern: '"
						+ (StringUtils.isEmpty(auditLogPattern) ? "<not set>" : auditLogPattern)
						+ "'");
			}
			String auditLogOrder = config.getInitParameter("auditLogOrder");
			if (m_log.isDebugEnabled()) {
				m_log.debug("Pattern used for auditLogOrder: '"
						+ (StringUtils.isEmpty(auditLogOrder) ? "<not set>" : auditLogOrder)
						+ "'");
			}
				AuditLogger.configure(auditLogPattern, auditLogOrder,logDateFormat, timezone);
		}

		initparam = config.getInitParameter("transactionLog");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Are we doing auditLogging?: '"
					+ (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
					+ "'");
		}
		mDoTransactionLog = false; // Default is no accountlogging
		if (!StringUtils.isEmpty(initparam)) {
			if (initparam.equalsIgnoreCase("true")
					|| initparam.equalsIgnoreCase("yes")) {
				mDoTransactionLog = true;
			}
		}
		if (mDoTransactionLog==true) { // If we are not going to do any logging we wont bother setting it up
			String transactionLogPattern = config.getInitParameter("transactionLogPattern");
			if (m_log.isDebugEnabled()) {
				m_log.debug("Pattern used for transactionLogPattern: '"
						+ (StringUtils.isEmpty(transactionLogPattern) ? "<not set>" : transactionLogPattern)
						+ "'");
			}
			String transactionLogOrder = config.getInitParameter("transactionLogOrder");
			if (m_log.isDebugEnabled()) {
				m_log.debug("Pattern used for transactionLogOrder: '"
						+ (StringUtils.isEmpty(transactionLogOrder) ? "<not set>" : transactionLogOrder)
						+ "'");
			}	
			TransactionLogger.configure(transactionLogPattern, transactionLogOrder, logDateFormat, timezone);
		}
		// Are we supposed to abort the response if logging is failing?
		initparam = config.getInitParameter("logSafer");
		if (m_log.isDebugEnabled()) {
			m_log.debug("Are we doing safer logging?: '"
					+ (StringUtils.isEmpty(initparam) ? "<not set>" : initparam)
					+ "'");
		}
		mDoSaferLogging = false; // Default is not to abort when logging fails
		if (!StringUtils.isEmpty(initparam)) {
			if (initparam.equalsIgnoreCase("true")
					|| initparam.equalsIgnoreCase("yes")) {
				mDoSaferLogging = true;
			}
		}

        if (mDoSaferLogging==true) {
            try {
                final Class implClass = Class.forName(SAFER_LOG4JAPPENDER_CLASS);
                final Method method = implClass.getMethod("addSubscriber", ISaferAppenderListener.class);
                method.invoke(null, this); // first object parameter can be null because this is a static method
                m_log.info("added us as subscriber to org.ejbca.appserver.jboss.SaferDailyRollingFileAppender");
                // create the method object of the static probeable error handler, so we don't have to do this every tim we log
    			final Class errHandlerClass = Class.forName(PROBEABLE_ERRORHANDLER_CLASS);
    			m_errorHandlerMethod = errHandlerClass.getMethod("hasFailedSince", Date.class);
            } catch (Exception e) {
                m_log.error("Was configured to do safer logging but could not instantiate needed classes", e);
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
		// Cache-friendly parameters
		initparam = config.getInitParameter("untilNextUpdate");
		if (StringUtils.isEmpty(initparam)) {
			initparam = "0";	// Disabled by default
		}
		if (m_log.isDebugEnabled()) {
			m_log.debug("untilNextUpdate: " + initparam);
		}
		untilNextUpdate = Long.parseLong(initparam) * 1000;
		initparam = config.getInitParameter("maxAge");
		if (StringUtils.isEmpty(initparam)) {
			initparam = "30";	// 30 seconds by default
		}
		if (m_log.isDebugEnabled()) {
			m_log.debug("maxAge: " + initparam);
		}
		maxAge = Long.parseLong(initparam) * 1000;
		
		// Finally we load the CA certificates and private keys of this OCSP responder
		{
			// Create properties used to set up the CertificateCache
			Properties cacheProperties = new Properties();
			
			final String sValue = config.getInitParameter("ocspSigningCertsValidTime");
			if (StringUtils.isEmpty(sValue)) {
				final String errorMessage = "Servlet param ocspSigningCertsValidTime missing";
				m_log.error(errorMessage);
				throw new ServletException(errorMessage);
			}
			try {
				m_valid_time = Integer.parseInt(sValue)*1000;
				m_log.debug("ocspSigningCertsValidTime is: "+m_valid_time);
				cacheProperties.put("ocspSigningCertsValidTime", Integer.valueOf(m_valid_time));
			} catch( NumberFormatException e ) {
				final String errorMessage = "Servlet param ocspSigningCertsValidTime not an integer: "+sValue;
				m_log.error(errorMessage);
				throw new ServletException(errorMessage);
			}
			// Create and load the certificate cache
			// If this is an internal or external ocsp responder
			m_caCertCache = createCertificateCache(cacheProperties);
		}
	} // init
	
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.SaferAppenderInterface#canlog(boolean)
	 */
	public void setCanlog(boolean pCanlog) {
		canlog = pCanlog;
	}

	/** Method that checks with ProbeableErrorHandler if an error has happended since a certain time.
	 * Uses reflection to call ProbeableErrorHandler because it is dependent on JBoss log4j logging, 
	 * which is not available on other application servers.
	 * 
	 * @param startTime
	 * @return true if an error has occured
	 */
    private boolean hasErrorHandlerFailedSince(Date startTime) {
        if ( m_errorHandlerMethod==null )
            return false;
        try {
            final boolean result = ((Boolean)m_errorHandlerMethod.invoke(null, startTime)).booleanValue(); // first object parameter can be null because this is a static method
            if (!result) {
                m_log.error("Audit and/or account logging is not working properly.");
            }
        } catch (Exception e) {
            m_log.error(e);
        }
        return false;
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		m_log.trace(">doPost()");
		String contentType = request.getHeader("Content-Type");
		if (!contentType.equalsIgnoreCase("application/ocsp-request")) {
			m_log.debug("Content type is not application/ocsp-request");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Content type is not application/ocsp-request");
		} else {
			// Do it...
			serviceOCSP(request, response);
		}
		m_log.trace("<doPost()");
	} //doPost

	public void doGet(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		m_log.trace(">doGet()");
		// We have a command to force reloading of keys that can only be run from localhost
		String reloadCAKeys = request.getParameter("reloadkeys");
		if (StringUtils.equals(reloadCAKeys, "true")) {
			String remote = request.getRemoteAddr();
			if (StringUtils.equals(remote, "127.0.0.1")) {
				String iMsg = intres.getLocalizedMessage("ocsp.reloadkeys", remote);
				m_log.info(iMsg);
				// Reload CA certificates
				m_caCertCache.forceReload();
				try {
					// Also reload signing keys
					mKeysValidTo = 0;
					loadPrivateKeys(m_adm);
				} catch (Exception e) {
					m_log.error(e);
					throw new ServletException(e);
				}
			} else {
				m_log.info("Got reloadKeys command from unauthorized ip: "+remote);
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			}
		} else {
			serviceOCSP(request, response);
		}
		m_log.trace("<doGet()");
	} // doGet

	/** Reads the request bytes and verifies min and max size of the request. If an error occurs it throws a MalformedRequestException. 
	 * The calling process should then send back an approriate HTTP error code, HttpServletResponse.SC_BAD_REQUEST.
	 * Can get request bytes both from a HTTP GET and POST request
	 * 
	 * @param request
	 * @param response
	 * @return the request bytes or null if an error occured.
	 * @throws IOException In case there is no stream to read
	 * @throws MalformedRequestException 
	 */
	private byte[] checkAndGetRequestBytes(HttpServletRequest request, HttpServletResponse response) throws IOException, MalformedRequestException {
		byte[] ret = null;
		// Get the request data
		String method = request.getMethod();
		String remoteAddress = request.getRemoteAddr();
		if (m_log.isDebugEnabled()) {
			m_log.debug("Received "+method+" request with content length: "+request.getContentLength()+" from "+remoteAddress);		
		}
		if (request.getContentLength() > MAX_OCSP_REQUEST_SIZE) {
			String msg = intres.getLocalizedMessage("ocsp.toolarge", MAX_OCSP_REQUEST_SIZE, request.getContentLength());
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		} else {
			// So we passed basic tests, now we can read the bytes, but still keep an eye on the size
			// we can not fully trust the sent content length.
			if (StringUtils.equals(method, "POST")) {
		        ServletInputStream in = request.getInputStream();
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				try {
					// This works for small requests, and OCSP requests are small
					int b = in.read();
					while ( (b != -1) && (baos.size() <= MAX_OCSP_REQUEST_SIZE) ) {
						baos.write(b);
						b = in.read();
					}
					// Double-check so the actual data also is smaller than the allowed length, not just the Content-Length header.
					if (baos.size() > MAX_OCSP_REQUEST_SIZE) {
						String msg = intres.getLocalizedMessage("ocsp.toolarge", MAX_OCSP_REQUEST_SIZE, baos.size());
						m_log.info(msg);
						throw new MalformedRequestException(msg);
					} else {
						// All seems good, we got the request bytes
						baos.flush();
						in.close();
						ret = baos.toByteArray();				
					}
				} finally {
					in.close();
					baos.close();
				}				
			} else if (StringUtils.equals(method, "GET")) {
				// GET request
				StringBuffer url = request.getRequestURL();
//				if (m_log.isDebugEnabled()) {
//					m_log.debug("URL: "+url.toString());
//				}
				// RFC2560 A.1.1 says that request longer than 255 bytes SHOULD be sent by POST, we support GET for longer requests anyway.
				if (url.length() <= MAX_OCSP_REQUEST_SIZE) {
					String pathInfo = request.getPathInfo();
					if (pathInfo != null && pathInfo.length() > 0) {
						if (m_log.isDebugEnabled()) {
							// Don't log the request if it's too long, we don't want to cause denial of service by filling log files or buffers.
							if (pathInfo.length() < 2048) {
								m_log.debug("pathInfo: "+pathInfo);
							} else {
								m_log.debug("pathInfo too long to log: "+pathInfo.length());
							}
						}
						try {
							ret = org.ejbca.util.Base64.decode(URLDecoder.decode(pathInfo.substring(1), "UTF-8").getBytes());
						} catch (Exception e) {
							String msg = intres.getLocalizedMessage("ocsp.badurlenc");
							m_log.info(msg);
							throw new MalformedRequestException(e);
						}
					} else {
						String msg = intres.getLocalizedMessage("ocsp.missingreq");
						m_log.info(msg);
						throw new MalformedRequestException(msg);
					}
				} else {
					String msg = intres.getLocalizedMessage("ocsp.toolarge", MAX_OCSP_REQUEST_SIZE, url.length());
					m_log.info(msg);
					throw new MalformedRequestException(msg);
				}
			} else {
				// Strange, an unknown method
				String msg = intres.getLocalizedMessage("ocsp.unknownmethod", method);
				m_log.info(msg);
				throw new MalformedRequestException(msg);
			}
		}
		// Make a final check that we actually received something
		if ((ret == null) || (ret.length == 0)) {
			String msg = intres.getLocalizedMessage("ocsp.emptyreq", remoteAddress);
			m_log.info(msg);
			throw new MalformedRequestException(msg);
		}
		return ret;
	}
	
	/** Performs service of the actual OCSP request, which is contained in reqBytes. 
	 *  
	 *  @param reqBytes the binary OCSP request bytes. This parameter must already have been checked for max or min size. 
	 */
	public void serviceOCSP(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		if (m_log.isTraceEnabled()) {
			m_log.trace(">service()");
		}
        mTransactionID += 1;
		ITransactionLogger transactionLogger;
		IAuditLogger auditLogger;
		Date startTime = new Date();
		if (mDoTransactionLog) {
			transactionLogger = new TransactionLogger();
		} else {
			transactionLogger = new DummyTransactionLogger();	// Ignores everything
		}
		if (mDoAuditLog) {
			auditLogger = new AuditLogger();
		} else {
			auditLogger = new DummyAuditLogger();	// Ignores everything
		}
		String remoteAddress = request.getRemoteAddr();
		auditLogger.paramPut(IAuditLogger.OCSPREQUEST, ""); // No request bytes yet
		auditLogger.paramPut(IAuditLogger.LOG_ID, mTransactionID);
		auditLogger.paramPut(IAuditLogger.SESSION_ID, m_SessionID);
		auditLogger.paramPut(IAuditLogger.CLIENT_IP, remoteAddress);
		transactionLogger.paramPut(ITransactionLogger.LOG_ID, mTransactionID);
		transactionLogger.paramPut(ITransactionLogger.SESSION_ID, m_SessionID);
		transactionLogger.paramPut(ITransactionLogger.CLIENT_IP, remoteAddress);

		try {
			OCSPResp ocspresp = null;
			OCSPRespGenerator res = new OCSPRespGenerator();
			X509Certificate cacert = null; // CA-certificate used to sign response
			try {
				byte[] reqBytes = checkAndGetRequestBytes(request, response);
				auditLogger.paramPut(AuditLogger.OCSPREQUEST, new String (Hex.encode(reqBytes)));
				OCSPReq req = null;
				try {
					req = new OCSPReq(reqBytes);					
				} catch (Exception e) {
					// When not beeing able to parse the request, we want to send a MalformedRequest back
					throw new MalformedRequestException(e);
				}
				if (req.getRequestorName() == null) {
					m_log.debug("Requestorname is null"); 
				} else {
					if (m_log.isDebugEnabled()) {
						m_log.debug("Requestorname is: "+req.getRequestorName().toString());						
					}
					transactionLogger.paramPut(ITransactionLogger.REQ_NAME, req.getRequestorName().toString());
				}
				// Make sure our signature keys are updated
				loadPrivateKeys(m_adm);

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
				if (req.isSigned()) {
					X509Certificate signercert = OCSPUtil.checkRequestSignature(request.getRemoteAddr(), req, m_caCertCache);
					String signercertIssuerName = CertTools.getIssuerDN(signercert);
					BigInteger signercertSerNo = CertTools.getSerialNumber(signercert);
					String signercertSubjectName = CertTools.getSubjectDN(signercert);
					transactionLogger.paramPut(ITransactionLogger.SIGN_ISSUER_NAME_DN, signercertIssuerName);
					transactionLogger.paramPut(ITransactionLogger.SIGN_SERIAL_NO, signercert.getSerialNumber().toByteArray());
					transactionLogger.paramPut(ITransactionLogger.SIGN_SUBJECT_NAME, signercertSubjectName);
					transactionLogger.paramPut(ITransactionLogger.REPLY_TIME, TransactionLogger.REPLY_TIME);
					if (m_reqMustBeSigned) {
						// If it verifies OK, check if it is revoked
						RevokedCertInfo rci = isRevoked(m_adm, CertTools.getIssuerDN(signercert), CertTools.getSerialNumber(signercert));
						// If rci == null it means the certificate does not exist in database, we then treat it as ok,
						// because it may be so that only revoked certificates is in the (external) OCSP database.
						if ((rci != null) && rci.isRevoked()) {
							String serno = signercertSerNo.toString(16);
							String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.revoked", signercertSubjectName, signercertIssuerName, serno);
							m_log.info(infoMsg);
							throw new SignRequestSignatureException(infoMsg);
						}

						if (m_reqRestrictSignatures) {
							loadTrustDir();
							if ( m_reqRestrictMethod == RESTRICTONSIGNER) {
								if (!OCSPUtil.checkCertInList(signercert, mTrustedReqSigSigners)) {
									String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName, signercertSerNo.toString(16));
									m_log.info(infoMsg);
									throw new SignRequestSignatureException(infoMsg);
								}
							} else if (m_reqRestrictMethod == RESTRICTONISSUER) {
								X509Certificate signerca = m_caCertCache.findLatestBySubjectDN(signercertIssuerName);
								if ((signerca == null) || (!OCSPUtil.checkCertInList(signerca, mTrustedReqSigIssuers)) ) {
									String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName, signercertSerNo.toString(16));
									m_log.info(infoMsg);
									throw new SignRequestSignatureException(infoMsg);
								}
							} else {
								throw new Exception("m_reqRestrictMethod="+m_reqRestrictMethod); // there must be an internal error. We do not want to send a response, just to be safe.
							}
						}
					}
				} else {
					if (m_reqMustBeSigned) {
						// Signature required
						throw new SignRequestException("Signature required");
					}
				}
				
				// Get the certificate status requests that are inside this OCSP req
				Req[] requests = req.getRequestList();
				transactionLogger.paramPut(ITransactionLogger.NUM_CERT_ID, requests.length);
				if (requests.length <= 0) {
					String infoMsg = intres.getLocalizedMessage("ocsp.errornoreqentities");
					m_log.info(infoMsg);
					{
						// All this just so we can create an error response
						cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
					}
					throw new MalformedRequestException(infoMsg);
				}
				int maxRequests = 100;
				if (requests.length > maxRequests) {
					String infoMsg = intres.getLocalizedMessage("ocsp.errortoomanyreqentities", maxRequests);
					m_log.info(infoMsg);
					{
						// All this just so we can create an error response
						cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
					}
					throw new MalformedRequestException(infoMsg);
				}

				if (m_log.isDebugEnabled()) {
					m_log.debug("The OCSP request contains " + requests.length + " simpleRequests.");
				}

				// Add standard response extensions
				Hashtable responseExtensions = OCSPUtil.getStandardResponseExtensions(req);
            	transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
            	auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
				// Look over the status requests
				ArrayList responseList = new ArrayList();
				for (int i = 0; i < requests.length; i++) {
					CertificateID certId = requests[i].getCertID();
					// now some Logging
					transactionLogger.paramPut(ITransactionLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
					transactionLogger.paramPut(ITransactionLogger.DIGEST_ALGOR, certId.getHashAlgOID()); //todo, find text version of this or find out if it should be something else                    
					transactionLogger.paramPut(ITransactionLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
					transactionLogger.paramPut(ITransactionLogger.ISSUER_KEY, certId.getIssuerKeyHash());
					auditLogger.paramPut(IAuditLogger.ISSUER_KEY, certId.getIssuerKeyHash());
					auditLogger.paramPut(IAuditLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
					auditLogger.paramPut(IAuditLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
 					byte[] hashbytes = certId.getIssuerNameHash();
					String hash = null;
					if (hashbytes != null) {
						hash = new String(Hex.encode(hashbytes));                    	
					}
					String infoMsg = intres.getLocalizedMessage("ocsp.inforeceivedrequest", certId.getSerialNumber().toString(16), hash, request.getRemoteAddr());
					m_log.info(infoMsg);
					boolean unknownCA = false; 
					// if the certId was issued by an unknown CA
					// The algorithm here:
					// We will sign the response with the CA that issued the first 
					// certificate(certId) in the request. If the issuing CA is not available
					// on this server, we sign the response with the default responderId (from params in web.xml).
					// We have to look up the ca-certificate for each certId in the request though, as we will check
					// for revocation on the ca-cert as well when checking for revocation on the certId. 
					cacert = m_caCertCache.findByHash(certId);
					if (cacert == null) {
						// We could not find certificate for this request so get certificate for default responder
						cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
						unknownCA = true;
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
						responseList.add(new OCSPResponseItem(certId, new UnknownStatus(), untilNextUpdate));
						transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_UNKNOWN); 
						transactionLogger.writeln();
						continue;
					} else {
						transactionLogger.paramPut(ITransactionLogger.ISSUER_NAME_DN, cacert.getSubjectDN().getName());
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
					// Check if the cacert (or the default responderid) is revoked
					rci = isRevoked(m_adm, CertTools.getIssuerDN(cacert), CertTools.getSerialNumber(cacert));
					if (null != rci && rci.getReason() == RevokedCertInfo.NOT_REVOKED) {
						rci = null;
					}
					CertificateStatus certStatus = null; // null means good
					transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); // it seems to be correct
					if (null == rci) {
						// Check if cert is revoked
						rci = isRevoked(m_adm, cacert.getSubjectDN().getName(), certId.getSerialNumber());
						if (null == rci) {
							// No revocation info available for this cert, handle it
							if (m_log.isDebugEnabled()) {
								m_log.debug("Unable to find revocation information for certificate with serial '"
										+ certId.getSerialNumber().toString(16) + "'"
										+ " from issuer '" + cacert.getSubjectDN().getName() + "'");                                
							}
							String status = "good";
							certStatus = null; // null means "good" in OCSP
							transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); 
							// If we do not treat non existing certificates as good 
							// OR
							// we don't actually handle requests for the CA issuing the certificate asked about
							// then we return unknown
							if ( (!m_nonExistingIsGood) || (m_caCertCache.findByHash(certId) == null) ) {
								status = "unknown";
								certStatus = new UnknownStatus();
								transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_UNKNOWN);
							}
							infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
							m_log.info(infoMsg);
							responseList.add(new OCSPResponseItem(certId, certStatus, untilNextUpdate));
							transactionLogger.writeln();
						} else {
							// Revocation info available for this cert, handle it
							if (rci.getReason() != RevokedCertInfo.NOT_REVOKED) {
								certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
										new CRLReason(rci.getReason())));
								transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED); //1 = revoked
							} else {
								certStatus = null;
							}
							String status = "good";
							transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); 
							if (certStatus != null) {
								status ="revoked";
								transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED); //1 = revoked
							}
							infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
							m_log.info(infoMsg);
							responseList.add(new OCSPResponseItem(certId, certStatus, untilNextUpdate));
							transactionLogger.writeln();
						}
					} else {
						certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
								new CRLReason(rci.getReason())));
						infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "revoked", certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
						m_log.info(infoMsg);
						responseList.add(new OCSPResponseItem(certId, certStatus, untilNextUpdate));
						transactionLogger.paramPut(ITransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED);
						transactionLogger.writeln();
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
				} // end of huge for loop
				if (cacert != null) {
					// Add responseExtensions
					X509Extensions exts = new X509Extensions(responseExtensions);
					// generate the signed response object
					BasicOCSPResp basicresp = signOCSPResponse(req, responseList, exts, cacert);
					ocspresp = res.generate(OCSPRespGenerator.SUCCESSFUL, basicresp);
					auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
					transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
				} else {
					// Only unknown CAs in requests and no default reponders cert 
					String errMsg = intres.getLocalizedMessage("ocsp.errornocacreateresp");
					m_log.error(errMsg);
					throw new ServletException(errMsg);
				}
			} catch (MalformedRequestException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
				m_log.info(errMsg);
				if (m_log.isDebugEnabled()) {
					m_log.debug(errMsg, e);
				}
				ocspresp = res.generate(OCSPRespGenerator.MALFORMED_REQUEST, null);	// RFC 2560: responseBytes are not set on error.
				transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
				transactionLogger.writeln();
				auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
			} catch (SignRequestException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
				m_log.info(errMsg); // No need to log the full exception here
				ocspresp = res.generate(OCSPRespGenerator.SIG_REQUIRED, null);	// RFC 2560: responseBytes are not set on error.
				transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.SIG_REQUIRED);
				transactionLogger.writeln();
				auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.SIG_REQUIRED);
			} catch (SignRequestSignatureException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
				m_log.info(errMsg); // No need to log the full exception here
				ocspresp = res.generate(OCSPRespGenerator.UNAUTHORIZED, null);	// RFC 2560: responseBytes are not set on error.
				transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				transactionLogger.writeln();
				auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
			} catch (InvalidKeyException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
				m_log.info(errMsg, e);
				ocspresp = res.generate(OCSPRespGenerator.UNAUTHORIZED, null);	// RFC 2560: responseBytes are not set on error.
				transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				transactionLogger.writeln();
				auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
			} catch (Throwable e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
				m_log.error(errMsg, e);
				ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, null);	// RFC 2560: responseBytes are not set on error.
				transactionLogger.paramPut(ITransactionLogger.STATUS, OCSPRespGenerator.INTERNAL_ERROR);
				transactionLogger.writeln();
				auditLogger.paramPut(IAuditLogger.STATUS, OCSPRespGenerator.INTERNAL_ERROR);
			}
			byte[] respBytes = ocspresp.getEncoded();
			auditLogger.paramPut(IAuditLogger.OCSPRESPONSE, new String (Hex.encode(respBytes)));
			auditLogger.paramPut(IAuditLogger.REPLY_TIME, String.valueOf( new Date().getTime() - startTime.getTime() ));
			auditLogger.writeln();
			auditLogger.flush();
			transactionLogger.flush(String.valueOf( new Date().getTime() - startTime.getTime() ));
			if (mDoSaferLogging){
				// See if the Errorhandler has found any problems
				if (hasErrorHandlerFailedSince(startTime)) {
					m_log.info("ProbableErrorhandler reported error, cannot answer request");
					ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, null);	// RFC 2560: responseBytes are not set on error.
					respBytes = ocspresp.getEncoded();
				}
				// See if the Appender has reported any problems
				if (!canlog) {
					m_log.info("SaferDailyRollingFileAppender reported error, cannot answer request");
					ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, null);	// RFC 2560: responseBytes are not set on error.
					respBytes = ocspresp.getEncoded();
				}
			}
			response.setContentType("application/ocsp-response");
			//response.setHeader("Content-transfer-encoding", "binary");
			response.setContentLength(respBytes.length);
			addRfc5019CacheHeaders(request, response, ocspresp, maxAge);
			response.getOutputStream().write(respBytes);
			response.getOutputStream().flush();
		} catch (OCSPException e) {
			String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
			m_log.error(errMsg, e);
			throw new ServletException(e);
		} catch (Exception e ) {
			m_log.error("", e);
			transactionLogger.flush();
			auditLogger.flush();
		}
		if (m_log.isTraceEnabled()) {
			m_log.trace("<service()");
		}
	}

	/**
	 * RFC 2560 does not specify how cache headers should be used, but RFC 5019 does. Therefore we will only
	 * add the headers if the requirements of RFC 5019 is fulfilled: A GET-request, a single embedded reponse,
	 * the response contains a nextUpdate and no nonce is present.
	 * @param maxAge is the margin to Expire when using max-age in milliseconds 
	 */
	private void addRfc5019CacheHeaders(HttpServletRequest request, HttpServletResponse response, OCSPResp ocspresp, long maxAge) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
		if (maxAge <= 0) {
			m_log.debug("Will not add RFC 5019 caches headers: RFC 5019 6.2: max-age should be 'later than thisUpdate but earlier than nextUpdate'.");
			return;
		}
		if (!"GET".equalsIgnoreCase(request.getMethod())) {
			m_log.debug("Will not add RFC 5019 caches headers: \"clients MUST use the GET method (to enable OCSP response caching)\"");
			return;
		}
		if (ocspresp.getResponseObject() == null) {
			m_log.debug("Will not add cache headers for response to bad request.");
			return;
		}
		SingleResp[] singleRespones = ((BasicOCSPResp) ocspresp.getResponseObject()).getResponses();
		if (singleRespones.length != 1) {
			m_log.debug("Will not add RFC 5019 caches headers: reponse contains multiple embedded responses.");
			return;
		}
		if (singleRespones[0].getNextUpdate() == null) {
			m_log.debug("Will not add RFC 5019 caches headers: nextUpdate isn't set.");
			return;
		}
		if (singleRespones[0].getSingleExtensions() != null && singleRespones[0].getSingleExtensions().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) == null) {
			m_log.debug("Will not add RFC 5019 caches headers: response contains a nonce.");
			return;
		}
		long now = new Date().getTime();
		//long producedAt = ((BasicOCSPResp) ocspresp.getResponseObject()).getProducedAt().getTime();
		long nextUpdate = singleRespones[0].getNextUpdate().getTime();
		long thisUpdate = singleRespones[0].getThisUpdate().getTime();
		if (maxAge >= (nextUpdate - thisUpdate)) {
			maxAge = nextUpdate - thisUpdate - 1;
			m_log.warn(intres.getLocalizedMessage("ocsp.shrinkmaxage", maxAge));
		}
		// RFC 5019 6.2: Date: The date and time at which the OCSP server generated the HTTP response.
		// On JBoss AS the "Date"-header is cached for 1 second, so this value will be overwritten and off by up to a second 
		response.setDateHeader("Date", now);
		// RFC 5019 6.2: Last-Modified: date and time at which the OCSP responder last modified the response. == thisUpdate
		response.setDateHeader("Last-Modified", thisUpdate);
		// RFC 5019 6.2: Expires: This date and time will be the same as the nextUpdate timestamp in the OCSP response itself.
		response.setDateHeader("Expires", nextUpdate);	// This is overridden by max-age on HTTP/1.1 compatible components
		// RFC 5019 6.2: This profile RECOMMENDS that the ETag value be the ASCII HEX representation of the SHA1 hash of the OCSPResponse structure.
		response.setHeader("ETag", "\"" + new String(Hex.encode(MessageDigest.getInstance("SHA-1", "BC").digest(ocspresp.getEncoded()))) + "\"");
		response.setHeader("Cache-Control", "max-age=" + (maxAge/1000) + ",public,no-transform,must-revalidate");
	}
} // OCSPServlet
