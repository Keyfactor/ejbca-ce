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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
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
import org.ejbca.core.protocol.ocsp.IOCSPExtension;
import org.ejbca.core.protocol.ocsp.ISaferAppenderListener;
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
 * @author Thomas Meckel (Ophios GmbH), Tomas Gustavsson, Lars Silven
 * @version  $Id$
 */
public abstract class OCSPServletBase extends HttpServlet implements ISaferAppenderListener { 

	private static final Logger m_log = Logger.getLogger(OCSPServletBase.class);
	private static final int RESTRICTONISSUER = 0;
	private static final int RESTRICTONSIGNER = 1;
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

	abstract protected void loadPrivateKeys(Admin adm) throws Exception;

	abstract protected Certificate findCertificateByIssuerAndSerno(Admin adm, String issuerDN, BigInteger serno);

	abstract protected OCSPCAServiceResponse extendedService(Admin m_adm2, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

	abstract protected RevokedCertInfo isRevoked(Admin m_adm2, String name, BigInteger serialNumber);

	/** returns a CertificateCache of appropriate type */
	abstract protected CertificateCache createCertificateCache(Properties prop);

	/** Generates an EJBCA caid from a CA certificate, or looks up the default responder certificate.
	 * 
	 * @param cacert the CA certificate to get the CAid from. If this is null, the default responder CA cert  is looked up and used
	 * @return int 
	 */
	protected int getCaid( X509Certificate cacert ) {
		X509Certificate cert = cacert;
		if (cacert == null) {
			m_log.debug("No correct CA-certificate available to sign response, signing with default CA: "+m_defaultResponderId);
			cert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);    		
		}

		int result = CertTools.stringToBCDNString(cert.getSubjectDN().toString()).hashCode();
		m_log.debug( cert.getSubjectDN() + " has caid: " + result );
		return result;
	}


	private BasicOCSPResp signOCSPResponse(OCSPReq req, ArrayList responseList, X509Extensions exts, X509Certificate cacert)
	throws CADoesntExistsException, ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {

		BasicOCSPResp retval = null;
		{
			// Call extended CA services to get our OCSP stuff
			OCSPCAServiceRequest ocspservicerequest = new OCSPCAServiceRequest(req, responseList, exts, m_sigAlg, m_useCASigningCert, m_includeChain);
			ocspservicerequest.setRespIdType(m_respIdType);
			OCSPCAServiceResponse caserviceresp = extendedService(m_adm, getCaid(cacert), ocspservicerequest);
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
                Method method = implClass.getMethod("addSubscriber", ISaferAppenderListener.class);
                method.invoke(null, this); // first object parameter can be null because this is a static method
                m_log.info("added us as subscriber to org.ejbca.appserver.jboss.SaferDailyRollingFileAppender");
                // create the method object of the static probeable error handler, so we don't have to do this every tim we log
    			Class errHandlerClass = Class.forName(PROBEABLE_ERRORHANDLER_CLASS);
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
	 * @return true or false
	 */
	private boolean hasErrorHandlerFailedSince(Date startTime) {
		boolean ret = false; // Default value false if something goes wrong
		try {
			Boolean b = (Boolean)m_errorHandlerMethod.invoke(null, startTime); // first object parameter can be null because this is a static method
			ret = b.booleanValue();
		} catch (SecurityException e) {
			m_log.error(e);
		} catch (IllegalArgumentException e) {
			m_log.error(e);
		} catch (IllegalAccessException e) {
			m_log.error(e);
		} catch (InvocationTargetException e) {
			m_log.error(e);
		}
		return ret;
	}
	
	public void doPost(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		m_log.trace(">doPost()");
		String contentType = request.getHeader("Content-Type");
		if (!contentType.equalsIgnoreCase("application/ocsp-request")) {
			m_log.debug("Content type is not application/ocsp-request");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Content type is not application/ocsp-request");
			return;
		}
		// Get the request data
		
		m_log.debug("Received request of length: "+request.getContentLength());
        ServletInputStream in = request.getInputStream();
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
		m_log.trace("<doPost()");
	} //doPost

	public void doGet(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		m_log.trace(">doGet()");
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
				// Reload CA certificates
				m_caCertCache.forceReload();
				try {
					// Also reloas signing keys
					mKeysValidTo = 0;
					loadPrivateKeys(m_adm);
				} catch (Exception e) {
					m_log.error(e);
					throw new ServletException(e);
				}
			} else {
				m_log.info("Got reloadKeys command from unauthorized ip: "+remote);
			}
		}
		response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "OCSP only supports POST");
		m_log.trace("<doGet()");
	} // doGet

	public void service(HttpServletRequest request, HttpServletResponse response, byte[] reqBytes)
	throws IOException, ServletException {
		if (m_log.isTraceEnabled()) {
			m_log.trace(">service()");
		}
        mTransactionID += 1;
		TransactionLogger transactionLogger = null;
		AuditLogger auditLogger = null;
		Date startTime = new Date();
		if (mDoTransactionLog) transactionLogger = new TransactionLogger();
		if (mDoAuditLog)  auditLogger = new AuditLogger();
		String transactionID = GUIDGenerator.generateGUID(this);
		if (auditLogger != null) auditLogger.paramPut(AuditLogger.OCSPREQUEST, new String (Hex.encode(reqBytes)));
		if (auditLogger != null) auditLogger.paramPut(AuditLogger.LOG_ID, mTransactionID);
		if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.LOG_ID, mTransactionID);
		if (auditLogger != null) auditLogger.paramPut(AuditLogger.SESSION_ID, m_SessionID);
		if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.SESSION_ID, m_SessionID);
		//audit.paramPut(TransactionLogger.DIGEST_ALGOR, m_sigAlg); //Algorithm used by server to generate signature on OCSP responses
		String remoteAddress = request.getRemoteAddr();
		if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CLIENT_IP, remoteAddress);
		if (auditLogger != null) auditLogger.paramPut(AuditLogger.CLIENT_IP, remoteAddress);
		if ((reqBytes == null) || (reqBytes.length == 0)) {
			m_log.info("No request bytes from ip: "+remoteAddress);
			if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
			if (transactionLogger != null) transactionLogger.writeln();
			if (transactionLogger != null) transactionLogger.flush();
			if (auditLogger != null) auditLogger.paramPut(auditLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
			if (auditLogger != null) auditLogger.flush();
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
			try {
				OCSPReq req = null;
				try {
					req = new OCSPReq(reqBytes);					
				} catch (Exception e) {
					// When not beeing able to parse the request, we want to send a MalformedRequest back
					throw new MalformedRequestException(e);
				}
				if (null== req.getRequestorName()) {
					m_log.debug("Requestorname is null"); 
				} else {
					if (m_log.isDebugEnabled()) {
						m_log.debug("Requestorname is: "+req.getRequestorName().toString());						
					}
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.REQ_NAME, req.getRequestorName().toString());
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
					String signercertIssuerName = signercert.getIssuerDN().getName();
					BigInteger signercertSerNo = signercert.getSerialNumber();
					String signercertSubjectName = signercert.getSubjectDN().getName();
					if (transactionLogger != null ) transactionLogger.paramPut(TransactionLogger.SIGN_ISSUER_NAME_DN, signercertIssuerName);
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.SIGN_SERIAL_NO, new String(Hex.encode(signercert.getSerialNumber().toByteArray())));
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.SIGN_SUBJECT_NAME, signercertSubjectName);
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.REPLY_TIME, TransactionLogger.REPLY_TIME);
					if (m_reqMustBeSigned) {
						// If it verifies OK, check if it is revoked
						RevokedCertInfo rci = isRevoked(m_adm, signercert.getIssuerDN().getName(), signercert.getSerialNumber());
						// If rci == null it means the certificate does not exist in database, we then treat it as ok,
						// because it may be so that only revoked certificates is in the (external) OCSP database.
						if ((rci != null) && rci.isRevoked()) {
							String serno = signercertSerNo.toString(16);
							String errMsg = intres.getLocalizedMessage("ocsp.infosigner.revoked", signercertSubjectName, signercertIssuerName, serno);
							m_log.error(errMsg);
							throw new SignRequestSignatureException(errMsg);
						}

						if (m_reqRestrictSignatures) {
							loadTrustDir();
							if ( m_reqRestrictMethod == RESTRICTONSIGNER) {
								if (!OCSPUtil.checkCertInList(signercert, mTrustedReqSigSigners)) {
									String errMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName, signercertSerNo.toString(16));
									m_log.error(errMsg);
									throw new SignRequestSignatureException(errMsg);
								}
							} else if (m_reqRestrictMethod == RESTRICTONISSUER) {
								X509Certificate signerca = m_caCertCache.findLatestBySubjectDN(signercertIssuerName);
								if ((signerca == null) || (!OCSPUtil.checkCertInList(signerca, mTrustedReqSigIssuers)) ) {
									String errMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName, signercertSerNo.toString(16));
									m_log.error(errMsg);
									throw new SignRequestSignatureException(errMsg);
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
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.NUM_CERT_ID, requests.length);
				if (requests.length <= 0) {
					String errMsg = intres.getLocalizedMessage("ocsp.errornoreqentities");
					m_log.error(errMsg);
					{
						// All this just so we can create an error response
						cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
					}
					throw new MalformedRequestException(errMsg);
				}
				int maxRequests = 100;
				if (requests.length > maxRequests) {
					String errMsg = intres.getLocalizedMessage("ocsp.errortoomanyreqentities", maxRequests);
					m_log.error(errMsg);
					{
						// All this just so we can create an error response
						cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
					}
					throw new MalformedRequestException(errMsg);
				}

				if (m_log.isDebugEnabled()) {
					m_log.debug("The OCSP request contains " + requests.length + " simpleRequests.");
				}

				// Add standard response extensions
				Hashtable responseExtensions = OCSPUtil.getStandardResponseExtensions(req);
                if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
                if (auditLogger!= null) auditLogger.paramPut(auditLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
				// Look over the status requests
				ArrayList responseList = new ArrayList();
				for (int i = 0; i < requests.length; i++) {
					CertificateID certId = requests[i].getCertID();
					// now some Logging
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.SERIAL_NOHEX, new String( Hex.encode(certId.getSerialNumber().toByteArray())));
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.DIGEST_ALGOR, certId.getHashAlgOID()); //todo, find text version of this or find out if it should be something else                    
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_HASH, new String( new String( Hex.encode(certId.getIssuerNameHash()))));
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.ISSUER_KEY,new String(Hex.encode(certId.getIssuerKeyHash())));
					if (auditLogger != null) auditLogger.paramPut(AuditLogger.SERIAL_NOHEX, new String( Hex.encode(certId.getSerialNumber().toByteArray())));
					if (auditLogger != null) auditLogger.paramPut(AuditLogger.ISSUER_NAME_HASH, new String( new String( Hex.encode(certId.getIssuerNameHash()))));
					if (auditLogger != null) auditLogger.paramPut(AuditLogger.ISSUER_KEY,new String(Hex.encode(certId.getIssuerKeyHash())));
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
					try {
						cacert = m_caCertCache.findByHash(certId);
						if (cacert == null) {
							// We could not find certificate for this request so get certificate for default responder
							cacert = m_caCertCache.findLatestBySubjectDN(m_defaultResponderId);
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
						if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_UNKNOWN); 
						if (transactionLogger != null) transactionLogger.writeln();
						continue;
					} else {
						if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN, cacert.getSubjectDN().getName());
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
					CertificateStatus certStatus = null; // null means good
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); // it seems to be correct

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
							if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); 
							// If we do not treat non existing certificates as good 
							// OR
							// we don't actually handle requests for the CA issuing the certificate asked about
							// then we return unknown
							if ( (!m_nonExistingIsGood) || (m_caCertCache.findByHash(certId) == null) ) {
								status = "unknown";
								certStatus = new UnknownStatus();
								if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_UNKNOWN);
							}
							infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
							m_log.info(infoMsg);
							responseList.add(new OCSPResponseItem(certId, certStatus));
							if (transactionLogger != null) transactionLogger.writeln();
							//  if (account != null) account.writeln();
						} else {
							BigInteger rciSerno = rci.getUserCertificate(); 
							if (rciSerno.compareTo(certId.getSerialNumber()) == 0) {
								if (rci.getReason() != RevokedCertInfo.NOT_REVOKED) {
									certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
											new CRLReason(rci.getReason())));
									if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED); //1 = revoked
								} else {
									certStatus = null;
								}
								String status = "good";
								if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_GOOD); 
								if (certStatus != null) {
									status ="revoked";
									if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED); //1 = revoked
								}
								infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", status, certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());

								m_log.info(infoMsg);
								responseList.add(new OCSPResponseItem(certId, certStatus));
								if (transactionLogger != null) transactionLogger.writeln();
							} else {
								m_log.error("ERROR: Certificate serialNumber ("+rciSerno.toString(16)+") in response from database does not match request ("
										+certId.getSerialNumber().toString(16)+").");
								infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "unknown", certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
								m_log.info(infoMsg);
								if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_UNKNOWN); 
								if (transactionLogger != null) transactionLogger.writeln();
								responseList.add(new OCSPResponseItem(certId, new UnknownStatus()));                		
							}
						}
					} else {
						certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(rci.getRevocationDate()),
								new CRLReason(rci.getReason())));
						infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "revoked", certId.getSerialNumber().toString(16), cacert.getSubjectDN().getName());
						m_log.info(infoMsg);
						responseList.add(new OCSPResponseItem(certId, certStatus));
						if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPUnidResponse.OCSP_REVOKED);
						if (transactionLogger != null) transactionLogger.writeln();
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
				if ((req != null) && (cacert != null)) {
					// Add responseExtensions
					X509Extensions exts = new X509Extensions(responseExtensions);
					// generate the signed response object
					BasicOCSPResp basicresp = signOCSPResponse(req, responseList, exts, cacert);
					ocspresp = res.generate(OCSPRespGenerator.SUCCESSFUL, basicresp);
					if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
					if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.SUCCESSFUL);
				} else {
					String errMsg = intres.getLocalizedMessage("ocsp.errornocacreateresp");
					m_log.error(errMsg);
					throw new ServletException(errMsg);
				}
			} catch (MalformedRequestException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
				m_log.info(errMsg, e);
				ocspresp = res.generate(OCSPRespGenerator.MALFORMED_REQUEST, null);	// RFC 2560: responseBytes are not set on error.
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
				if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.MALFORMED_REQUEST);
				if (transactionLogger != null) transactionLogger.writeln();
			} catch (SignRequestException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
				m_log.info(errMsg); // No need to log the full exception here
				ocspresp = res.generate(OCSPRespGenerator.SIG_REQUIRED, null);	// RFC 2560: responseBytes are not set on error.
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.SIG_REQUIRED);
				if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.SIG_REQUIRED);
				if (transactionLogger != null) transactionLogger.writeln();
			} catch (SignRequestSignatureException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
				m_log.info(errMsg); // No need to log the full exception here
				ocspresp = res.generate(OCSPRespGenerator.UNAUTHORIZED, null);	// RFC 2560: responseBytes are not set on error.
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				if (transactionLogger != null) transactionLogger.writeln();
			} catch (InvalidKeyException e) {
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
				m_log.info(errMsg, e);
				ocspresp = res.generate(OCSPRespGenerator.UNAUTHORIZED, null);	// RFC 2560: responseBytes are not set on error.
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.UNAUTHORIZED);
				if (transactionLogger != null) transactionLogger.writeln();
			} catch (Exception e) {
				if (e instanceof ServletException)
					throw (ServletException) e;
				String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
				m_log.error(errMsg, e);
				ocspresp = res.generate(OCSPRespGenerator.INTERNAL_ERROR, null);	// RFC 2560: responseBytes are not set on error.
				if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespGenerator.INTERNAL_ERROR);
				if (transactionLogger != null) transactionLogger.writeln();
				if (auditLogger != null) auditLogger.paramPut(AuditLogger.STATUS, OCSPRespGenerator.INTERNAL_ERROR);
			}
			byte[] respBytes = ocspresp.getEncoded();
			
			if (auditLogger != null) auditLogger.paramPut(AuditLogger.OCSPRESPONSE, new String (Hex.encode(respBytes)));
			if (auditLogger != null) auditLogger.paramPut(AuditLogger.REPLY_TIME, String.valueOf( new Date().getTime() - startTime.getTime() ));
			//if (transactionLogger != null) transactionLogger.paramPut(TransactionLogger.REPLY_TIME, String.valueOf( new Date().getTime() - startTime.getTime() ));
			if (auditLogger != null) auditLogger.writeln();
			if (transactionLogger != null) transactionLogger.flush(String.valueOf( new Date().getTime() - startTime.getTime() ));
			if (auditLogger != null) auditLogger.flush();
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
			response.getOutputStream().write(respBytes);
			response.getOutputStream().flush();
		} catch (OCSPException e) {
			String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq");
			m_log.error(errMsg, e);
			throw new ServletException(e);
		} catch (Exception e ) {
			m_log.error(e);
			if (transactionLogger != null) transactionLogger.flush();
			if (auditLogger != null) auditLogger.flush();
		}
		if (m_log.isTraceEnabled()) {
			m_log.trace("<service()");
		}
	}
} // OCSPServlet
