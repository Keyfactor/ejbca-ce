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

package org.ejbca.core.ejb.ca.caadmin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.NotSupportedException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.CVCCA;
import org.ejbca.core.model.ca.caadmin.CVCCAInfo;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenContainerImpl;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.HardCATokenInfo;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.ca.catoken.NullCATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.util.AlgorithmTools;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.core.protocol.ocsp.CertificateCacheInternal;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SimpleTime;
import org.ejbca.util.StringTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;



/**
 * Administrates and manages CAs in EJBCA system.
 *
 * @version $Id$
 *
 * @ejb.bean description="Session bean handling core CA function,signing certificates"
 *   display-name="CAAdminSB"
 *   name="CAAdminSession"
 *   jndi-name="CAAdminSession"
 *   local-jndi-name="CAAdminSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 * 
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 *  name="DataSource"
 *  type="java.lang.String"
 *  value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   remote-class="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   remote-class="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *
 * @ejb.ejb-external-ref description="The CA entity bean"
 *   view-type="local"
 *   ref-name="ejb/CADataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.caadmin.CADataLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.CADataLocal"
 *   link="CAData"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref description="The Approval Session Bean"
 *   view-type="local"
 *   ref-name="ejb/ApprovalSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *   business="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *   link="ApprovalSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The CRL Create bean"
 *   view-type="local"
 *   ref-name="ejb/CreateCRLSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *   link="CreateCRLSession"
 *   
 * @ejb.ejb-external-ref description="Publishers are configured to store certificates and CRLs in additional places
 * from the main database. Publishers runs as local beans"
 *   view-type="local"
 *   ref-name="ejb/PublisherSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal"
 *   link="PublisherSession"
 *
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "verify*"
 *   read-only = "true"
 *
 */
public class CAAdminSessionBean extends BaseSessionBean {

    /** The local home interface of CAData.*/
    private CADataLocalHome cadatahome;

    /** The local interface of the log session bean */
    private ILogSessionLocal logsession;

    /** The local interface of the authorization session bean */
    private IAuthorizationSessionLocal authorizationsession;

    /** The local interface of the certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession;

    /** The local interface of the job runner session bean used to create crls.*/
    private ICreateCRLSessionLocal crlsession;

    private IPublisherSessionLocal publisherSession;

    /** The local interface of the approval session bean */
    private IApprovalSessionLocal approvalsession;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Caching of CA IDs with CA cert hash as ID
     */
    private final Map caCertToCaId = new HashMap();

    private IApprovalSessionLocal getApprovalSession(){
    	if(approvalsession == null){
    		try {
    			IApprovalSessionLocalHome approvalsessionhome = (IApprovalSessionLocalHome) getLocator().getLocalHome(IApprovalSessionLocalHome.COMP_NAME);
    			approvalsession = approvalsessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}  
    	}
    	return approvalsession;
    }
    
    private IPublisherSessionLocal getPublisherSession(){
    	if(publisherSession == null){
    		try {
    			IPublisherSessionLocalHome home = (IPublisherSessionLocalHome) getLocator().getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
    			publisherSession = home.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}  
    	}
    	return publisherSession;
    }

    /** Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
            try{
                ILogSessionLocalHome home = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = home.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return logsession;
    }


    /** Gets connection to authorization session bean
     * @return Connection
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if(authorizationsession == null){
            try{
                IAuthorizationSessionLocalHome home = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = home.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession

    /** Gets connection to crl create session bean
     * @return Connection
     */
    private ICreateCRLSessionLocal getCRLCreateSession() {
    	if(crlsession == null){
    		try{
    			ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) getLocator().getLocalHome(ICreateCRLSessionLocalHome.COMP_NAME);
    			crlsession = home.create();
    		}catch(Exception e){
    			throw new EJBException(e);
    		}
    	}
    	return crlsession;
    }

    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
    	if(certificatestoresession == null){
    		try{
    			ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    			certificatestoresession = home.create();
    		}catch(Exception e){
    			throw new EJBException(e);
    		}
    	}
    	return certificatestoresession;
    }

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        cadatahome = (CADataLocalHome)getLocator().getLocalHome(CADataLocalHome.COMP_NAME);
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }


    /**
     * A method designed to be called at startuptime to speed up the (next) first request to a CA.
     * This method will initialize the CA-cache with all CAs, if they are not already in the cache.
     * Can have a side-effect of upgrading a CA, therefore the Required transaction setting.
     * 
     * @param admin administrator calling the method
     * 
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    public void initializeAndUpgradeCAs(Admin admin) {
    	try {
    		Collection result = cadatahome.findAll();
    		Iterator iter = result.iterator();
    		while(iter.hasNext()){
    			CADataLocal cadata = (CADataLocal) iter.next();
    			String caname = cadata.getName();
    			try {
    				cadata.upgradeCA();
    				log.info("Initialized CA: "+caname+", with expire time: "+new Date(cadata.getExpireTime()));
    			} catch (UnsupportedEncodingException e) {
    				log.error("UnsupportedEncodingException trying to load CA with name: "+caname, e);
    			} catch (IllegalKeyStoreException e) {
    				log.error("IllegalKeyStoreException trying to load CA with name: "+caname, e);
    			}
    		}
    	} catch (FinderException e) {
    		log.error("FinderException trying to load CAs: ", e);
    	}
    }
    
    /**
     * Method used to create a new CA.
     *
     * The cainfo parameter should at least contain the following information.
     *   SubjectDN
     *   Name (if null then is subjectDN used).
     *   Validity
     *   a CATokenInfo
     *   Description (optional)
     *   Status (SecConst.CA_ACTIVE or SecConst.CA_WAITING_CERTIFICATE_RESPONSE)
     *   SignedBy (CAInfo.SELFSIGNED, CAInfo.SIGNEDBYEXTERNALCA or CAId of internal CA)    
     *
     *  For other optional values see:
     *  @see org.ejbca.core.model.ca.caadmin.CAInfo
     *  @see org.ejbca.core.model.ca.caadmin.X509CAInfo
     *  
     * @ejb.interface-method
     * @jboss.method-attributes transaction-timeout="900"
     */
    public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException, CATokenOfflineException, CATokenAuthenticationFailedException {
    	int castatus = SecConst.CA_OFFLINE;
        // Check that administrat has superadminsitrator rights.
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException ade){
        	String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", "create", cainfo.getName());
            getLogSession().log (admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, ade);
            throw new AuthorizationDeniedException(msg);
        }
        // Check that CA doesn't already exists
        try{
            int caid = cainfo.getCAId();
            if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
            	String msg = intres.getLocalizedMessage("caadmin.wrongcaid", new Integer(caid));
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
                throw new CAExistsException(msg);
            }
            cadatahome.findByPrimaryKey(new Integer(caid));
        	String msg = intres.getLocalizedMessage("caadmin.caexistsid", new Integer(caid));
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
            throw new CAExistsException(msg);
        }catch(javax.ejb.FinderException fe) {}

        try{
            cadatahome.findByName(cainfo.getName());
        	String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg);
            throw new CAExistsException(msg);
        }catch(javax.ejb.FinderException fe) {}

        // Create CAToken
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo, cainfo.getCAId());
		String authCode = catokeninfo.getAuthenticationCode();
        authCode = getDefaultKeyStorePassIfSWAndEmpty(authCode, catokeninfo);
        if(catokeninfo instanceof SoftCATokenInfo){
        	try{
        		// There are two ways to get the authentication code:
        		// 1. The user provided one when creating the CA on the create CA page
        		// 2. We use the system default password
        		boolean renew = false;
        		catoken.generateKeys(authCode, renew);
        	}catch(Exception e){
        		String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
        		throw new EJBException(e);
        	}
        }
        try{
        	catoken.activate(authCode);
        }catch(CATokenAuthenticationFailedException ctaf){
        	String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");            	
        	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, ctaf);
        	throw ctaf;
        }catch(CATokenOfflineException ctoe){
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
        	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, ctoe);
        	throw ctoe;
        }

        // Create CA
        CA ca = null;
        // The certificate profile used for the CAs certificate
    	CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin,cainfo.getCertificateProfileId());
        // AltName is not implemented for all CA types
    	String caAltName = null;
    	// X509 CA is the normal type of CA
        if (cainfo instanceof X509CAInfo) {
        	log.info("Creating an X509 CA");
        	X509CAInfo x509cainfo = (X509CAInfo) cainfo;
        	// Create X509CA
        	ca = new X509CA(x509cainfo);
        	X509CA x509ca = (X509CA) ca;
        	ca.setCAToken(catoken);

        	// getCertificateProfile
        	if((x509cainfo.getPolicies() != null) && (x509cainfo.getPolicies().size() > 0)) {
        		certprofile.setUseCertificatePolicies(true);
        		certprofile.setCertificatePolicies(x509cainfo.getPolicies());
        	} else if(certprofile.getUseCertificatePolicies()) {
        		x509ca.setPolicies(certprofile.getCertificatePolicies());
        	}
        	caAltName = x509cainfo.getSubjectAltName();
        } else {
        	// CVC CA is a special type of CA for EAC electronic passports
        	log.info("Creating a CVC CA");
        	CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
        	// Create CVCCA
        	ca = new CVCCA(cvccainfo);
        	ca.setCAToken(catoken);
        }

        // Certificate chain
    	Collection certificatechain = null;
    	String sequence = catoken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
        if(cainfo.getSignedBy() == CAInfo.SELFSIGNED){
        	try{
        		// create selfsigned certificate
        		Certificate cacertificate = null;

        		log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());

        		UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName, null,
        				0,0,0,  cainfo.getCertificateProfileId(), null, null, 0, 0, null);

        		cacertificate = ca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, cainfo.getValidity(), certprofile, sequence);

        		log.debug("CAAdminSessionBean : " + CertTools.getSubjectDN(cacertificate));

        		// Build Certificate Chain
        		certificatechain = new ArrayList();
        		certificatechain.add(cacertificate);

        		// set status to active
        		castatus = SecConst.CA_ACTIVE;
        	}catch(CATokenOfflineException e){
        		String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
        		throw e;
        	}catch(Exception fe){
        		String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, fe);
        		throw new EJBException(fe);
        	}
        }
        if(cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
        	certificatechain = new ArrayList();
        	// set status to waiting certificate response.
        	castatus = SecConst.CA_WAITING_CERTIFICATE_RESPONSE;
        }

        if(cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0){
        	// Create CA signed by other internal CA.
        	try{
        		CADataLocal signcadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getSignedBy()));
        		CA signca = signcadata.getCA();
        		//Check that the signer is valid
        		checkSignerValidity(admin, signcadata);
        		// Create cacertificate
        		Certificate cacertificate = null;

        		UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName, null,
        				0, 0, 0, cainfo.getCertificateProfileId(),null, null, 0, 0, null);

        		cacertificate = signca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(), certprofile, sequence);

        		// Build Certificate Chain
        		Collection rootcachain = signca.getCertificateChain();
        		certificatechain = new ArrayList();
        		certificatechain.add(cacertificate);
        		certificatechain.addAll(rootcachain);
        		// set status to active
        		castatus = SecConst.CA_ACTIVE;
        	}catch(CATokenOfflineException e){
        		String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
        		throw e;
        	}catch(Exception fe){
        		String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, fe);
        		throw new EJBException(fe);
        	}
        }

        // Set Certificate Chain
        ca.setCertificateChain(certificatechain);


        //	Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
        
        if(castatus ==SecConst.CA_ACTIVE){
        	// activate External CA Services
        	activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
        }
        // Store CA in database.
        try{
        	cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), castatus, ca);
        	if(castatus == SecConst.CA_ACTIVE){
                //  create initial CRL
        	    createCRLs(admin, ca, cainfo);
        	}
    		String msg = intres.getLocalizedMessage("caadmin.createdca", cainfo.getName(), new Integer(castatus));            	
        	getLogSession().log(admin, ca.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CACREATED, msg);
        }catch(javax.ejb.CreateException e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
        	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg);
        	throw new EJBException(e);
        }
        // Update local OCSP's CA certificate cache
        CertificateCacheInternal.getInstance().update(ca.getCACertificate());
    } // createCA

    private void createCRLs(Admin admin, CA ca, CAInfo cainfo) throws CATokenOfflineException {
        final String fp = this.getCRLCreateSession().run(admin, ca);
        // If we could not create a full CRL (for example CVC CAs does not even support CRLs), don't try to create a delta CRL.
        if (fp != null) {
            final CRLInfo crlInfo = getCRLCreateSession().getCRLInfo(admin, fp);
            if(cainfo.getDeltaCRLPeriod() > 0) {
                this.getCRLCreateSession().runDeltaCRL(admin, ca, crlInfo.getLastCRLNumber(), crlInfo.getCreateDate().getTime());
            }                   
        }
    }

    /**
     * Method used to edit the data of a CA. 
     * 
     * Not all of the CAs data can be edited after the creation, therefore will only
     * the values from CAInfo that is possible be uppdated. 
     *
     * @param cainfo CAInfo object containing values that will be updated
     * 
     *  For values see:
     *  @see org.ejbca.core.model.ca.caadmin.CAInfo
     *  @see org.ejbca.core.model.ca.caadmin.X509CAInfo
     *  
     * @ejb.interface-method
     */
    public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException{
        boolean xkmsrenewcert = false;
        boolean cmsrenewcert = false;

        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", cainfo.getName());            	
            getLogSession().log(admin, cainfo.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if extended service certificates are about to be renewed.
        Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
        while(iter.hasNext()){
          Object next = iter.next();
    	  // No OCSP Certificate exists that can be renewed.
          if(next instanceof XKMSCAServiceInfo){
              xkmsrenewcert = ((XKMSCAServiceInfo) next).getRenewFlag();
          } else if(next instanceof CmsCAServiceInfo){
              cmsrenewcert = ((CmsCAServiceInfo) next).getRenewFlag();
          }
        }

        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getCAId()));
            CA ca = cadata.getCA();

            // Update CA values
            ca.updateCA(cainfo);
            // Store CA in database
            cadata.setCA(ca);
            // Try to activate the CA token after we have edited the CA
            try{
            	CATokenContainer catoken = ca.getCAToken();
            	CATokenInfo catokeninfo = cainfo.getCATokenInfo();
            	String authCode = catokeninfo.getAuthenticationCode();
                String keystorepass = getDefaultKeyStorePassIfSWAndEmpty(authCode, catokeninfo);
                if (keystorepass != null) {
                	catoken.activate(keystorepass );                	
                } else {
                	log.debug("Not trying to activate CAToken after editing, authCode == null.");
                }
            }catch(CATokenAuthenticationFailedException ctaf){
            	String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");            	
            	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, ctaf);
            }catch(CATokenOfflineException ctoe){
            	String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
            	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, ctoe);
            }
            // No OCSP Certificate exists that can be renewed.
            if(xkmsrenewcert){
           	  XKMSCAServiceInfo info = (XKMSCAServiceInfo)ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE);
              Certificate xkmscert = (Certificate)info.getXKMSSignerCertificatePath().get(0);
  			  ArrayList xkmscertificate = new ArrayList();
  			  xkmscertificate.add(xkmscert);
              // Publish the extended service certificate, but only for active services
              if ( (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!xkmscertificate.isEmpty()) ) {
            	  publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
              }
            }
            if(cmsrenewcert){
              CmsCAServiceInfo info = (CmsCAServiceInfo)ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE);
              Certificate cmscert = (Certificate)info.getCertificatePath().get(0);
  			  ArrayList cmscertificate = new ArrayList();
  			  cmscertificate.add(cmscert);
              // Publish the extended service certificate, but only for active services
              if ( (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!cmscertificate.isEmpty()) ) {
                  publishCACertificate(admin, cmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
              }
            }
            // Log Action
    		String msg = intres.getLocalizedMessage("caadmin.editedca", cainfo.getName());            	
            getLogSession().log(admin, cainfo.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        }catch(Exception fe) {
    		String msg = intres.getLocalizedMessage("caadmin.erroreditca", cainfo.getName());            	
            log.error(msg, fe);
            getLogSession().log(admin, cainfo.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, fe);
            throw new EJBException(fe);
        }
    } // editCA

    /**
     * Method used to remove a CA from the system. 
     *
     * You should first check that the CA isn't used by any EndEntity, Profile or AccessRule
     * before it is removed. CADataHandler for example makes this check. 
     * 
     * Should be used with care. If any certificate has been created with the CA use revokeCA instead
     * and don't remove it.
     * 
     * @ejb.interface-method
     */
    public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException{
        // check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremoveca", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, e);
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            // Remove CA
            cadata.remove();
			// Invalidate CA cache to refresh information
			CACacheManager.instance().removeCA(caid);
            // Remove an eventual CA token from the token registry
            CATokenManager.instance().addCAToken(caid, null);
    		String msg = intres.getLocalizedMessage("caadmin.removedca", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        }catch(Exception e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorremoveca", new Integer(caid), e.getMessage());            	
            log.error(msg, e);
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }
    } // removeCA

    /**
     * Renames the name of CA used in administrators web interface.
     * This name doesn't have to be the same as SubjectDN and is only used for reference.
     * 
     * @ejb.interface-method
     */
    public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException{
        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByName(oldname);
            // Check authorization
            int caid = cadata.getCaId().intValue();
            try{
                getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
            }catch(AuthorizationDeniedException e){
        		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenameca", new Integer(caid));            	
                getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
                throw new AuthorizationDeniedException(msg);
            }

            try{
                CADataLocal cadatanew = cadatahome.findByName(newname);
                cadatanew.getCaId();
                throw new CAExistsException(" CA name " + newname + " already exists.");
            }catch(javax.ejb.FinderException fe) {
                // new CA doesn't exits, it's ok to rename old one.
                cadata.setName(newname);
				// Invalidate CA cache to refresh information
				CACacheManager.instance().removeCA(cadata.getCaId().intValue());
	    		String msg = intres.getLocalizedMessage("caadmin.renamedca", oldname, newname);            	
                getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
            }
        }catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorrenameca", oldname);            	
            log.error(msg, fe);
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
            throw new EJBException(fe);
        }
    } // renamewCA


    /**
     * Returns a value object containing nonsensitive information about a CA give it's name.
     * @param admin administrator calling the method
     * @param name human readable name of CA
     * @return value object
     * @throws CADoesntExistsException if no such CA exists 
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfoOrThrowException(Admin admin, String name) throws CADoesntExistsException {
    	CAInfo caInfo = getCAInfo(admin, name);
    	if (caInfo == null) {
    		String msg = "No CA with name " + name + " was found.";
    		log.debug(msg);
    		throw new CADoesntExistsException(msg);
    	}
    	return caInfo;
    }

    /**
     * Returns a value object containing nonsensitive information about a CA give it's name.
     * @param admin administrator calling the method
     * @param name human readable name of CA
     * @return value object or null if CA does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfo(Admin admin, String name) {
        CAInfo cainfo = null;
        try{
            CADataLocal cadata = cadatahome.findByName(name);
            cainfo = cadata.getCA().getCAInfo();
            if (!authorizedToCA(admin,cainfo.getCAId())) {
            	return null;
            }
            int status = cainfo.getStatus();
            Date expireTime = cainfo.getExpireTime();
            if(status == SecConst.CA_ACTIVE && expireTime.before(new Date())){
                cainfo.setStatus(SecConst.CA_EXPIRED); // update the value object
                cadata.setStatus(SecConst.CA_EXPIRED);
                cadata.setUpdateTime(new Date().getTime());
            }
        } catch(javax.ejb.FinderException fe) {             
            // ignore
            log.debug("Can not find CA with name: '"+name+"'.");
        } catch(Exception e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", name);            	
            log.error(msg, e);
            throw new EJBException(e);
        }
        return cainfo;
    } // getCAInfo


    /**
     * Returns a value object containing nonsensitive information about a CA give it's CAId.
     * 
     * @param admin administrator calling the method
     * @param caid numerical id of CA (subjectDN.hashCode())
     * @return value object
     * @throws CADoesntExistsException if no such CA exists
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfoOrThrowException(Admin admin, int caid) throws CADoesntExistsException{
    	CAInfo caInfo = getCAInfo(admin, caid);
    	if (caInfo == null) {
    		String msg = "No CA with id " + caid + " was found.";
    		log.debug(msg);
    		throw new CADoesntExistsException(msg);
    	}
    	return caInfo;
    }

    /**
     * Returns a value object containing nonsensitive information about a CA give it's CAId.
     * 
     * @param admin administrator calling the method
     * @param caid numerical id of CA (subjectDN.hashCode())
     * @return value object or null if CA does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfo(Admin admin, int caid){
    	// No sign test for the standard method
    	return getCAInfo(admin, caid, false);
    }
    
    /**
     * Returns a value object containing nonsensitive information about a CA give it's CAId.
     * 
     * If doSignTest is true, and the CA is active and the CA is included in healthcheck (cainfo.getIncludeInHealthCheck()), 
     * a signature with the test keys is performed to set the CA Token status correctly.
     * 
     * @param admin administrator calling the method
     * @param caid numerical id of CA (subjectDN.hashCode())
     * @param doSignTest true if a test signature should be performed, false if only the status from token info is checked. Should normally be set to false.
     * @return value object or null if CA does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfo(Admin admin, int caid, boolean doSignTest){
        CAInfo cainfo = null;
        try{
            if (!authorizedToCA(admin,caid)) {
            	return null;
            }
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            CA ca = cadata.getCA();
            String name = ca.getName();
            cainfo = ca.getCAInfo();
            int status = cainfo.getStatus();
            boolean includeInHealthCheck = cainfo.getIncludeInHealthCheck();
            Date expireTime = cainfo.getExpireTime();
            if (status == SecConst.CA_ACTIVE && expireTime.before(new Date())) {
                cainfo.setStatus(SecConst.CA_EXPIRED); // update the value object
                cadata.setStatus(SecConst.CA_EXPIRED);
                cadata.setUpdateTime(new Date().getTime());
            }   
            int tokenstatus = ICAToken.STATUS_OFFLINE;
            if (doSignTest && status == SecConst.CA_ACTIVE && includeInHealthCheck) {
            	// Only do a real test signature if the CA is supposed to be active and if it is included in healthchecking
            	// Otherwise we will only waste resources
            	if (log.isDebugEnabled()) {
                	log.debug("Making test signature with CAs token. CA="+name+", doSignTest="+doSignTest+", CA status="+status+", includeInHealthCheck="+includeInHealthCheck);            		
            	}
                CATokenContainer catoken = ca.getCAToken();
                tokenstatus = catoken.getCATokenInfo().getCATokenStatus();            	
            } else {
//            	if (log.isDebugEnabled()) {
//                	log.debug("Not making test signature with CAs token. doSignTest="+doSignTest+", CA status="+status+", includeInHealthCheck="+includeInHealthCheck);            		
//            	}
            	tokenstatus = cainfo.getCATokenInfo().getCATokenStatus(); 
            }
            // Set a possible new status in the info value object
            cainfo.getCATokenInfo().setCATokenStatus(tokenstatus);
        } catch(javax.ejb.FinderException fe) {
            // ignore
            log.debug("Can not find CA with id: "+caid);
        } catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", new Integer(caid));            	
            log.error(msg, e);
            throw new EJBException(e);
        }        
        return cainfo;
    } // getCAInfo
    
    /**
     * Get the CA object. Does not perform any authorization check.
     * @param admin is used for logging
     * @param caid identifies the CA
     * @return the CA object
     * @throws CADoesntExistsException if no CA was found, the CA has expired or the certificate isn't valid yet
     * @ejb.interface-method
     */
    public CA getCA(Admin admin, int caid) throws CADoesntExistsException {
        final CA ca;
        final CADataLocal cadata;
        try {
            CADataLocal tmpCAdata = null;
            try {
                tmpCAdata = this.cadatahome.findByPrimaryKey(new Integer(caid));
            } catch (FinderException fe) {
    			// subject DN of the CA certificate might not have all objects that is the DN of the certificate data.
            	try {
            		final Integer oRealCAId = (Integer)this.caCertToCaId.get(new Integer(caid));
            		if ( oRealCAId!=null ) { // has the "real" CAID been mapped to the certificate subject hash by a previous call?
            			tmpCAdata = this.cadatahome.findByPrimaryKey(oRealCAId); // using cached value of real caid.
            		} else {
            			final Iterator i = cadatahome.findAll().iterator(); // no, we have to search for it among all CA certs
            			while ( tmpCAdata==null && i.hasNext() ) {
            				final CADataLocal tmp = (CADataLocal)i.next();
            				final Certificate caCert = tmp!=null ? tmp.getCA().getCACertificate() : null;
            				if ( caCert!=null && caid==CertTools.getSubjectDN(caCert).hashCode() ) {
            					tmpCAdata = tmp; // found. Do also cache it if someone else is needing it later
            					this.caCertToCaId.put(new Integer(caid), new Integer(tmpCAdata.getSubjectDN().hashCode()));
            				}
            			}
            		}
                } catch (FinderException e) {
                    // do nothing. can not find CA. CADoesntExistsException will be thrown
                }
                if ( tmpCAdata==null ) {
                    String msg = intres.getLocalizedMessage("signsession.canotfoundcaid", new Integer(caid));        	
                    getLogSession().log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, fe);
                    throw new CADoesntExistsException(msg);
                }
            }
            cadata = tmpCAdata;
            ca = tmpCAdata.getCA();
        } catch (UnsupportedEncodingException uee) {
            throw new EJBException(uee);
        } catch(IllegalKeyStoreException e){
            throw new EJBException(e);
        }
    	// Check that CA hasn't expired.
        try {
        	CertTools.checkValidity(ca.getCACertificate(), new Date());
        } catch (CertificateExpiredException cee) {
        	// Signers Certificate has expired.
        	cadata.setStatus(SecConst.CA_EXPIRED);
            String msg = intres.getLocalizedMessage("signsession.caexpired", cadata.getSubjectDN());
            getLogSession().log(admin, cadata.getCaId().intValue(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg, cee);
            throw new CADoesntExistsException(msg);
        } catch (CertificateNotYetValidException e) {
            throw new CADoesntExistsException(e);
		}
        return ca;
    }
    
    /**
     * Verify that a CA exists. (This method does not check admin privileges
     * and will leak the existance of a CA.)
     * 
     * @param caid is the id of the CA
     * @throws CADoesntExistsException if the CA isn't found
     * 
     * @ejb.interface-method
     */
    public void verifyExistenceOfCA(int caid) throws CADoesntExistsException {
    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet rs = null;
    	try {
    		con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
    		final String sql = "SELECT cAId FROM CAData WHERE cAId=?";
    		ps = con.prepareStatement(sql);
    		ps.setInt(1, caid);
    		rs = ps.executeQuery();
    		ps.setFetchSize(1);
    		ps.setMaxRows(1);
    		rs = ps.executeQuery();
    		if (!rs.next()) {
    			String msg = "No CA with id " + caid + " found.";
    			log.debug(msg);
    			throw new CADoesntExistsException(msg);
    		}
    	} catch (SQLException e) {
    		log.error("", e);
    		throw new EJBException(e);
		} finally {
    		JDBCUtil.close(con, ps, rs);
    	}
    }

    /**
     * Returns a HashMap containing mappings of caid (Integer) to CA name (String) of all CAs in the system.
     * 
     * @return HashMap with Integer->String mappings
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public HashMap getCAIdToNameMap(Admin admin){
        HashMap returnval = new HashMap();
        try{
            Collection result = cadatahome.findAll();
            Iterator iter = result.iterator();
            while(iter.hasNext()){
                CADataLocal cadata = (CADataLocal) iter.next();
                returnval.put(cadata.getCaId(), cadata.getName());
            }
        }catch(javax.ejb.FinderException fe){}


        return returnval;
    }

    /**
     *  Method returning id's of all CA's available to the system. i.e. not having status
     * "external" or "waiting for certificate response"
     *
     * @return a Collection (Integer) of available CA id's
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAvailableCAs(){
    	ArrayList al = new ArrayList();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			final String sql = "SELECT cAId FROM CAData";
			ps = con.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				al.add(rs.getInt(1));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
    	return al;
    }

    /**
     *  Method returning id's of all CA's available to the system that the administrator is authorized to
     *  i.e. not having status "external" or "waiting for certificate response"
     *
     * @param admin The administrator
     * @return a Collection<Integer> of available CA id's
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAvailableCAs(Admin admin) {
    	return getAuthorizationSession().getAuthorizedCAIds(admin, getAvailableCAs());
    }

    /**
     *  Creates a certificate request that should be sent to External Root CA for processing.
     *
     *  @param admin the administrator performing the action
     *  @param caid id of the CA that should create the request 
     *  @param cachain A Collection of CA-certificates.
     *  @param setstatustowaiting should be set true when creating new CAs and false for renewing old CAs
     *  @param keystorepass password used when regenerating keys, can be null if regenerateKeys is false.
     *  @param regenerateKeys if renewing a CA this is used to also generate a new KeyPair.
     *  @return request message in binary format, can be a PKCS10 or CVC request
     *  
     * @ejb.interface-method
     */
    public byte[] makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting, String keystorepass, boolean regenerateKeys) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
    	if (log.isTraceEnabled()) {
        	log.trace(">makeRequest: "+caid);
    	}
        byte[] returnval = null;
        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
            throw new AuthorizationDeniedException(msg);
        }
        
        // Get CA info.
        CADataLocal cadata = null;
        try{
            cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
            CA ca = cadata.getCA();
            String caname = ca.getName();
            
            try{
            	// Generate new certificate request.
            	Collection chain = null;
            	if (cachain.size() > 0) {
                	chain = CertTools.createCertChain(cachain);
                	log.debug("Setting request certificate chain of size: "+chain.size());
                	ca.setRequestCertificateChain(chain);            		
            	} else {
            		log.debug("Empty request certificate chain parameter.");
            		chain = new ArrayList();
            	}
            	String signAlg = "SHA1WithRSA"; // Default algorithm
            	CATokenInfo tinfo = ca.getCAInfo().getCATokenInfo();
            	if (tinfo != null) {
            		signAlg = tinfo.getSignatureAlgorithm();
            	}
            	log.debug("Using signing algorithm: "+signAlg+" for the CSR.");
            	
        		CATokenContainer caToken = ca.getCAToken();
        		if (regenerateKeys) {
        			log.debug("Generating new keys.");
            		boolean renew = true;
                    keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCATokenInfo());
            		caToken.generateKeys(keystorepass, renew);
        			ca.setCAToken(caToken);
        			// In order to generate a certificate with this keystore we must make sure it is activated
        			ca.getCAToken().activate(keystorepass);
        		}
        		// The CA certificate signing this request is the first in the certificate chain
        		Iterator iter = chain.iterator();
        		Certificate cacert = null;
        		if (iter.hasNext()) {
            		cacert = (Certificate)iter.next();        			
        		}
            	returnval = ca.createRequest(null, signAlg, cacert);            	

            	// Set statuses if it should be set.
            	if (setstatustowaiting || regenerateKeys){
            		cadata.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
            		ca.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
            	}

            	cadata.setCA(ca);
            	// Log information about the event
            	String msg = intres.getLocalizedMessage("caadmin.certreqcreated", caname, new Integer(caid));            	
            	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
            }catch(CATokenOfflineException e) {                
        		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
                getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
                throw e;
            }
        }catch(CertPathValidatorException e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
            throw e;
        }catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
            throw new EJBException(e);
        }
        
		String msg = intres.getLocalizedMessage("caadmin.certreqcreated", new Integer(caid));            	
        getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
    	if (log.isTraceEnabled()) {
        	trace("<makeRequest: "+caid);
    	}
        return returnval;
    } // makeRequest

    /** 
     * If the CA can do so, this method signs a nother entitys CSR, for authentication. Prime example of for EU EAC ePassports where
     * the DVs initial certificate request is signed by the CVCA. 
     * The signature algorithm used to sign the request will be whatever algorithm the CA uses to sign certificates.
     * 
     * @param admin
     * @param caid the CA that should sign the request
     * @param request binary certificate request, the format should be understood by the CA
     * @return binary certificate request, which is the same as passed in except also signed by the CA, or it might be the exact same if the CA does not support request signing
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws CATokenOfflineException
     * 
     * @ejb.interface-method
     */
    public byte[] signRequest(Admin admin, int caid, byte[] request, boolean usepreviouskey, boolean createlinkcert) throws AuthorizationDeniedException, CADoesntExistsException, CATokenOfflineException {
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
            throw new AuthorizationDeniedException(msg);
        }
    	byte [] returnval = null;
    	CADataLocal signedbydata;
    	String caname = ""+caid;
		try {
			signedbydata = this.cadatahome.findByPrimaryKey(new Integer(caid));
	    	caname = signedbydata.getName();
	    	CA signedbyCA = signedbydata.getCA();
	    	returnval = signedbyCA.signRequest(request, usepreviouskey, createlinkcert);
	    	String msg = intres.getLocalizedMessage("caadmin.certreqsigned", caname);            	
	    	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_SIGNEDREQUEST,msg);
		} catch (FinderException e) {
			throw new CADoesntExistsException("caid="+caid);
        }catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcertreqsign", caname);            	
            getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SIGNEDREQUEST,msg,e);
            throw new EJBException(e);
        }
    	return returnval;
    }

    /**
     * Receives a certificate response from an external CA and sets the newly created CAs status to active.
     * 
     * @param admin The administrator performing the action
     * @param caid  The caid (DN.hashCode()) of the CA that is receiving this response
     * @param responsemessage X509ResponseMessage with the certificate issued to this CA
     * @param chain an optional collection with the CA certificate(s), or null. If given the complete chain (except this CAs own certificate must be given)
     * 
     * @throws EjbcaException 
     *  
     * @ejb.interface-method
     */
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage, Collection cachain) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException{
    	// check authorization
    	Certificate cacert = null;
    	// Check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
    		throw new AuthorizationDeniedException(msg);
    	}

    	// Get CA info.
    	CADataLocal cadata = null;
    	try{
    		cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
    		CA ca = cadata.getCA();

    		try{
    			if(responsemessage instanceof X509ResponseMessage){
    				cacert = ((X509ResponseMessage) responsemessage).getCertificate();
    			}else{
    	    		String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg", responsemessage != null ? responsemessage.getClass().getName() : "null");
    				getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util. Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    				throw new EjbcaException(msg);
    			}

    			// If signed by external CA, process the received certificate and store it, activating the CA
    			if(ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
    				// Check that DN is the equals the request.
    				if(!CertTools.getSubjectDN(cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))){
        	    		String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN(cacert), ca.getSubjectDN());            	
    					getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    					throw new EjbcaException(msg);
    				}

    				ArrayList tmpchain = new ArrayList();
    				tmpchain.add(cacert);
    				// If we have a chain given as parameter, we will use that.
    				// If no parameter is given we assume that the request chain was stored when the request was created.
    				Collection reqchain = cachain;
    				if (reqchain == null) {
        				reqchain = ca.getRequestCertificateChain();
    					log.debug("Using pre-stored CA certificate chain.");
        				if (reqchain == null) {
        					String msg = intres.getLocalizedMessage("caadmin.errornorequestchain", caid, ca.getSubjectDN());
        					log.info(msg);
        					throw new CertPathValidatorException(msg);
        				}
    				} else {
    					log.debug("Using CA certificate chain from parameter.");
    				}
    				log.debug("Picked up request certificate chain of size: "+reqchain.size());    					
    				tmpchain.addAll(reqchain);
    				Collection chain = CertTools.createCertChain(tmpchain);
    				log.debug("Storing certificate chain of size: "+chain.size());
    				ca.setCertificateChain(chain);

    				// Publish CA Cert
    		        ArrayList cacertcol = new ArrayList();
    		        cacertcol.add(cacert);
    				publishCACertificate(admin, cacertcol, ca.getCRLPublishers(), ca.getSubjectDN());
    				getCRLCreateSession().publishCRL(admin, cacert, ca.getCRLPublishers(), ca.getSubjectDN(), ca.getDeltaCRLPeriod()>0);

    				// Set status to active, so we can sign certificates for the external services below.
    				cadata.setStatus(SecConst.CA_ACTIVE);
    				ca.setStatus(SecConst.CA_ACTIVE);

    				// activate External CA Services
    				Iterator iter = ca.getExternalCAServiceTypes().iterator();
    				while(iter.hasNext()){
    				    int type = ((Integer) iter.next()).intValue();
    				    try{
    				        ca.initExternalService(type, ca);
    				        ArrayList extcacertificate = new ArrayList();
    				        ExtendedCAServiceInfo info = null;
    				        if(type == ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE){
    				        	info = (OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE);
    				        	// The OCSP certificate is the same as the singing certificate
    				        }
    				        if(type == ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE){
    				        	info = ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE);
    				        	extcacertificate.add(((XKMSCAServiceInfo)info).getXKMSSignerCertificatePath().get(0));
    				        }
    				        if(type == ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE){
    				        	info = ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE);
    				        	extcacertificate.add(((CmsCAServiceInfo)info).getCertificatePath().get(0));
    				        }
    		        		// Publish the extended service certificate, but only for active services
    		        		if ( (info != null) && (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) && (!extcacertificate.isEmpty()) ) {
        				        publishCACertificate(admin, extcacertificate, ca.getCRLPublishers(), ca.getSubjectDN());
    		        		}
    				    }catch(CATokenOfflineException e){
            	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg,e);
    				        throw e;
    				    }catch(Exception fe){
            	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg,fe);
    				        throw new EJBException(fe);
    				    }
    				}

    				// Set expire time
    				ca.setExpireTime(CertTools.getNotAfter(cacert));
    				cadata.setExpireTime(CertTools.getNotAfter(cacert).getTime());    				
                    // Save CA
    				cadata.setCA(ca);

    				// Create initial CRL
                    this.getCRLCreateSession().run(admin, ca);                    
    			}else{
    	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				// Cannot create certificate request for internal CA
    				getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    				throw new EjbcaException(msg);
    			}

    		}catch(CATokenOfflineException e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
    			throw e;
    		} catch (CertificateEncodingException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
        		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
        		throw new EjbcaException(e.getMessage());
			} catch (CertificateException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			} catch (IOException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			} catch (NoSuchAlgorithmException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			} catch (NoSuchProviderException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			}
    	}catch(FinderException e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
    		throw new EjbcaException(e.getMessage());
    	} catch (UnsupportedEncodingException e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg, e);
    		throw new EjbcaException(e.getMessage());
		}

		String msg = intres.getLocalizedMessage("caadmin.certrespreceived", new Integer(caid));            	
    	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
    } // recieveResponse

    /**
     * Processes a Certificate Request from an external CA.
     *   
     * @param cainfo the info for the CA that should be created, or already exists. Don't forget to set signedBy in the info.
     *  
     * @ejb.interface-method
     */
    public IResponseMessage processRequest(Admin admin, CAInfo cainfo, IRequestMessage requestmessage)
    throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException, CATokenOfflineException {
    	final CA ca;
    	Collection certchain = null;
    	IResponseMessage returnval = null;
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", cainfo.getName());            	
    		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
    		throw new AuthorizationDeniedException(msg);
    	}

    	// Check that CA doesn't already exists
    	CADataLocal oldcadata = null;
    	try{
    		int caid = cainfo.getCAId();
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
        		String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());            	
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    			throw new CAExistsException(msg);
    		}
    		oldcadata = cadatahome.findByPrimaryKey(new Integer(caid));
    	}catch(javax.ejb.FinderException fe) {}

    	if (oldcadata == null) {
        	try{
        		oldcadata = cadatahome.findByName(cainfo.getName());
        	}catch(javax.ejb.FinderException fe) {}    		
    	}

    	boolean processinternalca = false;
    	if (oldcadata != null) {
    		// If we find an already existing CA, there is a good chance that we should throw an exception
    		// Saying that the CA already exists.
    		// However, if we have the same DN, and give the same name, we simply assume that the admin actually wants
    		// to treat an internal CA as an external CA, perhaps there is different HSMs connected for root CA and sub CA?
    		if (log.isDebugEnabled()) {
        		log.debug("Old castatus="+oldcadata.getStatus()+", oldcaid="+oldcadata.getCaId().intValue()+", caid="+cainfo.getCAId()+", oldcaname="+oldcadata.getName()+", name="+cainfo.getName());    			
    		}
    		if ( ((oldcadata.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) || (oldcadata.getStatus() == SecConst.CA_ACTIVE))
    			&& (oldcadata.getCaId().intValue() == cainfo.getCAId()) && (oldcadata.getName().equals(cainfo.getName())) ) {
    			// Yes, we have all the same DN, CAName and the old CA is either waiting for a certificate response or is active
    			// (new CA or active CA that we want to renew)
    			processinternalca = true;
    			log.debug("Processing an internal CA, as an external.");
    		} else {
        		String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());            	
        		throw new CAExistsException(msg);    			
    		}
    	}

    	//get signing CA
    	if(cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0){
    		try{
    			CADataLocal signcadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getSignedBy()));
    			CA signca = signcadata.getCA();
    			try{
    				//Check that the signer is valid
    				checkSignerValidity(admin, signcadata);

    				// Get public key from request
    				PublicKey publickey = requestmessage.getRequestPublicKey();

    				// Create cacertificate
    				Certificate cacertificate = null;
    				String subjectAltName = null;
    				if(cainfo instanceof X509CAInfo){
    					subjectAltName = ((X509CAInfo) cainfo).getSubjectAltName();
    			    }
    				UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), subjectAltName, null,
    						0, 0, 0,  cainfo.getCertificateProfileId(), null, null, 0, 0, null);
    				// We can pass the PKCS10 request message as extra parameters
    				if(requestmessage instanceof PKCS10RequestMessage){
    					ExtendedInformation extInfo = new ExtendedInformation();
    					PKCS10CertificationRequest pkcs10 = ((PKCS10RequestMessage) requestmessage).getCertificationRequest();
    					extInfo.setCustomData(ExtendedInformation.CUSTOM_PKCS10, new String(Base64.encode(pkcs10.getEncoded()))); 
    					cadata.setExtendedinformation(extInfo);
    				}
    				CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, cainfo.getCertificateProfileId());
    				String sequence = null;
    				byte[] ki = requestmessage.getRequestKeyInfo();
    				if ( (ki != null) && (ki.length > 0) ) {
    					sequence = new String(ki);    						
    				}
    				cacertificate = signca.generateCertificate(cadata, publickey, -1, cainfo.getValidity(), certprofile, sequence);
    				// X509ResponseMessage works for both X509 CAs and CVC CAs here...pure luck? I don't think so!
    				returnval = new X509ResponseMessage();
    				returnval.setCertificate(cacertificate);

    				// Build Certificate Chain
    				Collection rootcachain = signca.getCertificateChain();
    				certchain = new ArrayList();
    				certchain.add(cacertificate);
    				certchain.addAll(rootcachain);

    				if (!processinternalca) {
    					// If this is an internal CA, we don't create it and set a NULL token, since the CA is already created
        				if(cainfo instanceof X509CAInfo){
        					log.info("Creating a X509 CA (process request)");
        					ca = new X509CA((X509CAInfo) cainfo);
        				} else if(cainfo instanceof CVCCAInfo){
        					// CVC CA is a special type of CA for EAC electronic passports
        					log.info("Creating a CVC CA (process request)");
        					CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
        					// Create CVCCA
        					ca = new CVCCA(cvccainfo);
        				} else {
        					ca = null;
        				}
    					ca.setCertificateChain(certchain);
    					CATokenContainer token = new CATokenContainerImpl(new NullCATokenInfo(), cainfo.getCAId());
    					ca.setCAToken(token);

        				// set status to active
        				cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);    					
    				} else {
    					ca = null;
    				}

    				// Publish CA certificates.
    			    publishCACertificate(admin, certchain, signca.getCRLPublishers(), ca!=null ? ca.getSubjectDN() : null);
    				getCRLCreateSession().publishCRL(admin, cacertificate, signca.getCRLPublishers(), ca!=null ? ca.getSubjectDN() : null, ca!=null && ca.getDeltaCRLPeriod()>0);

    			}catch(CATokenOfflineException e){
    	    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
    				error(msg, e);
    				getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
    				throw e;
    			}
    		}catch(Exception e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
				error(msg, e);
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
    			throw new EJBException(e);
    		}

    	}

    	if(certchain != null) {
    		String msg = intres.getLocalizedMessage("caadmin.processedca", cainfo.getName());            	
    		getLogSession().log(admin, cainfo.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);    		
    	} else {
    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
    		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);    		
    	}

    	return returnval;
    } // processRequest
    
    /**
     *  Add an external CA's certificate as a CA
     *   
     * @ejb.interface-method
     */
    public void importCACertificate(Admin admin, String caname, Collection certificates) throws CreateException {
    	Certificate caCertificate = (Certificate) certificates.iterator().next();
    	CA ca = null;
    	CAInfo cainfo = null;

    	// Parameters common for both X509 and CVC CAs
    	ArrayList approvalsettings = new ArrayList(); 
    	int numofreqapprovals = 1;
    	boolean finishuser = false;
    	ArrayList crlpublishers = new ArrayList(); 
    	long crlperiod = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
    	long crlIssueInterval = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
    	long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_HOUR;
    	long deltacrlperiod = 0 * SimpleTime.MILLISECONDS_PER_HOUR;
    	int certprofileid = CertTools.isSelfSigned(caCertificate) ? SecConst.CERTPROFILE_FIXED_ROOTCA : SecConst.CERTPROFILE_FIXED_SUBCA;
    	String subjectdn = CertTools.getSubjectDN(caCertificate);
    	int validity = 0;
    	int signedby = CertTools.isSelfSigned(caCertificate) ? CAInfo.SELFSIGNED : CAInfo.SIGNEDBYEXTERNALCA;
    	String description = "CA created by certificate import.";
    	log.info("Preparing to import of CA with Subject DN " + subjectdn);

    	if (caCertificate instanceof X509Certificate) {
    		X509Certificate x509CaCertificate = (X509Certificate) caCertificate;
    		String subjectaltname = null;
    		try {
    			subjectaltname = CertTools.getSubjectAlternativeName(x509CaCertificate);
    		} catch (CertificateParsingException e) {
    			log.error("", e);
    		} catch (IOException e) {
    			log.error("", e);
    		}

    		// Process certificate policies. 
    		ArrayList policies = new ArrayList();
    		CertificateProfile certprof = getCertificateStoreSession().getCertificateProfile(admin, certprofileid);
    		if (certprof.getCertificatePolicies() != null && certprof.getCertificatePolicies().size() > 0) {
    			policies.addAll(certprof.getCertificatePolicies());
    		}

    		boolean useauthoritykeyidentifier = false;
    		boolean authoritykeyidentifiercritical = false;              

    		boolean usecrlnumber = false;
    		boolean crlnumbercritical = false;

    		boolean useutf8policytext = false;
    		boolean useprintablestringsubjectdn = false;
    		boolean useldapdnorder = !DnComponents.isReverseOrder();
    		boolean usecrldistpointoncrl = false;
    		boolean crldistpointoncrlcritical = false;

    		cainfo = new X509CAInfo(subjectdn, caname, SecConst.CA_EXTERNAL, new Date(), subjectaltname,
    				certprofileid, validity, CertTools.getNotAfter(x509CaCertificate), 
    				CAInfo.CATYPE_X509, signedby,
    				null, null, description, -1, null,
    				policies, crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
    				useauthoritykeyidentifier, 
    				authoritykeyidentifiercritical,
    				usecrlnumber, 
    				crlnumbercritical, 
    				"","","", "", 
    				finishuser, 
    				new ArrayList(),
    				useutf8policytext,
    				approvalsettings,
    				numofreqapprovals, 
    				useprintablestringsubjectdn,
    				useldapdnorder,
    				usecrldistpointoncrl,
    				crldistpointoncrlcritical,
    				false,
                    true, // isDoEnforceUniquePublicKeys
                    true // isDoEnforceUniqueDistinguishedName
    				);
    	} else if (StringUtils.equals(caCertificate.getType(), "CVC")) {
    		cainfo = new CVCCAInfo(subjectdn, caname, 0, new Date(),
    				certprofileid, validity, 
    				null, CAInfo.CATYPE_CVC, signedby,
    				null, null, description, -1, null,
    				crlperiod, crlIssueInterval, crlOverlapTime, deltacrlperiod, crlpublishers, 
    				finishuser, new ArrayList(),
    				approvalsettings,
    				numofreqapprovals,
    				false,
                    true, // isDoEnforceUniquePublicKeys
                    true // isDoEnforceUniqueDistinguishedName
                    );
    	}
    	if(cainfo instanceof X509CAInfo){
    		log.info("Creating a X509 CA (process request)");
    		ca = new X509CA((X509CAInfo) cainfo);
    	} else if(cainfo instanceof CVCCAInfo){
    		// CVC CA is a special type of CA for EAC electronic passports
    		log.info("Creating a CVC CA (process request)");
    		CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
    		ca = new CVCCA(cvccainfo);
    	}
    	ca.setCertificateChain(certificates);
    	CATokenContainer token = new CATokenContainerImpl(new NullCATokenInfo(), cainfo.getCAId());
    	ca.setCAToken(token);
    	// set status to active
    	cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);    					
		// Publish CA certificates.
	    publishCACertificate(admin, certificates, null, ca.getSubjectDN());
    }

    /** Inits an external CA service. this means that a new key and certificate will be generated for this service, if it exists before.
     * If it does not exist before it will be created.
     * @throws CATokenOfflineException 
     * @throws AuthorizationDeniedException 
     * @throws IllegalKeyStoreException 
     * @throws UnsupportedEncodingException 
     * @ejb.interface-method
     */
    public void initExternalCAService(Admin admin, int caid, ExtendedCAServiceInfo info) throws CATokenOfflineException, AuthorizationDeniedException, CADoesntExistsException, UnsupportedEncodingException, IllegalKeyStoreException {
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
    		throw new AuthorizationDeniedException(msg);
    	}

    	// Get CA info.
    	try {
    		CADataLocal cadata = null;
    		cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
    		CA ca = cadata.getCA();
    		if(ca.getStatus() == SecConst.CA_OFFLINE){
    			String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getName());            	
    			throw new CATokenOfflineException(msg);
    		}
    		ArrayList infos = new ArrayList();
    		infos.add(info);
    		activateAndPublishExternalCAServices(admin, infos, ca);
            // Update CA in database
            cadata.setCA(ca);
    	} catch (FinderException e) {
    		throw new CADoesntExistsException("caid="+caid);
    	}
    	
    }
    
    /**
     *  Renews a existing CA certificate using the same keys as before. Data about new CA is taken
     *  from database. This method is used for renewing CAs internally in EJBCA. For renewing CAs signed by external CAs,
     *  makeRequest is used to generate a certificate request.
     *
     *  @param caid the caid of the CA that will be renewed
     *  @param keystorepass password used when regenerating keys, can be null if regenerateKeys is false.
     *  @param regenerateKeys, if true and the CA have a softCAToken the keys are regenerated before the certrequest.
     *          
     * @ejb.interface-method
     * @jboss.method-attributes transaction-timeout="900"
     */
    public void renewCA(Admin admin, int caid, String keystorepass, boolean regenerateKeys)  throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
    	if (log.isTraceEnabled()) {
        	log.trace(">CAAdminSession, renewCA(), caid=" + caid);
    	}
    	Collection cachain = null;
    	Certificate cacertificate = null;
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
    		throw new AuthorizationDeniedException(msg);
    	}

    	// Get CA info.
    	CADataLocal cadata = null;
    	try{
    		cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
    		CA ca = cadata.getCA();
    		
    		
    		if(ca.getStatus() == SecConst.CA_OFFLINE){
        		String msg = intres.getLocalizedMessage("error.catokenoffline", cadata.getName());            	
    			throw new CATokenOfflineException(msg);
    		}
    		
    		CATokenContainer caToken = ca.getCAToken();
    		if (regenerateKeys) {
        		boolean renew = true;
                keystorepass = getDefaultKeyStorePassIfSWAndEmpty(keystorepass, caToken.getCATokenInfo());
        		caToken.generateKeys(keystorepass, renew);
        		// We need to save all this
    			ca.setCAToken(caToken);
    			cadata.setCA(ca);
    			// After this we need to reload all CAs? 
    			// Make sure we store the new CA and token and reload or update the caches
    			Provider prov = Security.getProvider(caToken.getProvider());
    			log.debug("Provider classname: "+prov.getClass().getName());
    			if (StringUtils.contains(prov.getClass().getName(), "iaik")) {
        			// This is because IAIK PKCS#11 provider cuts ALL PKCS#11 sessions when I generate new keys for one CA
        			CACacheManager.instance().removeAll();
        			CATokenManager.instance().removeAll();
    			} else {
    				// Using the Sun provider we don't have to reload every CA, just update values in the caches
    				CACacheManager.instance().removeCA(ca.getCAId());
    				CATokenManager.instance().removeCAToken(ca.getCAId());
    			}    			
        		cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
        		ca = cadata.getCA();
    			// In order to generate a certificate with this keystore we must make sure it is activated
    			caToken = ca.getCAToken();
    			caToken.activate(keystorepass);
    		}
    		
    		try{
    			// if issuer is insystem CA or selfsigned, then generate new certificate.
    			if(ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA){
    				if(ca.getSignedBy() == CAInfo.SELFSIGNED){
    					// create selfsigned certificate
    					String subjectAltName = null;
    					if (ca instanceof X509CA) {
							X509CA x509ca = (X509CA) ca;
							subjectAltName = x509ca.getSubjectAltName();
						}
    					UserDataVO cainfodata = new UserDataVO("nobody",  ca.getSubjectDN(), ca.getSubjectDN().hashCode(), subjectAltName, null,
    							0, 0, 0, ca.getCertificateProfileId(), null, null, 0, 0 ,null);

    					CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());
    					String sequence = caToken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
    					cacertificate = ca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, ca.getValidity(), certprofile, sequence);
    					// Build Certificate Chain
    					cachain = new ArrayList();
    					cachain.add(cacertificate);

    				}else{
    					// Resign with CA above.
    					if(ca.getSignedBy() > CAInfo.SPECIALCAIDBORDER || ca.getSignedBy() < 0){
    						// Create CA signed by other internal CA.
    						CADataLocal signcadata = cadatahome.findByPrimaryKey(new Integer(ca.getSignedBy()));
    						CA signca = signcadata.getCA();
    						//Check that the signer is valid
    						checkSignerValidity(admin, signcadata);
    						// Create cacertificate
        					String subjectAltName = null;
        					if (ca instanceof X509CA) {
    							X509CA x509ca = (X509CA) ca;
    							subjectAltName = x509ca.getSubjectAltName();
    						}
    						UserDataVO cainfodata = new UserDataVO("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), subjectAltName, null,
    								0,0,0, ca.getCertificateProfileId(), null, null, 0,0, null);

    						CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());
        					String sequence = caToken.getCATokenInfo().getKeySequence(); // get from CAtoken to make sure it is fresh
    						cacertificate = signca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, ca.getValidity(), certprofile, sequence);
    						// Build Certificate Chain
    						Collection rootcachain = signca.getCertificateChain();
    						cachain = new ArrayList();
    						cachain.add(cacertificate);
    						cachain.addAll(rootcachain);
    					}
    				}
    			} else {
    				// We should never get here
    				log.error("Directly renewing a CA signed by external can not be done");
    				throw new NotSupportedException("Directly renewing a CA signed by external can not be done");
    			}
    			// Set statuses and expire time
    			cadata.setExpireTime(CertTools.getNotAfter(cacertificate).getTime());
    			ca.setExpireTime(CertTools.getNotAfter(cacertificate));
    			cadata.setStatus(SecConst.CA_ACTIVE);
    			ca.setStatus(SecConst.CA_ACTIVE);

    			ca.setCertificateChain(cachain);
    			cadata.setCA(ca);

    			// Publish the new CA certificate
    			ArrayList cacert = new ArrayList();
    			cacert.add(ca.getCACertificate());
    			publishCACertificate(admin, cacert, ca.getCRLPublishers(), ca.getSubjectDN());
    			createCRLs(admin, ca, ca.getCAInfo());
    		    getCRLCreateSession().publishCRL(admin, ca.getCACertificate(), ca.getCRLPublishers(), ca.getSubjectDN(), ca.getDeltaCRLPeriod()>0);
    		}catch(CATokenOfflineException e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorrenewca", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
    			throw e;
    		}
    	}catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorrenewca", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,e);
    		throw new EJBException(e);
    	}
		String msg = intres.getLocalizedMessage("caadmin.renewdca", new Integer(caid));            	
    	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CARENEWED,msg);
    	if (log.isTraceEnabled()) {
        	log.trace("<CAAdminSession, renewCA(), caid=" + caid);
    	}
    } // renewCA

    /**
     * Soft keystores can not have empty passwords, it probably mens to use the default one
     * @param keystorepass The password that can not be empty if SW.
     * @param tokenInfo Tells if SW.
     * @return The password to use.
     */
    private String getDefaultKeyStorePassIfSWAndEmpty(final String keystorepass, CATokenInfo tokenInfo) {
        if (tokenInfo instanceof SoftCATokenInfo && StringUtils.isEmpty(keystorepass)) {
            log.debug("Using system default keystore password");
            final String newKeystorepass = EjbcaConfiguration.getCaKeyStorePass();                
            return StringTools.passwordDecryption(newKeystorepass, "ca.keystorepass");
        }
        return keystorepass;
    }


    /**
     *  Method that revokes the CA. After this is all certificates created by this CA
     *  revoked and a final CRL is created.
     *
     *  @param reason one of RevokedCertInfo.REVOKATION_REASON values.
     *  
     * @ejb.interface-method
     */
    public void revokeCA(Admin admin, int caid, int reason)  throws CADoesntExistsException, AuthorizationDeniedException{
        // check authorization
		try{
			getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
		}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorevoke", new Integer(caid));            	
			getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
			throw new AuthorizationDeniedException(msg);
		}

        // Get CA info.
        CADataLocal ca = null;
        try{
        	ca = this.cadatahome.findByPrimaryKey(new Integer(caid));
        }catch(javax.ejb.FinderException fe){
           throw new EJBException(fe);
        }

        String issuerdn = ca.getSubjectDN();


        try{
			CA cadata = ca.getCA();

			// Revoke CA certificate
			getCertificateStoreSession().revokeCertificate(admin, cadata.getCACertificate(), cadata.getCRLPublishers(), reason, ca.getSubjectDN());
             // Revoke all certificates generated by CA
			if(cadata.getStatus() != SecConst.CA_EXTERNAL){
		      getCertificateStoreSession().revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);		    
              getCRLCreateSession().run(admin, cadata);
			}
			
			cadata.setRevokationReason(reason);
			cadata.setRevokationDate(new Date());
			if(cadata.getStatus() != SecConst.CA_EXTERNAL){
		  	  ca.setStatus(SecConst.CA_REVOKED);
			}
			ca.setCA(cadata);

        }catch(Exception e){
        	String msg = intres.getLocalizedMessage("caadmin.errorrevoke", ca.getName());            	
        	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAREVOKED,msg,e);
        	throw new EJBException(e);
        }

    	String msg = intres.getLocalizedMessage("caadmin.revokedca", ca.getName(), new Integer(reason));            	
		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAREVOKED,msg);
    } // revokeCA

    /**
     * Method that should be used when upgrading from EJBCA 3.1 to EJBCA 3.2, changes class name of 
     * nCipher HardToken HSMs after code re-structure.
     *
     * @param admin Administrator probably Admin.TYPE_CACOMMANDLINE_USER
     * @param caid id of CA to upgrade
     * 
     * @ejb.interface-method
     */
    public void upgradeFromOldCAHSMKeyStore(Admin admin, int caid){
        try{
            // check authorization
            if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER) {
              getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
            }
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            CA ca = cadata.getCA();
            CATokenContainer token = ca.getCAToken();
            CATokenInfo tokeninfo = token.getCATokenInfo();
            HardCATokenInfo htokeninfo = null;
            if (tokeninfo instanceof HardCATokenInfo) {
            	error("(this is not an error) Found hard token for ca with id: "+caid);
				htokeninfo = (HardCATokenInfo)tokeninfo;	
			} else {
            	error("(this is not an error) No need to update soft token for ca with id: "+caid);
			}
            if (htokeninfo != null) {
            	String oldtoken = htokeninfo.getClassPath();
            	if (oldtoken.equals("se.anatom.ejbca.ca.caadmin.hardcatokens.NFastCAToken") 
            			|| oldtoken.equals("se.primeKey.caToken.nFast.NFastCAToken")) {
            		htokeninfo.setClassPath(org.ejbca.core.model.ca.catoken.NFastCAToken.class.getName());
                	error("(this is not an error) Updated catoken classpath ("+oldtoken+") for ca with id: "+caid);
            		token.updateCATokenInfo(htokeninfo);
            		ca.setCAToken(token);
            		cadata.setCA(ca);
            	} else {
                	error("(this is not an error) No need to update catoken classpath ("+oldtoken+") for ca with id: "+caid);            		
            	}
            }            
        }catch(Exception e){
        	error("An error occured when trying to upgrade hard token classpath: ", e);
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,"An error occured when trying to upgrade hard token classpath", e);
            throw new EJBException(e);
        }

    } // upgradeFromOldCAHSMKeyStore

    /**
     * Method that is used to create a new CA from an imported keystore from another type of CA, for example OpenSSL.
     *
     * @param admin Administrator
     * @param caname the CA-name (human readable) the newly created CA will get
     * @param p12file a byte array of old server p12 file.
     * @param keystorepass used to unlock the keystore.
     * @param privkeypass used to unlock the private key.
     * @param privateSignatureKeyAlias the alias for the private key in the keystore.
     * @param privateEncryptionKeyAlias the alias for the private encryption key in the keystore
     * 
     * @ejb.interface-method
     */
    public void importCAFromKeyStore(Admin admin, String caname, byte[] p12file, String keystorepass,
                                         String privkeypass, String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
        try{
            // check authorization
			if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
			}
            // load keystore
            java.security.KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(p12file),keystorepass.toCharArray());
            // Extract signarture keys
            if ( privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias) ) {
            	throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
            	String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = (Certificate) signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey( privateSignatureKeyAlias, privkeypass.toCharArray());
            log.debug("ImportSignatureKeyAlgorithm="+p12PrivateSignatureKey.getAlgorithm());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if ( !keystore.isKeyEntry(privateEncryptionKeyAlias) ) {
                	throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
	            Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
	            if (encryptionCertChain.length < 1) {
	            	String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
	                log.error(msg);
	                throw new Exception(msg);
	            }
	            caEncryptionCertificate = (Certificate) encryptionCertChain[0];
	            p12PrivateEncryptionKey = (PrivateKey) keystore.getKey( privateEncryptionKeyAlias, privkeypass.toCharArray());
	            p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            }
            importCAFromKeys(admin, caname, keystorepass, signatureCertChain,
					p12PublicSignatureKey, p12PrivateSignatureKey,
					p12PrivateEncryptionKey, p12PublicEncryptionKey);
        } catch(Exception e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorimportca", caname, "PKCS12", e.getMessage());
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
            throw new EJBException(e);
        }
    } // importCAFromKeyStore
    
    /**
     * Removes the catoken keystore from the database and sets its status to 
     * {@link ICAToken#STATUS_OFFLINE}.
     * 
     * The signature algorithm, encryption algorithm, key algorithm and other 
     * properties are not removed so that the keystore can later by restored 
     * by using {@link CAAdminSessionBean#restoreCAKeyStore(Admin, String, byte[], String, String, String, String)}.
     *
     * @param admin Administrator
     * @param caname Name (human readable) of CA for which the keystore should be removed
     * 
     * @throws EJBException in case if the catoken is not a soft catoken
     * 
     * @see CAAdminSessionBean#exportCAKeyStore(Admin, String, String, String, String, String)
     * 
     * @ejb.interface-method
     */
    public void removeCAKeyStore(Admin admin, String caname) throws EJBException {
        try {
            // check authorization
			if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
			}

			CADataLocal caData = cadatahome.findByName(caname); 
			CA thisCa = caData.getCA();
			
	    	CATokenContainer thisCAToken = thisCa.getCAToken();
	    	int tokentype = thisCAToken.getCATokenType();
	    	if ( tokentype != CATokenConstants.CATOKENTYPE_P12 && thisCAToken.getCATokenInfo() instanceof SoftCATokenInfo) {
	    		throw new Exception("Cannot export anything but a soft token.");
	    	}
	    	
	    	// Create a new CAToken with the same properties but OFFLINE and without keystore
	    	SoftCATokenInfo thisCATokenInfo = (SoftCATokenInfo) thisCAToken.getCATokenInfo();
	    	thisCATokenInfo.setCATokenStatus(ICAToken.STATUS_OFFLINE);
	    	CATokenContainer emptyToken = new CATokenContainerImpl(thisCATokenInfo, caData.getCaId());
	    	thisCa.setCAToken(emptyToken);
	    	
	    	// Save to database
	    	caData.setCA(thisCa);
	    	
	    	// Log
	    	String msg = intres.getLocalizedMessage("caadmin.removedcakeystore", new Integer(thisCa.getCAId()));            	
            getLogSession().log(admin, thisCa.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
			
        } catch(Exception e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorremovecakeystore", caname, "PKCS12", e.getMessage());
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED, msg, e);
            throw new EJBException(e);
        }
    } // removeCAKeyStore
    
    /**
     * Restores the keys for the catoken from a keystore.
     *
     * @param admin Administrator
     * @param caname Name (human readable) of the CA for which the keystore should be restored
     * @param p12file The keystore to read keys from
     * @param keystorepass Password for the keystore
     * @param privkeypass Password for the private key
     * @param privateSignatureKeyAlias Alias of the signature key in the keystore
     * @param privateEncryptionKeyAlias Alias of the encryption key in the keystore
     * 
     * @throws EJBException in case of the catoken is not a soft catoken or
     * 		   if the ca already has an active catoken or
     * 		   if any of the aliases can not be found or
     * 		   if the keystore does not contain the right private key
     * 
     * @ejb.interface-method
     */
    public void restoreCAKeyStore(Admin admin, String caname, byte[] p12file, String keystorepass, String privkeypass, String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws EJBException {
        try{
            // check authorization
			if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
			}

			CADataLocal caData = cadatahome.findByName(caname); 
			CA thisCa = caData.getCA();
			
	    	CATokenContainer thisCAToken = thisCa.getCAToken();
	    	int tokentype = thisCAToken.getCATokenType();
	    	if (tokentype != CATokenConstants.CATOKENTYPE_P12 && thisCAToken.getCATokenInfo() instanceof SoftCATokenInfo) {
	    		throw new Exception("Cannot restore anything but a soft token.");
	    	}
	    	
	    	// Only restore to an offline CA
	    	if (thisCAToken.getCATokenInfo().getCATokenStatus() != ICAToken.STATUS_OFFLINE) {
	    		throw new Exception("The CA already has an active CA token.");
	    	}
	    	
	    	// load keystore
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new ByteArrayInputStream(p12file), keystorepass.toCharArray());
            // Extract signarture keys
            if (privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias) ) {
            	throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
            	String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = (Certificate) signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey( privateSignatureKeyAlias, privkeypass.toCharArray());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if (!keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                	throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
	            Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
	            if (encryptionCertChain.length < 1) {
	            	String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
	                log.error(msg);
	                throw new Exception(msg);
	            }
	            caEncryptionCertificate = (Certificate) encryptionCertChain[0];
	            p12PrivateEncryptionKey = (PrivateKey) keystore.getKey( privateEncryptionKeyAlias, privkeypass.toCharArray());
	            p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            } else {
            	throw new Exception("Missing encryption key");
            }
            
            // Sign something to see that we are restoring the right private signature key
            String testSigAlg = (String)AlgorithmTools.getSignatureAlgorithms(thisCa.getCACertificate().getPublicKey()).iterator().next();
            if (testSigAlg == null) {
            	testSigAlg = "SHA1WithRSA";
            }
            // Sign with imported private key
            byte[] input = "Test data...".getBytes();
            Signature signature = Signature.getInstance(testSigAlg, "BC");
            signature.initSign(p12PrivateSignatureKey);
            signature.update(input);
            byte[] signed = signature.sign();
            // Verify with public key from CA certificate
            signature = Signature.getInstance(testSigAlg, "BC");
            signature.initVerify(thisCa.getCACertificate().getPublicKey());
            signature.update(input);
            if (!signature.verify(signed)) {
            	throw new Exception("Could not use private key for verification. Wrong p12-file for this CA?");
            }
            
	    	// Import the keys and save to database
	    	thisCAToken.importKeys(keystorepass, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain);
	    	thisCa.setCAToken(thisCAToken);
	    	caData.setCA(thisCa);
	    	
	    	// Log
	    	String msg = intres.getLocalizedMessage("caadmin.restoredcakeystore", new Integer(thisCa.getCAId()));            	
            getLogSession().log(admin, thisCa.getCAId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch(Exception e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorrestorecakeystore", caname, "PKCS12", e.getMessage());
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }
    } // restoreCAKeyStore
    
    /**
     * Method that is used to create a new CA from keys and certificates.
     * 
     * @param admin
     * @param caname The name the new CA will have
     * @param keystorepass The keystore password the CA will have
     * @param signatureCertChain The CA certificate(s)
     * @param p12PublicSignatureKey CA public signature key
     * @param p12PrivateSignatureKey CA private signature key
     * @param p12PrivateEncryptionKey CA private encryption key, or null to generate a new encryption key
     * @param p12PublicEncryptionKey CA public encryption key, or null to generate a new encryption key
     * 
     * @throws Exception
     * @throws CATokenAuthenticationFailedException
     * @throws CATokenOfflineException
     * @throws IllegalKeyStoreException
     * @throws CreateException
     * 
     * @ejb.interface-method
     */
	public void importCAFromKeys(Admin admin, String caname, String keystorepass,
			Certificate[] signatureCertChain, PublicKey p12PublicSignatureKey,
			PrivateKey p12PrivateSignatureKey,
			PrivateKey p12PrivateEncryptionKey, PublicKey p12PublicEncryptionKey)
			throws Exception, CATokenAuthenticationFailedException,
			CATokenOfflineException, IllegalKeyStoreException, CreateException {
		// Transform into token
		SoftCATokenInfo sinfo = new SoftCATokenInfo();
		CATokenContainer catoken = new CATokenContainerImpl(sinfo, StringTools.strip(CertTools.stringToBCDNString(CertTools.getSubjectDN(signatureCertChain[0]))).hashCode());
		catoken.importKeys(keystorepass, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey,
					p12PublicEncryptionKey, signatureCertChain);
		log.debug("CA-Info: "+catoken.getCATokenInfo().getSignatureAlgorithm() + " " + catoken.getCATokenInfo().getEncryptionAlgorithm());
		// Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
		String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(p12PublicSignatureKey);
		String keySpecification = AlgorithmTools.getKeySpecification(p12PublicSignatureKey);
		if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
			keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
			keySpecification = "2048";
		}
		// Do the general import
		CA ca = importCA(admin, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
		String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CACREATED, msg);
	}

    /**
     * Method that is used to create a new CA from keys on an HSM and certificates in a file.
     *
     * @param admin Administrator
     * @param caname the CA-name (human readable) the newly created CA will get
     * @param signatureCertChain chain of certificates, this CAs certificate first.
     * @param catokenpassword used to unlock the HSM keys.
     * @param catokenclasspath classpath to one of the HardToken classes, for example org.ejbca.core.model.ca.catoken.PKCS11CAToken.
     * @param catokenproperties the catoken properties, same as usually entered in the adminGUI for hard token CAs.
     * 
     * @ejb.interface-method
     */
    public void importCAFromHSM(Admin admin, String caname, Certificate[] signatureCertChain, String catokenpassword, String catokenclasspath, String catokenproperties) throws Exception {
		String signatureAlgorithm = CertTools.getSignatureAlgorithm((Certificate) signatureCertChain[0]);
    	HardCATokenInfo hardcatokeninfo = new HardCATokenInfo();
    	hardcatokeninfo.setAuthenticationCode(catokenpassword);
    	hardcatokeninfo.setCATokenStatus(ICAToken.STATUS_ACTIVE);
    	hardcatokeninfo.setClassPath(catokenclasspath);
    	hardcatokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
    	hardcatokeninfo.setProperties(catokenproperties);
    	hardcatokeninfo.setSignatureAlgorithm(signatureAlgorithm);

        CATokenInfo catokeninfo = hardcatokeninfo;
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo, StringTools.strip(CertTools.stringToBCDNString(CertTools.getSubjectDN(signatureCertChain[0]))).hashCode());
        catoken.activate(catokenpassword);

        String keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
        String keySpecification = "2048";
        // Do the general import
        importCA(admin, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    }

    /**
     * 
     * @param admin
     * @param caname
     * @param keystorepass
     * @param signatureCertChain
     * @param catoken
     * @param keyAlgorithm keyalgorithm for extended CA services, OCSP, XKMS, CMS. Example AlgorithmConstants.KEYALGORITHM_RSA
     * @param keySpecification keyspecification for extended CA services, OCSP, XKMS, CMS. Example 2048
     * @throws Exception
     * @throws CATokenAuthenticationFailedException
     * @throws CATokenOfflineException
     * @throws IllegalKeyStoreException
     * @throws CreateException
     */
	private CA importCA(Admin admin, String caname, String keystorepass,
			Certificate[] signatureCertChain, CATokenContainer catoken,
			String keyAlgorithm, String keySpecification) throws Exception, CATokenAuthenticationFailedException, CATokenOfflineException, IllegalKeyStoreException, CreateException {
		// Create a new CA
		int signedby = CAInfo.SIGNEDBYEXTERNALCA;
		int certprof = SecConst.CERTPROFILE_FIXED_SUBCA;
		String description = "Imported external signed CA";
		Certificate caSignatureCertificate = (Certificate)signatureCertChain[0];
        ArrayList certificatechain = new ArrayList();
        for(int i=0;i< signatureCertChain.length;i++){
            certificatechain.add(signatureCertChain[i]);
        }
		if(signatureCertChain.length == 1) {
			if (verifyIssuer(caSignatureCertificate, caSignatureCertificate)) {
				signedby = CAInfo.SELFSIGNED;
				certprof = SecConst.CERTPROFILE_FIXED_ROOTCA;
				description = "Imported root CA";
			} else {
				// A less strict strategy can be to assume certificate signed
				// by an external CA. Useful if admin user forgot to create a full
				// certificate chain in PKCS#12 package.
				log.error("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate)
						+ ": certificate " + CertTools.getSerialNumberAsString(caSignatureCertificate)
						+ " is not self-signed.");
				throw new Exception("Cannot import CA "
						+ CertTools.getSubjectDN(caSignatureCertificate)
						+ ": certificate is not self-signed. Check "
						+ "certificate chain in PKCS#12");
			}
		} else if (signatureCertChain.length > 1){
			Collection cas = getAvailableCAs();
			Iterator iter = cas.iterator();
			// Assuming certificate chain in forward direction (from target
			// to most-trusted CA). Multiple CA chains can contains the
			// issuer certificate; so only the chain where target certificate
			// is the issuer will be selected.
			while (iter.hasNext()) {
				int caid = ((Integer)iter.next()).intValue();
				CAInfo superCaInfo = getCAInfo(admin, caid);
				Iterator i = superCaInfo.getCertificateChain().iterator();
				if (i.hasNext()) {
					Certificate superCaCert = (Certificate)i.next();
					if (verifyIssuer(caSignatureCertificate, superCaCert)) {
						signedby = caid;
						description = "Imported sub CA";
						break;
					}
				}
			}					
		}
		
		CAInfo cainfo = null;
		CA ca = null;
		int validity = (int)((CertTools.getNotAfter(caSignatureCertificate).getTime() - CertTools.getNotBefore(caSignatureCertificate).getTime()) / (24*3600*1000));
		ArrayList extendedcaservices = new ArrayList();
		if (caSignatureCertificate instanceof X509Certificate) {
			// Create an X509CA
			// Create and active extended CA Services (OCSP, XKMS, CMS).
			extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
			// Create and active XKMS CA Service.
			extendedcaservices.add(
			        new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
			                              "CN=XKMSCertificate, " + CertTools.getSubjectDN(caSignatureCertificate),
			                              "",
			                              keySpecification,
			                              keyAlgorithm));
			// Create and active CMS CA Service.
			extendedcaservices.add(
			        new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
			                              "CN=CMSCertificate, " + CertTools.getSubjectDN(caSignatureCertificate),
			                              "",
			                              keySpecification,
			                              keyAlgorithm));

			cainfo = new X509CAInfo(CertTools.getSubjectDN(caSignatureCertificate),
			                                   caname, SecConst.CA_ACTIVE, new Date(), 
			                                   "", certprof,
			                                   validity,
			                                   CertTools.getNotAfter(caSignatureCertificate), // Expiretime
			                                   CAInfo.CATYPE_X509,
			                                   signedby,
			                                   certificatechain,
			                                   catoken.getCATokenInfo(),
			                                   description,
			                                   -1, null, // revokationreason, revokationdate
			                                   null, // PolicyId
			                                   24 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLPeriod
			                                   0 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLIssuePeriod
			                                   10 * SimpleTime.MILLISECONDS_PER_HOUR, // CRLOverlapTime
			                                   0 * SimpleTime.MILLISECONDS_PER_HOUR, //DeltaCRLPeriod
			                                   new ArrayList(), // CRL publishers
			                                   true, // Authority Key Identifier
			                                   false, // Authority Key Identifier Critical
			                                   true, // CRL Number
			                                   false, // CRL Number Critical
			                                   "", // Default CRL Dist Point
			                                   "", // Default CRL Issuer
			                                   "", // Default OCSP Service Locator                                               
			                                   "", // CA defined freshest CRL
			                                   true, // Finish User
			                                   extendedcaservices,
			                                   false, // use default utf8 settings
			                                   new ArrayList(), // Approvals Settings
			                                   1, // Number of Req approvals
			                                   false, // Use UTF8 subject DN by default
			                                   true, // Use LDAP DN order by default
			                                   false,  // Use CRL Distribution Point on CRL
			                                   false,  // CRL Distribution Point on CRL critical,
			                                   true, // Include in HealthCheck
			                                   true, // isDoEnforceUniquePublicKeys
			                                   true // isDoEnforceUniqueDistinguishedName
			                                   );
			ca = new X509CA((X509CAInfo)cainfo);
		} else if (caSignatureCertificate.getType().equals("CVC")) {
			// Create a CVC CA
            // Create the CAInfo to be used for either generating the whole CA or making a request
            cainfo = new CVCCAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, SecConst.CA_ACTIVE, new Date(),
            		certprof, validity, 
            		CertTools.getNotAfter(caSignatureCertificate), CAInfo.CATYPE_CVC, signedby,
            		certificatechain, catoken.getCATokenInfo(), 
            		description, -1, (Date)null,
                    24, 0, 10, 0, // CRL periods
                    new ArrayList(), // CRL publishers
                    true, // Finish user 
                    extendedcaservices,
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in HealthCheck
                    true, // isDoEnforceUniquePublicKeys
                    true // isDoEnforceUniqueDistinguishedName
                    );
			ca = new CVCCA((CVCCAInfo)cainfo);
		}
		// We must activate the token, in case it does not have the default password
		catoken.activate(keystorepass);
		ca.setCAToken(catoken);
		ca.setCertificateChain(certificatechain);
		log.debug("CA-Info: "+catoken.getCATokenInfo().getSignatureAlgorithm() + " " + ca.getCAToken().getCATokenInfo().getEncryptionAlgorithm());
		//  Publish CA certificates.
		publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
		// activate External CA Services
		activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
		// Store CA in database.
		cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_ACTIVE, ca);
		this.getCRLCreateSession().run(admin, ca);
		return ca;
	} // importCA
    
    /**
     * Exports a CA to file. The method only works for soft tokens.
     *
     * @param admin Administrator
     * @param caname the CA-name (human readable) the CA
     * @param keystorepass used to lock the keystore.
     * @param privkeypass used to lock the private key.
     * @param privateSignatureKeyAlias the alias for the private signature key in the keystore.
     * @param privateEncryptionKeyAlias the alias for the private encryption key in teh keystore
     * 
     * @return A byte array of the CAs p12 in case of X509 CA and pkcs8 private certificate signing key in case of CVC CA.
     * 
     * @ejb.interface-method
     */
    public byte[] exportCAKeyStore(Admin admin, String caname, String keystorepass, String privkeypass, String privateSignatureKeyAlias, 
    		String privateEncryptionKeyAlias) throws Exception {
        log.trace(">exportCAKeyStore");               
        try {
	    	CA thisCa = cadatahome.findByName(caname).getCA();
			// Make sure we are not trying to export a hard or invalid token
	    	CATokenContainer thisCAToken = thisCa.getCAToken();
	    	int tokentype = thisCAToken.getCATokenType();
	    	if ( tokentype != CATokenConstants.CATOKENTYPE_P12 ) {
	    		throw new Exception("Cannot export anything but a soft token.");
	    	}
	    	// Check authorization
			if(admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
			}
            // Fetch keys
	    	// This is a way of verifying the passowrd. If activate fails, we will get an exception and the export will not proceed
	    	thisCAToken.activate(keystorepass);
	    	            
            PrivateKey p12PrivateEncryptionKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
	    	PublicKey p12PublicEncryptionKey = thisCAToken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
            PrivateKey p12PrivateCertSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
	    	PrivateKey p12PrivateCRLSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN);
	    	if ( !p12PrivateCertSignKey.equals(p12PrivateCRLSignKey) ) {
	    		throw new Exception("Assertion of equal signature keys failed.");
	    	}
	    	// Proceed with the export
	    	byte[] ret = null;
	    	String format = null;
	    	if (thisCa.getCAType() == CAInfo.CATYPE_CVC) {
	    		log.debug("Exporting private key with algorithm: "+p12PrivateCertSignKey.getAlgorithm()+" of format: "+p12PrivateCertSignKey.getFormat());
	    		format = p12PrivateCertSignKey.getFormat();
	    		ret = p12PrivateCertSignKey.getEncoded();
	    	} else {
	    		log.debug("Exporting PKCS12 keystore");
	    		format = "PKCS12";
	            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
	            keystore.load(null, keystorepass.toCharArray());
		    	// Load keys into keystore
		    	Certificate[] certificateChainSignature = (Certificate[]) thisCa.getCertificateChain().toArray(new Certificate[0]);
		    	Certificate[] certificateChainEncryption = new Certificate[1];
		    	//certificateChainSignature[0].getSigAlgName(), 
	            // generate dummy certificate for encryption key.
		    	certificateChainEncryption[0] = CertTools.genSelfCertForPurpose("CN=dummy2", 36500, null, p12PrivateEncryptionKey, p12PublicEncryptionKey,
		    			thisCAToken.getCATokenInfo().getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment);
		    	log.debug("Exporting with sigAlgorithm "+CertTools.getSignatureAlgorithm(certificateChainSignature[0])+"encAlgorithm="+thisCAToken.getCATokenInfo().getEncryptionAlgorithm());
	            if ( keystore.isKeyEntry(privateSignatureKeyAlias) ) {
		    		throw new Exception("Key \"" + privateSignatureKeyAlias + "\"already exists in keystore.");
	            }
	            if ( keystore.isKeyEntry(privateEncryptionKeyAlias) ) {
		    		throw new Exception("Key \"" + privateEncryptionKeyAlias + "\"already exists in keystore.");
	            }

	            keystore.setKeyEntry(privateSignatureKeyAlias, p12PrivateCertSignKey, privkeypass.toCharArray(), certificateChainSignature);
	            keystore.setKeyEntry(privateEncryptionKeyAlias, p12PrivateEncryptionKey, privkeypass.toCharArray(), certificateChainEncryption);
	            // Return keystore as byte array and clean up
	            ByteArrayOutputStream baos = new ByteArrayOutputStream();
	            keystore.store(baos, keystorepass.toCharArray());
	            if ( keystore.isKeyEntry(privateSignatureKeyAlias) ) {
	            	keystore.deleteEntry(privateSignatureKeyAlias);
	            }
	            if ( keystore.isKeyEntry(privateEncryptionKeyAlias) ) {
	            	keystore.deleteEntry(privateEncryptionKeyAlias);
	            }
	    		ret = baos.toByteArray();	    		
	    	}
        	String msg = intres.getLocalizedMessage("caadmin.exportedca", caname, format);
	        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEXPORTED, msg);
	        log.trace("<exportCAKeyStore");               
	    	return ret;
	    } catch(Exception e){
        	String msg = intres.getLocalizedMessage("caadmin.errorexportca", caname, "PKCS12", e.getMessage());
	        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEXPORTED, msg, e);
	        throw new EJBException(e);
	    }
	} // exportCAKeyStore


    /**
     *  Method returning a Collection of Certificate of all CA certificates known to the system.
     *  Certificates for External CAs or CAs that are awaiting certificate response are not returned, because we don't have certificates for them.
     *  Uses getAvailableCAs to list CAs.
     *  
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAllCACertificates(){
      ArrayList returnval = new ArrayList();

      try{
          Collection caids = getAvailableCAs();
          Iterator iter = caids.iterator();
          while(iter.hasNext()){
              Integer caid = (Integer)iter.next();
              CADataLocal cadata = cadatahome.findByPrimaryKey(caid);
              CA ca = cadata.getCA();
              if (log.isDebugEnabled()) {
                  debug("Getting certificate chain for CA: "+ca.getName()+", "+ca.getCAId());               
              }
              returnval.add(ca.getCACertificate());
          }
      }catch(javax.ejb.FinderException fe) {
          error("Can't find CA: ", fe);
      } catch(UnsupportedEncodingException uee){
          throw new EJBException(uee);
      } catch(IllegalKeyStoreException e){
          throw new EJBException(e);
      }
      return returnval;
    } // getAllCACertificates

    /**
     * Retrieve fingerprint for all keys as a String. Used for testing. 
     *
     * @param admin Administrator
     * @param caname the name of the CA whose fingerprint should be retrieved.
     * @throws Exception if the CA is not a soft token CA
     * @ejb.interface-method
     */
    public String getKeyFingerPrint(Admin admin, String caname) throws Exception  {
		try {
			if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
			}
			CA thisCa;
			thisCa = cadatahome.findByName(caname).getCA();

			// Make sure we are not trying to export a hard or invalid token
			if ( thisCa.getCAType() != CATokenConstants.CATOKENTYPE_P12 ) {
				throw new Exception("Cannot extract fingerprint from a non-soft token ("+thisCa.getCAType()+").");
			}
			// Fetch keys
			CATokenContainer thisCAToken = thisCa.getCAToken();
			PrivateKey p12PrivateEncryptionKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
			PrivateKey p12PrivateCertSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
			PrivateKey p12PrivateCRLSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN);
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(p12PrivateEncryptionKey.getEncoded());
			md.update(p12PrivateCertSignKey.getEncoded());
			md.update(p12PrivateCRLSignKey.getEncoded());
			return new String(Hex.encode(md.digest()));
		} catch (Exception e) {
			throw new Exception(e);
		}
    } // getKeyFingerPrint

    
    /**
     *  Activates an 'Offline' CA Token and sets the CA status to acitve and ready for use again.
     *  The admin must be authorized to "/ca_functionality/basic_functions/activate_ca" inorder to activate/deactivate.
     * 
     *  @param admin the adomistrator calling the method
     *  @param caid the is of the ca to activate
     *  @param the authorizationcode used to unlock the CA tokens private keys.
     *  @param gc is the GlobalConfiguration used to extract approval information 
     * 
     *  @throws AuthorizationDeniedException it the administrator isn't authorized to activate the CA.
     *  @throws CATokenAuthenticationFailedException if the current status of the ca or authenticationcode is wrong.
     *  @throws CATokenOfflineException if the CA token is still off-line when calling the method.
     *  @throws ApprovalException if an approval already is waiting for specified action 
     *  @throws WaitingForApprovalException  if approval is required and the action have been added in the approval queue.  
     *  
     * @ejb.interface-method
     */
    public void activateCAToken(Admin admin, int caid, String authorizationcode, GlobalConfiguration gc) throws AuthorizationDeniedException, CATokenAuthenticationFailedException, CATokenOfflineException, ApprovalException, WaitingForApprovalException{
       // Authorize
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_ACTIVATECA);
        }catch(AuthorizationDeniedException ade){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", new Integer(caid));            	
            getLogSession().log (admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,ade);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if approvals is required.
        CAInfo cainfo = getCAInfo(admin, caid);
        if (cainfo == null) {
    		String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", new Integer(caid));            	
    		log.error(msg);
    		return;
    	}
        if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
    		String msg = intres.getLocalizedMessage("caadmin.catokenexternal", new Integer(caid));            	
    		log.info(msg);
    		return;
        }
        int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ACTIVATECATOKEN, cainfo.getCAId(), cainfo.getCertificateProfileId());
        ActivateCATokenApprovalRequest ar = new ActivateCATokenApprovalRequest(cainfo.getName(),authorizationcode,admin,numOfApprovalsRequired,caid,ApprovalDataVO.ANY_ENDENTITYPROFILE);
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN)) {
        	getApprovalSession().addApprovalRequest(admin, ar, gc);
            String msg = intres.getLocalizedMessage("ra.approvalcaactivation");            	
        	throw new WaitingForApprovalException(msg);
        }
        
    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
        		String msg = intres.getLocalizedMessage("caadmin.erroractivatetoken", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    			throw new CATokenAuthenticationFailedException(msg);
    		}
    		CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
    		boolean cATokenDisconnected = false;
    		try {
    			if((cadata.getCA().getCAToken().getCATokenInfo()).getCATokenStatus() == ICAToken.STATUS_OFFLINE) {
    				cATokenDisconnected = true;
    			}
    		} catch (IllegalKeyStoreException e) {
    			String msg = intres.getLocalizedMessage("caadmin.errorreadingtoken", new Integer(caid));            	    			
    			log.error(msg,e);
			} catch (UnsupportedEncodingException e) {
				String msg = intres.getLocalizedMessage("caadmin.errorreadingtoken", new Integer(caid));            	    			
				log.error(msg,e);
			}
    		if(cadata.getStatus() == SecConst.CA_OFFLINE || cATokenDisconnected){
        		try {
    				cadata.getCA().getCAToken().activate(authorizationcode);
    				// If the CA was off-line, this is activation of the CA, if only the token was disconnected we only connect the token
    				// If CA is waiting for certificate response we can not change this status just by activating the token.
    				if (cadata.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
        				cadata.setStatus(SecConst.CA_ACTIVE);    					
    				}
    				// Invalidate CA cache to refresh information
    				CACacheManager.instance().removeCA(cadata.getCaId().intValue());
            		String msg = intres.getLocalizedMessage("caadmin.catokenactivated", cadata.getName());            	
    				getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
    			} catch (CATokenAuthenticationFailedException e) {
            		String msg = intres.getLocalizedMessage("caadmin.badcaactivationcode", cadata.getName());
    				getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAACTIVATIONCODE, msg);
                    throw e;
    			} catch (IllegalKeyStoreException e) {
                    throw new EJBException(e);
    			} catch (UnsupportedEncodingException e) {
                    throw new EJBException(e);
    			}
    		}else{
        		String msg = intres.getLocalizedMessage("caadmin.errornotoffline", cadata.getName());            	
				getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
				throw new CATokenAuthenticationFailedException(msg);
    		}
    	}catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    		throw new EJBException(fe);
    	}
    }

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest.class.getName(),null),
	};
    
    /**
     *  Deactivates an 'active' CA token and sets the CA status to offline.
     *  The admin must be authorized to "/ca_functionality/basic_functions/activate_ca" inorder to activate/deactivate.
     * 
     *  @param admin the adomistrator calling the method
     *  @param caid the is of the ca to activate. 
     * 
     *  @throws AuthorizationDeniedException it the administrator isn't authorized to activate the CA.
     *  @throws EjbcaException if the given caid couldn't be found or its status is wrong.
     *  
     * @ejb.interface-method
     */
    public void deactivateCAToken(Admin admin, int caid) throws AuthorizationDeniedException, EjbcaException{
       // Authorize
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_ACTIVATECA);
        }catch(AuthorizationDeniedException ade){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken", new Integer(caid));            	
            getLogSession().log (admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,ade);
            throw new AuthorizationDeniedException(msg);
        }

    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
                // This should never happen.
        		String msg = intres.getLocalizedMessage("caadmin.errordeactivatetoken", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    			throw new EjbcaException(msg);
    		}
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            if(cadata.getStatus() == SecConst.CA_EXTERNAL){
        		String msg = intres.getLocalizedMessage("caadmin.catokenexternal", new Integer(caid));            	
        		log.info(msg);
        		return;
            } else if(cadata.getStatus() == SecConst.CA_ACTIVE){
            	try {
            		cadata.getCA().getCAToken().deactivate();
            		cadata.setStatus(SecConst.CA_OFFLINE);
    				// Invalidate CA cache to refresh information
    				CACacheManager.instance().removeCA(cadata.getCaId().intValue());
            		String msg = intres.getLocalizedMessage("caadmin.catokendeactivated", cadata.getName());            	
            		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED,msg);
            	} catch (Exception e) {
            		throw new EJBException(e);
                }
            }else{
        		String msg = intres.getLocalizedMessage("caadmin.errornotonline", cadata.getName());            	
            	getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
            	throw new EjbcaException(msg);
            }
    	}catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg);
    		throw new EJBException(fe);
    	}
    }

    /**
     *  Method used to check if certificate profile id exists in any CA.
     *  
     * @ejb.interface-method
     */
    public boolean exitsCertificateProfileInCAs(Admin admin, int certificateprofileid){
      boolean returnval = false;
      try{
        Collection result = cadatahome.findAll();
        Iterator iter = result.iterator();
        while(iter.hasNext()){
          CADataLocal cadata = (CADataLocal) iter.next();
          returnval = returnval || (cadata.getCA().getCertificateProfileId() == certificateprofileid);
        }
      }catch(javax.ejb.FinderException fe){}
       catch(java.io.UnsupportedEncodingException e){}
       catch(IllegalKeyStoreException e){}

      return returnval;
    } // exitsCertificateProfileInCAs

    /**
     * Encrypts data with a CA key.
     * @param caid identifies the CA
     * @param data is the data to process
     * @return processed data
     * @throws Exception
     * 
     * @ejb.interface-method
     */
    public byte[] encryptWithCA(int caid, byte[] data) throws Exception {
        CADataLocal caData = cadatahome.findByPrimaryKey(new Integer(caid));
    	return caData.getCA().encryptData(data, SecConst.CAKEYPURPOSE_KEYENCRYPT);
    }

    /**
     * Decrypts data with a CA key.
     * @param caid identifies the CA
     * @param data is the data to process
     * @return processed data
     * @throws Exception
     *
     * @ejb.interface-method
      */
    public byte[] decryptWithCA(int caid, byte[] data) throws Exception {
        CADataLocal caData = cadatahome.findByPrimaryKey(new Integer(caid));
    	return caData.getCA().decryptData(data, SecConst.CAKEYPURPOSE_KEYENCRYPT);
    }

    /**
     *  Method used to check if publishers id exists in any CAs CRLPublishers Collection.
     *  
     * @ejb.interface-method
     */
    public boolean exitsPublisherInCAs(Admin admin, int publisherid){
      boolean returnval = false;
      try{
        Collection result = cadatahome.findAll();
        Iterator iter = result.iterator();
        while(iter.hasNext()){
          CADataLocal cadata = (CADataLocal) iter.next();
          Iterator pubiter = cadata.getCA().getCRLPublishers().iterator();
          while(pubiter.hasNext()){
        	  Integer pubInt = (Integer)pubiter.next();
        	  returnval = returnval || (pubInt.intValue() == publisherid);
          }
        }
      }catch(javax.ejb.FinderException fe){}
       catch(java.io.UnsupportedEncodingException e){}
       catch(IllegalKeyStoreException e){}
        
      return returnval;
    } // exitsPublisherInCAs
    
	/**
     * Help method that checks the CA data config and the certificate profile if the specified action 
     * requires approvals and how many
     * @param is the administrator requesting this operation
     * @param action one of CAInfo.REQ_APPROVAL_ constants
     * @param caid of the ca to check
     * @param certprofile of the ca to check
     * @return 0 if no approvals is required otherwise the number of approvals
     * 
     * @ejb.interface-method
     */
    public int getNumOfApprovalRequired(Admin admin, int action, int caid, int certProfileId) {
    	int retval = 0;
    	CAInfo cainfo = getCAInfo(admin, caid);
    	if (cainfo != null) {
        	if(cainfo.isApprovalRequired(action)){
        		retval = cainfo.getNumOfReqApprovals();
        	}
        	CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, certProfileId);
        	if(certprofile != null && certprofile.isApprovalRequired(action)) {
        		retval = Math.max(retval, certprofile.getNumOfReqApprovals());
        	}
    	}
    	return retval;
    }
    
    /**
     * Method that publishes the given CA certificate chain to the list of publishers.
     * Is mainly used when CA is created.
     *
     * @param admin            Information about the administrator or admin preforming the event.
     * @param certificatechain certchain of certificate to publish
     * @param usedpublishers   a collection if publisher id's (Integer) indicating which publisher that should be used.
     * @param caDataDN         DN from CA data. If a the CA certificate does not have a DN object to be used by the publisher this DN could be searched for the object.
     * @ejb.interface-method view-type="both"
     */
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection usedpublishers, String caDataDN) {
    	try {
    		Object[] certs = certificatechain.toArray();
    		for (int i = 0; i < certs.length; i++) {
    			Certificate cert = (Certificate)certs[i];
    			String fingerprint = CertTools.getFingerprintAsString(cert);
    			// CA fingerprint, figure out the value if this is not a root CA
    			String cafp = fingerprint;
    			// Calculate the certtype
    			boolean isSelfSigned = CertTools.isSelfSigned(cert);
    			int type = SecConst.CERTTYPE_ENDENTITY;
    			if (CertTools.isCA(cert))  {
    				// this is a CA
    				if (isSelfSigned) {
    					type = SecConst.CERTTYPE_ROOTCA;
    				} else {
    					type = SecConst.CERTTYPE_SUBCA;
    					// If not a root CA, the next certificate in the chain should be the CA of this CA
    					if ((i+1) < certs.length) {
    						Certificate cacert = (Certificate)certs[i+1]; 
    						cafp = CertTools.getFingerprintAsString(cacert);
    					}
    				}                		
    			} else if (isSelfSigned) {
    				// If we don't have basic constraints, but is self signed, we are still a CA, just a stupid CA
    				type = SecConst.CERTTYPE_ROOTCA;
    			} else {
    				// If and end entity, the next certificate in the chain should be the CA of this end entity
    				if ((i+1) < certs.length) {
    					Certificate cacert = (Certificate)certs[i+1]; 
    					cafp = CertTools.getFingerprintAsString(cacert);
    				}
    			}

    			String name = "SYSTEMCERT";
    			if (type != SecConst.CERTTYPE_ENDENTITY) {
    				name = "SYSTEMCA";
    			}
    			// Store CA certificate in the database if it does not exist
    			long updateTime = new Date().getTime();
    			int profileId = 0;
    			String tag = null;
    			CertificateInfo ci = getCertificateStoreSession().getCertificateInfo(admin, fingerprint);
    			if (ci == null) {
    				// If we don't have it in the database, store it setting certificateProfileId = 0 and tag = null
    				getCertificateStoreSession().storeCertificate(admin, cert, name, cafp, SecConst.CERT_ACTIVE, type, profileId, tag, updateTime);
    			} else {
    				updateTime = ci.getUpdateTime().getTime();
    				profileId = ci.getCertificateProfileId();
    				tag = ci.getTag();
    			}
    			if (usedpublishers != null) {
    				getPublisherSession().storeCertificate(admin, usedpublishers, cert, cafp, null, caDataDN, fingerprint, SecConst.CERT_ACTIVE, type, -1, RevokedCertInfo.NOT_REVOKED, tag, profileId, updateTime, null);
    			}
    		}
    	} catch (javax.ejb.CreateException ce) {
    		throw new EJBException(ce);
    	}
    }

    /**
     * Retrives a Collection of id:s (Integer) to authorized publishers.
     *
     * @param admin
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedPublisherIds(Admin admin) {
        HashSet returnval = new HashSet();
        try {
            // If superadmin return all available publishers
            returnval.addAll(getPublisherSession().getAllPublisherIds(admin));
        } catch (AuthorizationDeniedException e1) {
            // If regular CA-admin return publishers he is authorized to 
            Iterator authorizedcas = getAvailableCAs(admin).iterator();
            while (authorizedcas.hasNext()) {
                returnval.addAll(getCAInfo(admin, ((Integer) authorizedcas.next()).intValue()).getCRLPublishers());
            }
        }
        return returnval;
    }

    
    private boolean authorizedToCA(Admin admin, int caid){
      boolean returnval = false;
      if (admin.getAdminType() == Admin.TYPE_INTERNALUSER) {
    	  return true;	// Skip database seach since this is always ok
      }
      try{
        returnval = getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
      }catch(AuthorizationDeniedException e){}
      return returnval;
    }

    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their
     * CRLs. No overlap is used. This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     *
     * @return the number of crls created.
     * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
     * @ejb.interface-method 
     */
    public int createCRLs(Admin admin)  {
    	return createCRLs(admin, null, 0);
    }

    /**
     * Method that checks if there are any delta CRLs needed to be updated and then creates their
     * delta CRLs. No overlap is used. This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     *
     * @return the number of delta crls created.
     * @throws EJBException if communication or system error happens
     * @ejb.interface-method 
     */
    public int createDeltaCRLs(Admin admin)  {
    	return createDeltaCRLs(admin, null, 0);
    }

    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their
     * CRLs. A CRL is created:
     * 1. if the current CRL expires within the crloverlaptime (milliseconds)
     * 2. if a crl issue interval is defined (>0) a CRL is issued when this interval has passed, even if the current CRL is still valid
     *  
     * This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked
     * @param addtocrloverlaptime given in milliseconds and added to the CRL overlap time, if set to how often this method is run (poll time), it can be used to issue a new CRL if the current one expires within
     * the CRL overlap time (configured in CA) and the poll time. The used CRL overlap time will be (crloverlaptime + addtocrloverlaptime) 
     *
     * @return the number of crls created.
     * @throws EJBException if communication or system error occurrs
     * @ejb.interface-method 
     */
    public int createCRLs(Admin admin, Collection caids, long addtocrloverlaptime)  {
    	int createdcrls = 0;
    	try {
    		Iterator iter = null;
    		if (caids != null) {
    			iter = caids.iterator();
    		} 
    		if ( (iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS))) ) {
        		iter = getAvailableCAs().iterator();
    		}
    		while(iter.hasNext()){
    			int caid = ((Integer) iter.next()).intValue();
    			log.debug("createCRLs for caid: "+caid);
    			CA ca = getCA(admin, caid);
    			if (getCRLCreateSession().runNewTransactionConditioned(admin, ca, addtocrloverlaptime)) {
        			createdcrls++;
    			}
    		}
    	} catch (Exception e) {
        	String msg = intres.getLocalizedMessage("createcrl.erroravailcas");            	    			    	   
        	error(msg, e);
    		logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
            if (e instanceof EJBException) {
                throw (EJBException)e;
            }
    		throw new EJBException(e);
    	}
    	return createdcrls;
    }

    
    /**
     * Method that checks if there are any delta CRLs needed to be updated and then creates them.
     * This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked
     * @param crloverlaptime A new delta CRL is created if the current one expires within the crloverlaptime given in milliseconds
     *
     * @return the number of delta crls created.
     * @throws EJBException if communication or system error occurrs
     * @ejb.interface-method 
     */
    public int createDeltaCRLs(Admin admin, Collection caids, long crloverlaptime) {
    	int createddeltacrls = 0;
    	try {
    		Iterator iter = null;
    		if (caids != null) {
    			iter = caids.iterator();
    		}
    		if ( (iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS))) ) {
        		iter = getAvailableCAs().iterator();
    		}
    		while (iter.hasNext()) {
    			int caid = ((Integer) iter.next()).intValue();
    			log.debug("createDeltaCRLs for caid: "+caid);
    			CA ca = getCA(admin, caid);
    			if (getCRLCreateSession().runDeltaCRLnewTransactionConditioned(admin, ca, crloverlaptime)) {
    				createddeltacrls++;
    			}
    		}
    	} catch (Exception e) {
        	String msg = intres.getLocalizedMessage("createcrl.erroravailcas");            	    			    	   
        	error(msg, e);
    		logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
            if (e instanceof EJBException) {
                throw (EJBException)e;
            }
    		throw new EJBException(e);
    	}
    	return createddeltacrls;
    }

    //
    // Private methods
    //

	/** Check if subject certificate is signed by issuer certificate. Used in
	 * @see #upgradeFromOldCAKeyStore(Admin, String, byte[], char[], char[], String).
	 * This method does a lazy check: if signature verification failed for
	 * any reason that prevent verification, e.g. signature algorithm not
	 * supported, method returns false.
	 * Author: Marco Ferrante
	 *
	 * @param subject Subject certificate
	 * @param issuer Issuer certificate
	 * @return true if subject certificate is signed by issuer certificate
	 * @throws java.lang.Exception
	 */
	private boolean verifyIssuer(Certificate subject, Certificate issuer) throws Exception {
		try {
			PublicKey issuerKey = issuer.getPublicKey();
			subject.verify(issuerKey);
			return true;
		} catch (java.security.GeneralSecurityException e) {
			return false;
		}
	}
	
    /** Checks the signer validity given a CADataLocal object, as a side-effect marks the signer as expired if it is expired, 
     * and throws an EJBException to the caller. 
     * 
     * @param admin administrator calling the method
     * @param signcadata a CADataLocal entity object of the signer to be checked
     * @throws UnsupportedEncodingException if there is an error getting the CA from the CADataLoca
     * @throws IllegalKeyStoreException l
     * @throws EJBException embedding a CertificateExpiredException or a CertificateNotYetValidException if the certificate has expired or is not yet valid 
     */
    private void checkSignerValidity(Admin admin, CADataLocal signcadata) throws UnsupportedEncodingException, IllegalKeyStoreException {
    	// Check validity of signers certificate
    	Certificate signcert = (Certificate) signcadata.getCA().getCACertificate();
    	try{
    		CertTools.checkValidity(signcert, new Date());
    	}catch(CertificateExpiredException ce){
    		// Signers Certificate has expired.
    		signcadata.setStatus(SecConst.CA_EXPIRED);
    		String msg = intres.getLocalizedMessage("signsession.caexpired", signcadata.getSubjectDN());            	
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,ce);
    		throw new EJBException(ce);
    	}catch(CertificateNotYetValidException cve){
    		String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signcadata.getSubjectDN());            	
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED,msg,cve);
    		throw new EJBException(cve);
    	}
    }
    
    /** Helper method that activates CA services and publisher their certificates, if the services are marked as active
     * 
     */
	private void activateAndPublishExternalCAServices(Admin admin, Collection extendedCAServiceInfos, CA ca) {
		// activate External CA Services
		Iterator iter = extendedCAServiceInfos.iterator();
		while(iter.hasNext()){
			ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
			ArrayList certificate = new ArrayList();
			if(info instanceof OCSPCAServiceInfo){
				try{
					ca.initExternalService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, ca);
					// The OCSP certificate is the same as the CA signing certifcate
				}catch(Exception fe){
					String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "OCSPCAService");            	
					getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg,fe);
					throw new EJBException(fe);
				}
			}
			if(info instanceof XKMSCAServiceInfo){
				try{
					ca.initExternalService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, ca);
					certificate.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE)).getXKMSSignerCertificatePath().get(0));
				}catch(Exception fe){
					String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "XKMSCAService");            	
					getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg,fe);
					throw new EJBException(fe);
				}
			}
			if(info instanceof CmsCAServiceInfo){
				try{
					ca.initExternalService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE, ca);
					certificate.add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath().get(0));
				}catch(Exception fe){
					String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "CMSCAService");            	
					getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA,  new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CACREATED,msg,fe);
					throw new EJBException(fe);
				}
			}
			// Always store the certificate. Only publish the extended service certificate for active services.
			Collection publishers = null;
			if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
				publishers = ca.getCRLPublishers();
			}
			if ( (!certificate.isEmpty()) ) {
				publishCACertificate(admin, certificate, publishers, ca.getSubjectDN());        			
			}
		}
	} // activateAndPublishExternalCAServices 

} //CAAdminSessionBean
