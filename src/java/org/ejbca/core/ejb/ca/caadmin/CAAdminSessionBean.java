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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
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
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;



/**
 * Administrates and manages CAs in EJBCA system.
 *
 * @version $Id: CAAdminSessionBean.java,v 1.59 2007-10-10 12:15:43 anatom Exp $
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
 * @ejb.env-entry description="Used internally to keystores in database"
 *   name="keyStorePass"
 *   type="java.lang.String"
 *   value="${ca.keystorepass}"
 *
 * @ejb.env-entry description="Password for OCSP keystores"
 *   name="OCSPKeyStorePass"
 *   type="java.lang.String"
 *   value="${ca.ocspkeystorepass}"
 *   
 * @ejb.env-entry description="Password for XKMS keystores"
 *   name="XKMSKeyStorePass"
 *   type="java.lang.String"
 *   value="${ca.xkmskeystorepass}"
 *
 *   
 * @ejb.env-entry description="Password for CMS keystores"
 *   name="CMSKeyStorePass"
 *   type="java.lang.String"
 *   value="${ca.cmskeystorepass}"
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
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *
 * @ejb.ejb-external-ref description="The CRL Create bean"
 *   view-type="local"
 *   ref-name="ejb/CreateCRLSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *   link="CreateCRLSession"
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

    /** The local interface of the sign session bean */
    private ISignSessionLocal signsession;

    /** The local interface of the job runner session bean used to create crls.*/
    private ICreateCRLSessionLocal jobrunner;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        cadatahome = (CADataLocalHome)getLocator().getLocalHome(CADataLocalHome.COMP_NAME);
        // Install BouncyCastle provider
        CertTools.installBCProvider();
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
            getLogSession().log (admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, ade);
            throw new AuthorizationDeniedException(msg);
        }
        // Check that CA doesn't already exists
        try{
            int caid = cainfo.getCAId();
            if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
            	String msg = intres.getLocalizedMessage("caadmin.wrongcaid", new Integer(caid));
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg);
                throw new CAExistsException(msg);
            }
            cadatahome.findByPrimaryKey(new Integer(caid));
        	String msg = intres.getLocalizedMessage("caadmin.caexistsid", new Integer(caid));
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg);
            throw new CAExistsException(msg);
        }catch(javax.ejb.FinderException fe) {}

        try{
            cadatahome.findByName(cainfo.getName());
        	String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg);
            throw new CAExistsException(msg);
        }catch(javax.ejb.FinderException fe) {}

        // Create CAToken
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo);
		String authCode = catokeninfo.getAuthenticationCode();
		if (StringUtils.isEmpty(authCode)) {
			log.debug("Creating CA using system default keystore password");
    	    authCode = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");        			
		}
        if(catokeninfo instanceof SoftCATokenInfo){
        	try{
        		// There are two ways to get the authentication code:
        		// 1. The user provided one when creating the CA on the create CA page
        		// 2. We use the system default password
        		boolean renew = false;
        		catoken.generateKeys(authCode, renew);
        	}catch(Exception e){
        		String msg = intres.getLocalizedMessage("caadmin.errorcreatetoken");
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, e);
        		throw new EJBException(e);
        	}
        }
        try{
        	catoken.activate(authCode);
        }catch(CATokenAuthenticationFailedException ctaf){
        	String msg = intres.getLocalizedMessage("caadmin.errorcreatetokenpin");            	
        	getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, ctaf);
        	throw ctaf;
        }catch(CATokenOfflineException ctoe){
        	String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
        	getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, ctoe);
        	throw ctoe;
        }

        // Create CA
        CA ca = null;
        if(cainfo instanceof X509CAInfo){
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            // Create X509CA
            ca = new X509CA((X509CAInfo) cainfo);
            X509CA x509ca = (X509CA) ca;
            ca.setCAToken(catoken);

            // Create Certificate Chain
            Collection certificatechain = null;

            // getCertificateProfile
            CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin,cainfo.getCertificateProfileId());
            if(x509cainfo.getPolicyId() != null){
              certprofile.setUseCertificatePolicies(true);
              certprofile.setCertificatePolicyId(x509cainfo.getPolicyId());
            }else{
              if(certprofile.getUseCertificatePolicies())
                x509ca.setPolicyId(certprofile.getCertificatePolicyId());
            }

            if(cainfo.getSignedBy() == CAInfo.SELFSIGNED){
              try{
                // create selfsigned certificate
                Certificate cacertificate = null;

                log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());

                UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), x509cainfo.getSubjectAltName(), null,
                                                      0,0,0,  cainfo.getCertificateProfileId(), null, null, 0, 0, null);
                
                cacertificate = ca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, cainfo.getValidity(), certprofile);

                log.debug("CAAdminSessionBean : " + ((X509Certificate) cacertificate).getSubjectDN().toString());

                // Build Certificate Chain
                certificatechain = new ArrayList();
                certificatechain.add(cacertificate);

                // set status to active
                castatus = SecConst.CA_ACTIVE;
              }catch(CATokenOfflineException e){
            	  String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
            	  getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, e);
            	  throw e;
              }catch(Exception fe){
            	  String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
            	  getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, fe);
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

            		UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), x509cainfo.getSubjectAltName(), null,
            				0, 0, 0, cainfo.getCertificateProfileId(),null, null, 0, 0, null);
            		
            		cacertificate = signca.generateCertificate(cadata, catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), -1, cainfo.getValidity(), certprofile);

            		// Build Certificate Chain
            		Collection rootcachain = signca.getCertificateChain();
            		certificatechain = new ArrayList();
            		certificatechain.add(cacertificate);
            		certificatechain.addAll(rootcachain);
            		// set status to active
            		castatus = SecConst.CA_ACTIVE;
            	}catch(CATokenOfflineException e){
            		String msg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());            	
            		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, e);
            		throw e;
            	}catch(Exception fe){
            		String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
            		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, fe);
            		throw new EJBException(fe);
            	}
            }

            // Set Certificate Chain
            x509ca.setCertificateChain(certificatechain);

        }

        //	Publish CA certificates.
        
        getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers());
        
        
        
        if(castatus ==SecConst.CA_ACTIVE){
        	// activate External CA Services
        	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
        	while(iter.hasNext()){
        		ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
        		if(info instanceof OCSPCAServiceInfo){
        			try{
        				ca.initExternalService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, ca);
        				ArrayList ocspcertificate = new ArrayList();
        				ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE)).getOCSPSignerCertificatePath().get(0));
        				getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers());
        			}catch(Exception fe){
        				String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "OCSPCAService");            	
        				getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg,fe);
        				throw new EJBException(fe);
        			}
        		}
        		if(info instanceof XKMSCAServiceInfo){
        			try{
        				ca.initExternalService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, ca);
        				ArrayList xkmscertificate = new ArrayList();
        				xkmscertificate.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE)).getXKMSSignerCertificatePath().get(0));
        				getSignSession().publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers());
        			}catch(Exception fe){
        				String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "XKMSCAService");            	
        				getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg,fe);
        				throw new EJBException(fe);
        			}
        		}
        		if(info instanceof CmsCAServiceInfo){
        			try{
        				ca.initExternalService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE, ca);
        				ArrayList cmscertificate = new ArrayList();
        				cmscertificate.add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath().get(0));
        				getSignSession().publishCACertificate(admin, cmscertificate, ca.getCRLPublishers());
        			}catch(Exception fe){
        				String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "CMSCAService");            	
        				getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg,fe);
        				throw new EJBException(fe);
        			}
        		}
        	}
        }
        // Store CA in database.
        try{
        	cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), castatus, ca);
        	if(castatus == SecConst.CA_ACTIVE){
        		//  create initial CRL
        		this.getCRLCreateSession().run(admin,cainfo.getSubjectDN());
        	}
    		String msg = intres.getLocalizedMessage("caadmin.createdca", cainfo.getName(), new Integer(castatus));            	
        	getLogSession().log(admin, ca.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED, msg);
        }catch(javax.ejb.CreateException e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());            	
        	getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg);
        	throw new EJBException(e);
        }
        
        
    } // createCA

    /**
     * Method used to edit the data of a CA. 
     * 
     * Not all of the CAs data can be edited after the creation, therefore will only
     * the values from CAInfo that is possible be uppdated. 
     *
     * 
     *  For values see:
     *  @see org.ejbca.core.model.ca.caadmin.CAInfo
     *  @see org.ejbca.core.model.ca.caadmin.X509CAInfo
     *  
     * @ejb.interface-method
     */
    public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException{
        boolean ocsprenewcert = false;
        boolean xkmsrenewcert = false;
        boolean cmsrenewcert = false;

        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", cainfo.getName());            	
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if OCSP Certificate is about to be renewed.
        Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
        while(iter.hasNext()){
          Object next = iter.next();
          if(next instanceof OCSPCAServiceInfo){
            ocsprenewcert = ((OCSPCAServiceInfo) next).getRenewFlag();
          }
          if(next instanceof XKMSCAServiceInfo){
              xkmsrenewcert = ((XKMSCAServiceInfo) next).getRenewFlag();
          }
          if(next instanceof CmsCAServiceInfo){
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

            // If OCSP Certificate renew, publish the new one.
            if(ocsprenewcert){
              X509Certificate ocspcert = (X509Certificate) ((OCSPCAServiceInfo)
                                         ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE))
                                         .getOCSPSignerCertificatePath().get(0);
			  ArrayList ocspcertificate = new ArrayList();
              ocspcertificate.add(ocspcert);
              getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers());
            }
            if(xkmsrenewcert){
                X509Certificate xkmscert = (X509Certificate) ((XKMSCAServiceInfo)
                                           ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE))
                                           .getXKMSSignerCertificatePath().get(0);
  			  ArrayList xkmscertificate = new ArrayList();
  			  xkmscertificate.add(xkmscert);
              getSignSession().publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers());
            }
            if(cmsrenewcert){
                X509Certificate cmscert = (X509Certificate) ((CmsCAServiceInfo)
                                           ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE))
                                           .getCertificatePath().get(0);
  			  ArrayList cmscertificate = new ArrayList();
  			  cmscertificate.add(cmscert);
              getSignSession().publishCACertificate(admin, cmscertificate, ca.getCRLPublishers());
            }
            // Log Action
    		String msg = intres.getLocalizedMessage("caadmin.editedca", cainfo.getName());            	
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED, msg);
        }catch(Exception fe) {
    		String msg = intres.getLocalizedMessage("caadmin.erroreditca", cainfo.getName());            	
            log.error(msg, fe);
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED, msg, fe);
            throw new EJBException(fe);
        }
    } // editCA

    /**
     * Method used to remove a CA from the system. 
     *
     * First there is a check that the CA isn't used by any EndEntity, Profile or AccessRule
     * before it is removed. 
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
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg, e);
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
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED, msg);
        }catch(Exception e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorremoveca", new Integer(caid));            	
            log.error(msg, e);
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED, msg, e);
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
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
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
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);
            }
        }catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorrenameca", oldname);            	
            log.error(msg, fe);
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
            throw new EJBException(fe);
        }
    } // renamewCA

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
            if(cadata.getStatus() == SecConst.CA_ACTIVE && new Date(cadata.getExpireTime()).before(new Date())){
                cadata.setStatus(SecConst.CA_EXPIRED);
            }
            authorizedToCA(admin,cadata.getCaId().intValue());

            cainfo = cadata.getCA().getCAInfo();
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
     * @param admin administrator calling the method
     * @param caid numerical id of CA (subjectDN.hashCode())
     * @return value object or null if CA does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public CAInfo getCAInfo(Admin admin, int caid){
        CAInfo cainfo = null;
        try{
            authorizedToCA(admin,caid);
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            if(cadata.getStatus() == SecConst.CA_ACTIVE && new Date(cadata.getExpireTime()).before(new Date())){
                cadata.setStatus(SecConst.CA_EXPIRED);
            }

            cainfo = cadata.getCA().getCAInfo();
        } catch(javax.ejb.FinderException fe) {
            // ignore
            log.debug("Can nog find CA with id: "+caid);
        } catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorgetcainfo", new Integer(caid));            	
            log.error(msg, e);
            throw new EJBException(e);
        }        
        return cainfo;
    } // getCAInfo

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
     *  Method returning id's of all CA's avaible to the system. i.e. not have status
     * "external" or "waiting for certificate response"
     *
     * @return a Collection (Integer) of available CA id's
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAvailableCAs(Admin admin){
		ArrayList returnval = new ArrayList();
		try{
			Collection result = cadatahome.findAll();
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				CADataLocal cadata = (CADataLocal) iter.next();
				if(cadata.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE && cadata.getStatus() != SecConst.CA_EXTERNAL)
				  returnval.add(cadata.getCaId());
			}
		}catch(javax.ejb.FinderException fe){}

		return returnval;
    }


    /**
     *  Creates a certificate request that should be sent to External Root CA for process before
     *  activation of CA.
     *
     *  @param rootcertificates A Collection of rootcertificates.
     *  @param setstatustowaiting should be set true when creating new CAs and false for renewing old CAs
     *  @return PKCS10RequestMessage
     *  
     * @ejb.interface-method
     */
    public IRequestMessage makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
        PKCS10RequestMessage returnval = null;
        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
            throw new AuthorizationDeniedException(msg);
        }
        
        // Get CA info.
        CADataLocal cadata = null;
        try{
            cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
            CA ca = cadata.getCA();
            
            try{
                // if issuer is insystem CA or selfsigned, then generate new certificate.
                if(ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
                    
                    
                    ca.setRequestCertificateChain(createCertChain(cachain));
                    
                    // generate PKCS10CertificateRequest
                    // TODO implement PKCS10 Certificate Request attributes.
                    ASN1Set attributes = null;
                    
                    /* We don't use these uneccesary attributes
                     DERConstructedSequence kName = new DERConstructedSequence();
                     DERConstructedSet  kSeq = new DERConstructedSet();
                     kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
                     kSeq.addObject(new DERIA5String("foo@bar.se"));
                     kName.addObject(kSeq);
                     req.setAttributes(kName);
                     */
                    
                    PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                            CertTools.stringToBcX509Name(ca.getSubjectDN()), ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), attributes, ca.getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), ca.getCAToken().getProvider());
                    
                    // create PKCS10RequestMessage
                    returnval = new PKCS10RequestMessage(req);
                    // Set statuses.
                    if(setstatustowaiting){
                        cadata.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
                        ca.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
                    }
                    
                    cadata.setCA(ca);
                }else{
                    // Cannot create certificate request for internal CA
            		String msg = intres.getLocalizedMessage("caadmin.errorcertreqinternalca", new Integer(caid));            	
                    getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
                    throw new EJBException(new EjbcaException(msg));
                }
            }catch(CATokenOfflineException e) {                
        		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
                throw e;
            }
        }catch(CertPathValidatorException e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
            throw e;
        }catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcertreq", new Integer(caid));            	
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
            throw new EJBException(e);
        }
        
		String msg = intres.getLocalizedMessage("caadmin.certreqcreated", new Integer(caid));            	
        getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);
        
        return returnval;
    } // makeRequest

    /**
     *  Receives a certificate response from an external CA and sets the newly created CAs status to active.
     * @throws EjbcaException 
     *  
     * @ejb.interface-method
     */
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException{
    	// check authorization
    	Certificate cacert = null;
    	// Check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
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
    	    		String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg");            	
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util. Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    				throw new EjbcaException(msg);
    			}

    			// if issuer is insystem CA or selfsigned, then generate new certificate.
    			if(ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
    				// check the validity of the certificate chain.

    				// Check that DN is the equals the request.
    				if(!CertTools.getSubjectDN((X509Certificate) cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))){
        	    		String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN((X509Certificate) cacert), ca.getSubjectDN());            	
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    					throw new EjbcaException(msg);
    				}

    				ArrayList cachain = new ArrayList();
    				cachain.add(cacert);
    				cachain.addAll(ca.getRequestCertificateChain());

    				ca.setCertificateChain(createCertChain(cachain));
    				// Set statuses.
    				cadata.setStatus(SecConst.CA_ACTIVE);

    				// Publish CA Cert
    		        ArrayList cacertcol = new ArrayList();
    		        cacertcol.add(cacert);
    				getSignSession().publishCACertificate(admin, cacertcol, ca.getCRLPublishers());

    				if(ca instanceof X509CA){
    					cadata.setExpireTime(((X509Certificate) cacert).getNotAfter().getTime());
    				}

    				// activate External CA Services
    				Iterator iter = ca.getExternalCAServiceTypes().iterator();
    				while(iter.hasNext()){
    				    int type = ((Integer) iter.next()).intValue();
    				    try{
    				        ca.initExternalService(type, ca);
    				        ArrayList extcacertificate = new ArrayList();
    				        if(type == ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE){
    				        	extcacertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE)).getOCSPSignerCertificatePath().get(0));
    				        }
    				        if(type == ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE){
    				        	extcacertificate.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE)).getXKMSSignerCertificatePath().get(0));
    				        }
    				        if(type == ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE){
    				        	extcacertificate.add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath().get(0));
    				        }
    				        getSignSession().publishCACertificate(admin, extcacertificate, ca.getCRLPublishers());
    				    }catch(CATokenOfflineException e){
            	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				        getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg,e);
    				        throw e;
    				    }catch(Exception fe){
            	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				        getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,msg,fe);
    				        throw new EJBException(fe);
    				    }
    				}
                    // Save CA
    				cadata.setCA(ca);
                    //  create initial CRL
                    this.getCRLCreateSession().run(admin,ca.getSubjectDN());
    			}else{
    	    		String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", new Integer(caid));            	
    				// Cannot create certificate request for internal CA
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    				throw new EjbcaException(msg);
    			}

    		}catch(CATokenOfflineException e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
    			throw e;
    		} catch (CertificateEncodingException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
        		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
        		throw new EjbcaException(e.getMessage());
			} catch (CertificateException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			} catch (IOException e) {
	    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
	    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
	    		throw new EjbcaException(e.getMessage());
			}
    	}catch(FinderException e){
    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
    		throw new EjbcaException(e.getMessage());
    	} catch (UnsupportedEncodingException e) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcertresp", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg, e);
    		throw new EjbcaException(e.getMessage());
		}

		String msg = intres.getLocalizedMessage("caadmin.certrespreceived", new Integer(caid));            	
    	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);
    } // recieveResponse

    /**
     *  Processes a Certificate Request from an external CA.
     *   
     * @ejb.interface-method
     */
    public IResponseMessage processRequest(Admin admin, CAInfo cainfo, IRequestMessage requestmessage)
    throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException, CATokenOfflineException {
    	CA ca = null;
    	Collection certchain = null;
    	IResponseMessage returnval = null;
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", cainfo.getName());            	
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
    		throw new AuthorizationDeniedException(msg);
    	}

    	// Check that CA doesn't already exists
    	CADataLocal oldcadata = null;
    	try{
    		int caid = cainfo.getCAId();
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
        		String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());            	
    			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
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
    		log.debug("Old castatus="+oldcadata.getStatus());
    		if ( (oldcadata.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) && (oldcadata.getCaId().intValue() == cainfo.getCAId()) && (oldcadata.getName().equals(cainfo.getName())) ) {
    			// Yes, we have all the same DN, CAName and the old CA is waiting for a certificate response
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
    				if(cainfo instanceof X509CAInfo){
    					UserDataVO cadata = new UserDataVO("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), ((X509CAInfo) cainfo).getSubjectAltName(), null,
    							0, 0, 0,  cainfo.getCertificateProfileId(), null, null, 0, 0, null);
    					if(requestmessage instanceof PKCS10RequestMessage){
    					  ExtendedInformation extInfo = new ExtendedInformation();
    					  PKCS10CertificationRequest pkcs10 = ((PKCS10RequestMessage) requestmessage).getCertificationRequest();
    					  extInfo.setCustomData("PKCS10", new String(Base64.encode(pkcs10.getEncoded()))); 
    					  cadata.setExtendedinformation(extInfo);
    					}
    					CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, cainfo.getCertificateProfileId());
    					cacertificate = signca.generateCertificate(cadata, publickey, -1, cainfo.getValidity(), certprofile);
    					returnval = new X509ResponseMessage();
    					returnval.setCertificate(cacertificate);
    				}
    				// Build Certificate Chain
    				Collection rootcachain = signca.getCertificateChain();
    				certchain = new ArrayList();
    				certchain.add(cacertificate);
    				certchain.addAll(rootcachain);

    				if (!processinternalca) {
    					// If this is an internal CA, we don't create it and set a NULL token, since the CA is already created
        				if(cainfo instanceof X509CAInfo){
        					// Create X509CA
        					ca = new X509CA((X509CAInfo) cainfo);
        					ca.setCertificateChain(certchain);
        					CATokenContainer token = new CATokenContainerImpl(new NullCATokenInfo());
        					ca.setCAToken(token);
        				}

        				// set status to active
        				cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);    					
    				}

    				// Publish CA certificates.
    			    getSignSession().publishCACertificate(admin, certchain, signca.getCRLPublishers());

    			}catch(CATokenOfflineException e){
    	    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
    				getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
    				throw e;
    			}
    		}catch(Exception e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
    			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
    			throw new EJBException(e);
    		}

    	}

    	if(certchain != null) {
    		String msg = intres.getLocalizedMessage("caadmin.processedca", cainfo.getName());            	
    		getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);    		
    	}
    	else {
    		String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());            	
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);    		
    	}

    	return returnval;
    } // processRequest

    /**
     *  Renews a existing CA certificate using the same keys as before. Data  about new CA is taken
     *  from database.
     * 
     *  @param certificateresponce should be set with new certificatechain if CA is signed by external
     *         RootCA, otherwise use the null value.
     *  @param keystorepass password used when regenerating keys, can be null if regenerateKeys is false.
     *  @param regenerateKeys, if true and the CA have a softCAToken the keys are regenerated before the certrequest.
     *          
     * @ejb.interface-method
     */
    public void renewCA(Admin admin, int caid, IResponseMessage responsemessage, String keystorepass, boolean regenerateKeys)  throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
    	debug(">CAAdminSession, renewCA(), caid=" + caid);
    	Collection cachain = null;
    	Certificate cacertificate = null;
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
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
        		// Soft keystores can not have empty passwords, it probably mens to use the default one
        		if (caToken.getCATokenInfo() instanceof SoftCATokenInfo) {
            		if (StringUtils.isEmpty(keystorepass)) {
            			keystorepass = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");          		
                		if (keystorepass == null) {
                			log.error("Missing keyStorePass property. We can not autoActivate standard soft CA tokens.");
                			throw new IllegalArgumentException("Missing keyStorePass property.");		    		
                		}
            		}        			
        		}
        		caToken.generateKeys(keystorepass, renew);
    			ca.setCAToken(caToken);
    		}
    		
    		try{
    			// if issuer is insystem CA or selfsigned, then generate new certificate.
    			if(ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA){
    				if(ca.getSignedBy() == CAInfo.SELFSIGNED){
    					// create selfsigned certificate
    					if( ca instanceof X509CA){
    						UserDataVO cainfodata = new UserDataVO("nobody",  ca.getSubjectDN(), ca.getSubjectDN().hashCode(), ((X509CA) ca).getSubjectAltName(), null,
    								0, 0, 0, ca.getCertificateProfileId(), null, null, 0, 0 ,null);

    						CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());
    						cacertificate = ca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, ca.getValidity(), certprofile);
    					}
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
    						if( ca instanceof X509CA){
    							UserDataVO cainfodata = new UserDataVO("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), ((X509CA) ca).getSubjectAltName(), null,
    									0,0,0, ca.getCertificateProfileId(), null, null, 0,0, null);

    							CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());
    							cacertificate = signca.generateCertificate(cainfodata, ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN),-1, ca.getValidity(), certprofile);
    						}

    						// Build Certificate Chain
    						Collection rootcachain = signca.getCertificateChain();
    						cachain = new ArrayList();
    						cachain.add(cacertificate);
    						cachain.addAll(rootcachain);
    					}
    				}
    			}else{
    				// if external signer then use signed certificate.
    				// check the validity of the certificate chain.
    				if(responsemessage instanceof X509ResponseMessage){
    					cacertificate = ((X509ResponseMessage) responsemessage).getCertificate();
    				}else{
    	        		String msg = intres.getLocalizedMessage("error.errorcertrespillegalmsg");            	
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    					throw new EJBException(new EjbcaException(msg));
    				}

    				// Check that DN is the equals the request.
    				if(!CertTools.getSubjectDN((X509Certificate) cacertificate).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))){
        	    		String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN((X509Certificate) cacertificate), ca.getSubjectDN());            	
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    					throw new EJBException(new EjbcaException(msg));
    				}

    				cachain = new ArrayList();
    				cachain.add(cacertificate);
    				cachain.addAll(ca.getRequestCertificateChain());

    				cachain = createCertChain(cachain);

    			}
    			// Set statuses.
    			if(cacertificate instanceof X509Certificate)
    				cadata.setExpireTime(((X509Certificate) cacertificate).getNotAfter().getTime());
    			cadata.setStatus(SecConst.CA_ACTIVE);

    			ca.setCertificateChain(cachain);
    			cadata.setCA(ca);

    			// Publish the new CA certificate
                 ArrayList cacert = new ArrayList();
                 cacert.add(ca.getCACertificate());
     			 getSignSession().publishCACertificate(admin, cacert, ca.getCRLPublishers());


    		}catch(CATokenOfflineException e){
	    		String msg = intres.getLocalizedMessage("caadmin.errorrenewca", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
    			throw e;
    		}
    	}catch(Exception e){
    		String msg = intres.getLocalizedMessage("caadmin.errorrenewca", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,e);
    		throw new EJBException(e);
    	}
		String msg = intres.getLocalizedMessage("caadmin.renewdca", new Integer(caid));            	
    	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CARENEWED,msg);
    	debug("<CAAdminSession, renewCA(), caid=" + caid);
    } // renewCA

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
			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,e);
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
			getCertificateStoreSession().revokeCertificate(admin, cadata.getCACertificate(), cadata.getCRLPublishers(), reason);
             // Revoke all certificates generated by CA
			if(cadata.getStatus() != SecConst.CA_EXTERNAL){
		      getCertificateStoreSession().revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);		    
              getCRLCreateSession().run(admin, issuerdn);
			}
			
			cadata.setRevokationReason(reason);
			cadata.setRevokationDate(new Date());
			if(cadata.getStatus() != SecConst.CA_EXTERNAL){
		  	  ca.setStatus(SecConst.CA_REVOKED);
			}
			ca.setCA(cadata);

        }catch(Exception e){
        	String msg = intres.getLocalizedMessage("caadmin.errorrevoke", ca.getName());            	
        	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAREVOKED,msg,e);
        	throw new EJBException(e);
        }

    	String msg = intres.getLocalizedMessage("caadmin.revokedca", ca.getName(), new Integer(reason));            	
		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAREVOKED,msg);
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
            if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER)
              getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");

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
            		htokeninfo.setClassPath("org.ejbca.core.model.ca.catoken.NFastCAToken");
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
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"An error occured when trying to upgrade hard token classpath", e);
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
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
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
            X509Certificate caSignatureCertificate = (X509Certificate) signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            if ( p12PublicSignatureKey instanceof RSAPublicKey ) {
                p12PrivateSignatureKey = (PrivateKey) keystore.getKey( privateSignatureKeyAlias, privkeypass.toCharArray());
            } else {
            	p12PrivateSignatureKey = (ECPrivateKey) keystore.getKey( privateSignatureKeyAlias, privkeypass.toCharArray());
                log.debug("ImportSignatureKeyAlgorithm (expecting ECDSA)="+((ECPrivateKey) keystore.getKey( privateSignatureKeyAlias, privkeypass.toCharArray())).getAlgorithm());
            }
            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            X509Certificate caEncryptionCertificate = null;
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
	            caEncryptionCertificate = (X509Certificate) encryptionCertChain[0];
	            p12PrivateEncryptionKey = (PrivateKey) keystore.getKey( privateEncryptionKeyAlias, privkeypass.toCharArray());
	            p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            }
            // Transform into token
            SoftCATokenInfo sinfo = new SoftCATokenInfo();
            CATokenContainer catoken = new CATokenContainerImpl(sinfo);
            catoken.importKeys(keystorepass, p12PrivateSignatureKey, p12PublicSignatureKey, p12PrivateEncryptionKey,
            			p12PublicEncryptionKey, signatureCertChain);
            log.debug("CA-Info: "+catoken.getCATokenInfo().getSignatureAlgorithm() + " " + catoken.getCATokenInfo().getEncryptionAlgorithm());
            // Identify the key algorithms for extended CA services, OCSP, XKMS, CMS
            String keyAlgorithm = CATokenConstants.KEYALGORITHM_RSA;
            String keySpecification = "2048";
            if (!(p12PublicSignatureKey instanceof RSAPublicKey)) {
            	Enumeration en = ECNamedCurveTable.getNames();
            	while ( en.hasMoreElements() ) {
            		String currentCurveName = (String) en.nextElement();
            		if ( (ECNamedCurveTable.getParameterSpec(currentCurveName)).getCurve().equals( ((ECPrivateKey) p12PrivateSignatureKey).getParameters().getCurve() ) ) {
            			keySpecification = currentCurveName;
            			keyAlgorithm = CATokenConstants.KEYALGORITHM_ECDSA;
            			break;
            		}
            	}
            }
            // Do the general import
            CA ca = importCA(admin, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    		String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED, msg);
        } catch(Exception e) {
        	String msg = intres.getLocalizedMessage("caadmin.errorimportca", caname, "PKCS12", e.getMessage());
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED, msg, e);
            throw new EJBException(e);
        }
    } // importCAFromKeyStore

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
		String signatureAlgorithm = CertTools.getSignatureAlgorithm((X509Certificate) signatureCertChain[0]);
    	HardCATokenInfo hardcatokeninfo = new HardCATokenInfo();
    	hardcatokeninfo.setAuthenticationCode(catokenpassword);
    	hardcatokeninfo.setCATokenStatus(ICAToken.STATUS_ACTIVE);
    	hardcatokeninfo.setClassPath(catokenclasspath);
    	hardcatokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA1_WITH_RSA);
    	hardcatokeninfo.setProperties(catokenproperties);
    	hardcatokeninfo.setSignatureAlgorithm(signatureAlgorithm);

        CATokenInfo catokeninfo = hardcatokeninfo;
        CATokenContainer catoken = new CATokenContainerImpl(catokeninfo);
        catoken.activate(catokenpassword);

        X509Certificate caSignatureCertificate = (X509Certificate) signatureCertChain[0];
        
        String keyAlgorithm = CATokenConstants.KEYALGORITHM_RSA;
        String keySpecification = "2048";
        // Do the general import
        CA ca = importCA(admin, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    }

    /**
     * 
     * @param admin
     * @param caname
     * @param keystorepass
     * @param signatureCertChain
     * @param catoken
     * @param keyAlgorithm keyalgorithm for extended CA services, OCSP, XKMS, CMS. Example CATokenConstants.KEYALGORITHM_RSA
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
		// Create a X509CA
		int signedby = CAInfo.SIGNEDBYEXTERNALCA;
		int certprof = SecConst.CERTPROFILE_FIXED_SUBCA;
		String description = "Imported external signed CA";
		X509Certificate caSignatureCertificate = (X509Certificate)signatureCertChain[0];
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
				log.error("Cannot import CA " + caSignatureCertificate.getSubjectDN().getName()
						+ ": certificate " + caSignatureCertificate.getSerialNumber()
						+ " is not self-signed.");
				throw new Exception("Cannot import CA "
						+ caSignatureCertificate.getSubjectDN().getName()
						+ ": certificate is not self-signed. Check "
						+ "certificate chain in PKCS#12");
			}
		} else if (signatureCertChain.length > 1){
			Collection cas = getAvailableCAs(admin);
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
					X509Certificate superCaCert = (X509Certificate)i.next();
					if (verifyIssuer(caSignatureCertificate, superCaCert)) {
						signedby = caid;
						description = "Imported sub CA";
						break;
					}
				}
			}					
		}
		// Create and active extended CA Services (OCSP, XKMS, CMS).
		ArrayList extendedcaservices = new ArrayList();
		extendedcaservices.add(
				new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
		                        "CN=OCSPSignerCertificate, " + caSignatureCertificate.getSubjectDN().toString(),
		                        "",
		                        keySpecification,
		                        keyAlgorithm));
		// Create and active XKMS CA Service.
		extendedcaservices.add(
		        new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
		                              "CN=XKMSCertificate, " + caSignatureCertificate.getSubjectDN().toString(),
		                              "",
		                              keySpecification,
		                              keyAlgorithm));
		// Create and active CMS CA Service.
		extendedcaservices.add(
		        new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
		                              "CN=CMSCertificate, " + caSignatureCertificate.getSubjectDN().toString(),
		                              "",
		                              keySpecification,
		                              keyAlgorithm));
		int validity = (int)((caSignatureCertificate.getNotAfter().getTime() - caSignatureCertificate.getNotBefore().getTime()) / (24*3600*1000));
		X509CAInfo cainfo = new X509CAInfo(caSignatureCertificate.getSubjectDN().toString(),
		                                   caname, SecConst.CA_ACTIVE, new Date(), 
		                                   "", certprof,
		                                   validity,
		                                   caSignatureCertificate.getNotAfter(), // Expiretime
		                                   CAInfo.CATYPE_X509,
		                                   signedby,
		                                   certificatechain,
		                                   catoken.getCATokenInfo(),
		                                   description,
		                                   -1, null, // revokationreason, revokationdate
		                                   "", // PolicyId
		                                   24, // CRLPeriod
		                                   0, // CRLIssuePeriod
		                                   10, // CRLOverlapTime
		                                   new ArrayList(),
		                                   true, // Authority Key Identifier
		                                   false, // Authority Key Identifier Critical
		                                   true, // CRL Number
		                                   false, // CRL Number Critical
		                                   "", // Default CRL Dist Point
		                                   "", // Default CRL Issuer
		                                   "", // Default OCSP Service Locator                                               
		                                   true, // Finish User
		                                   extendedcaservices,
		                                   false, // use default utf8 settings
		                                   new ArrayList(), // Approvals Settings
		                                   1, // Number of Req approvals
		                                   false, // Use UTF8 subject DN by default
		                                   true // Use LDAP DN order by default
		                                   );
		X509CA ca = new X509CA(cainfo);
		// We must activate the token, in case it does not have the default password
		catoken.activate(keystorepass);
		ca.setCAToken(catoken);
		ca.setCertificateChain(certificatechain);
		log.debug("CA-Info: "+catoken.getCATokenInfo().getSignatureAlgorithm() + " " + ca.getCAToken().getCATokenInfo().getEncryptionAlgorithm());
		//  Publish CA certificates.
		getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers());
		// activate External CA Services
		Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
		while(iter.hasNext()){
		    ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
		    if(info instanceof OCSPCAServiceInfo){
		        try{
		            ca.initExternalService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, ca);
		            ArrayList ocspcertificate = new ArrayList();
		            ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE)).getOCSPSignerCertificatePath().get(0));
		            getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers());
		        }catch(Exception fe){
		            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
		            throw new EJBException(fe);
		        }
		    }
		    if(info instanceof XKMSCAServiceInfo){
		        try{
		            ca.initExternalService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, ca);
		            ArrayList xkmscertificate = new ArrayList();
		            xkmscertificate.add(((XKMSCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE)).getXKMSSignerCertificatePath().get(0));
		            getSignSession().publishCACertificate(admin, xkmscertificate, ca.getCRLPublishers());
		        }catch(Exception fe){
		            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
		            throw new EJBException(fe);
		        }
		    }
		    if(info instanceof CmsCAServiceInfo){
		        try{
		            ca.initExternalService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE, ca);
		            ArrayList cmscertificate = new ArrayList();
		            cmscertificate.add(((CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath().get(0));
		            getSignSession().publishCACertificate(admin, cmscertificate, ca.getCRLPublishers());
		        }catch(Exception fe){
		            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
		            throw new EJBException(fe);
		        }
		    }
		}
		// Store CA in database.
		cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_ACTIVE, ca);
		this.getCRLCreateSession().run(admin,cainfo.getSubjectDN());
		
		return ca;
	}
    
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
     * @return A byte array of the CAs p12.
     * 
     * @ejb.interface-method
     */
    public byte[] exportCAKeyStore(Admin admin, String caname, String keystorepass, String privkeypass, String privateSignatureKeyAlias, 
    		String privateEncryptionKeyAlias) throws Exception {
        log.debug(">exportCAKeyStore");               
        try {
	    	CA thisCa = cadatahome.findByName(caname).getCA();
			// Make sure we are not trying to export a hard or invalid token
	    	if ( thisCa.getCAType() != CATokenInfo.CATOKENTYPE_P12 ) {
	    		throw new Exception("Cannot export anything but a soft token.");
	    	}
	    	// Check authorization
			if(admin.getAdminType() != Admin.TYPE_CACOMMANDLINE_USER) {
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
			}
            // Fetch keys
	    	CATokenContainer thisCAToken = thisCa.getCAToken();
	    	// This is a way of verifying the passowrd. If activate fails, we will get an exception and the export will not proceed
	    	thisCAToken.activate(keystorepass);
	    	
	    	// Proceed with the export
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(null, keystorepass.toCharArray());
            
            PrivateKey p12PrivateEncryptionKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
	    	PublicKey p12PublicEncryptionKey = thisCAToken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
            PrivateKey p12PrivateCertSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
	    	PrivateKey p12PrivateCRLSignKey = thisCAToken.getPrivateKey(SecConst.CAKEYPURPOSE_CRLSIGN);
	    	if ( !p12PrivateCertSignKey.equals(p12PrivateCRLSignKey) ) {
	    		throw new Exception("Assertion of equal signature keys failed.");
	    	}
	    	// Load keys into keystore
	    	X509Certificate[] certificateChainSignature = (X509Certificate[]) thisCa.getCertificateChain().toArray(new X509Certificate[0]);
	    	X509Certificate[] certificateChainEncryption = new X509Certificate[1];
	    	//certificateChainSignature[0].getSigAlgName(), 
            // generate dummy certificate for encryption key.
	    	certificateChainEncryption[0] = CertTools.genSelfCertForPurpose("CN=dummy2", 36500, null, p12PrivateEncryptionKey, p12PublicEncryptionKey,
	    			thisCAToken.getCATokenInfo().getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment);
	    	log.debug("Exporting with sigAlgorithm "+certificateChainSignature[0].getSigAlgName()+"encAlgorithm="+thisCAToken.getCATokenInfo().getEncryptionAlgorithm());
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
        	String msg = intres.getLocalizedMessage("caadmin.exportedca", caname, "PKCS12");
	        getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEXPORTED, msg);
    		return baos.toByteArray();
	    } catch(Exception e){
        	String msg = intres.getLocalizedMessage("caadmin.errorexportca", caname, "PKCS12", e.getMessage());
	        getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEXPORTED, msg, e);
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
    public Collection getAllCACertificates(Admin admin){
      ArrayList returnval = new ArrayList();

      try{
          Collection caids = getAvailableCAs(admin);
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
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
			}
			CA thisCa;
			thisCa = cadatahome.findByName(caname).getCA();

			// Make sure we are not trying to export a hard or invalid token
			if ( thisCa.getCAType() != CATokenInfo.CATOKENTYPE_P12 ) {
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
     * 
     *  @throws AuthorizationDeniedException it the administrator isn't authorized to activate the CA.
     *  @throws CATokenAuthenticationFailedException if the current status of the ca or authenticationcode is wrong.
     *  @throws CATokenOfflineException if the CA token is still offline when calling the method.
     *  
     * @ejb.interface-method
     */
    public void activateCAToken(Admin admin, int caid, String authorizationcode) throws AuthorizationDeniedException, CATokenAuthenticationFailedException, CATokenOfflineException{
       // Authorize
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_ACTIVATECA);
        }catch(AuthorizationDeniedException ade){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", new Integer(caid));            	
            getLogSession().log (admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,ade);
            throw new AuthorizationDeniedException(msg);
        }

    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
        		String msg = intres.getLocalizedMessage("caadmin.erroractivatetoken", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
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
    				cadata.setStatus(SecConst.CA_ACTIVE);
    				// Invalidate CA cache to refresh information
    				CACacheManager.instance().removeCA(cadata.getCaId().intValue());
            		String msg = intres.getLocalizedMessage("caadmin.catokenactivated", cadata.getName());            	
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);
    			} catch (IllegalKeyStoreException e) {
                    throw new EJBException(e);
    			} catch (UnsupportedEncodingException e) {
                    throw new EJBException(e);
    			}
    		}else{
        		String msg = intres.getLocalizedMessage("caadmin.errornotoffline", cadata.getName());            	
				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
				throw new CATokenAuthenticationFailedException(msg);
    		}
    	}catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    		throw new EJBException(fe);
    	}
    }

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
            getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_ACTIVATECA);
        }catch(AuthorizationDeniedException ade){
    		String msg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken", new Integer(caid));            	
            getLogSession().log (admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg,ade);
            throw new AuthorizationDeniedException(msg);
        }

    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
                // This should never happen.
        		String msg = intres.getLocalizedMessage("caadmin.errordeactivatetoken", new Integer(caid));            	
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
    			throw new EjbcaException(msg);
    		}
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            if(cadata.getStatus() == SecConst.CA_ACTIVE){
            	try {
            		cadata.getCA().getCAToken().deactivate();
            		cadata.setStatus(SecConst.CA_OFFLINE);
    				// Invalidate CA cache to refresh information
    				CACacheManager.instance().removeCA(cadata.getCaId().intValue());
            		String msg = intres.getLocalizedMessage("caadmin.catokendeactivated", cadata.getName());            	
            		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,msg);
            	} catch (IllegalKeyStoreException e) {
            		throw new EJBException(e);
            	} catch (UnsupportedEncodingException e) {
            		throw new EJBException(e);
            	}
            }else{
        		String msg = intres.getLocalizedMessage("caadmin.errornotonline", cadata.getName());            	
            	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
            	throw new EjbcaException(msg);
            }
    	}catch(javax.ejb.FinderException fe) {
    		String msg = intres.getLocalizedMessage("caadmin.errorcanotfound", new Integer(caid));            	
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg);
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

    private boolean authorizedToCA(Admin admin, int caid){
      boolean returnval = false;
      try{
        returnval = getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + caid);
      }catch(AuthorizationDeniedException e){}
      return returnval;
    }

    //
    // Private methods
    //
	
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
    } //getLogSession


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
      if(jobrunner == null){
         try{
            ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) getLocator().getLocalHome(ICreateCRLSessionLocalHome.COMP_NAME);
            jobrunner = home.create();
         }catch(Exception e){
            throw new EJBException(e);
         }
      }
      return jobrunner;
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
    } //getCertificateStoreSession

    /** Gets connection to sign session bean
     * @return Connection
     */
    private ISignSessionLocal getSignSession() {
        if(signsession == null){
            try{
                ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) getLocator().getLocalHome(ISignSessionLocalHome.COMP_NAME);
                signsession = signsessionhome.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return signsession;
    } //getSignSession

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
	private boolean verifyIssuer(X509Certificate subject, X509Certificate issuer) throws Exception {
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
    	X509Certificate signcert = (X509Certificate) signcadata.getCA().getCACertificate();
    	try{
    		signcert.checkValidity();
    	}catch(CertificateExpiredException ce){
    		// Signers Certificate has expired.
    		signcadata.setStatus(SecConst.CA_EXPIRED);
    		String msg = intres.getLocalizedMessage("signsession.caexpired", signcadata.getSubjectDN());            	
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,ce);
    		throw new EJBException(ce);
    	}catch(CertificateNotYetValidException cve){
    		String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signcadata.getSubjectDN());            	
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,msg,cve);
    		throw new EJBException(cve);
    	}
    }

    /**
     * Method to create certificate path and to check it's validity from a list of certificates.
     * The list of certificates should only contain one root certificate.
     *
     * @param certlist
     * @return the certificatepath
     */
    private Collection createCertChain(Collection certlist) throws CertPathValidatorException{
       ArrayList returnval = new ArrayList();

	   certlist = orderCertificateChain(certlist);

	    // set certificate chain
       TrustAnchor trustanchor = null;
       ArrayList calist = new ArrayList();
       Iterator iter = certlist.iterator();
       while(iter.hasNext()){
	      Certificate next = (Certificate) iter.next();
	      if(next instanceof X509Certificate && CertTools.isSelfSigned(((X509Certificate) next))){
		      trustanchor = new TrustAnchor((X509Certificate) next, null);
	      }
	      else{
	     	calist.add(next);
	      }
     }

     if(calist.size() == 0){
     	// only one root cert, no certchain
		returnval.add(trustanchor.getTrustedCert());
     }else{
      try {
	    HashSet trustancors = new HashSet();
	    trustancors.add(trustanchor);

		//CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters( certlist );
		//CertStore store = CertStore.getInstance("Collection", ccsp );


	    // Create the parameters for the validator
	    PKIXParameters params = new PKIXParameters(trustancors);

	    // Disable CRL checking since we are not supplying any CRLs
	    params.setRevocationEnabled(false);
		//params.addCertStore(store);
		params.setDate( new Date() );
	    // Create the validator and validate the path

	    CertPathValidator certPathValidator
		    = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), "BC");
        CertificateFactory fact = CertTools.getCertificateFactory();
	    CertPath certpath = fact.generateCertPath(calist);

	    iter = certpath.getCertificates().iterator();


	    CertPathValidatorResult result = certPathValidator.validate(certpath, params);

	    // Get the CA used to validate this path
	    PKIXCertPathValidatorResult pkixResult = (PKIXCertPathValidatorResult)result;
	    returnval.addAll(certpath.getCertificates());

	    //c a.setRequestCertificateChain(certpath.getCertificates());
	    TrustAnchor ta = pkixResult.getTrustAnchor();
	    X509Certificate cert = ta.getTrustedCert();
	    returnval.add(cert);
      } catch (CertPathValidatorException e) {
	    throw e;
      }  catch(Exception e){
	    throw new EJBException(e);
      }
     }


     return returnval;
  }

  /**
   * Method ordering a list of x509certificate into a certificate path with to ca at the end.
   * Does not check validity or verification of any kind, just ordering by issuerdn.
   * @param certlist list of certificates to order.
   * @return Collection with certificatechain.
   */
  private Collection orderCertificateChain(Collection certlist) throws CertPathValidatorException{
  	 ArrayList returnval = new ArrayList();
     X509Certificate rootca = null;
  	 HashMap cacertmap = new HashMap();
  	 Iterator iter = certlist.iterator();
  	 while(iter.hasNext()){
  	 	X509Certificate cert = (X509Certificate) iter.next();
  	    if(CertTools.isSelfSigned(cert))
  	      rootca = cert;
  	    else {
  	    	log.debug("Adding to cacertmap with index '"+cert.getIssuerDN().toString()+"'");
  	    	cacertmap.put(cert.getIssuerDN().toString(),cert);
  	    }
  	 }

  	 if(rootca == null)
  	   throw new CertPathValidatorException("No root CA certificate found in certificatelist");

  	 returnval.add(0,rootca);
  	 X509Certificate currentcert = rootca;
  	 int i =0;
  	 while(certlist.size() != returnval.size() && i <= certlist.size()){
  		 log.debug("Looking in cacertmap for '"+currentcert.getSubjectDN().toString()+"'");
  	 	X509Certificate nextcert = (X509Certificate) cacertmap.get(currentcert.getSubjectDN().toString());
  	 	if(nextcert == null)
		  throw new CertPathValidatorException("Error building certificate path");

		returnval.add(0,nextcert);
		currentcert = nextcert;
  	 	i++;
  	 }

  	 if(i > certlist.size())
	  throw new CertPathValidatorException("Error building certificate path");


  	 return returnval;
  }


} //CAAdminSessionBean
