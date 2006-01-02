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

package se.anatom.ejbca.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.bouncycastle.asn1.ASN1Set;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAService;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.hardcatokens.HardCATokenManager;
import se.anatom.ejbca.ca.crl.ICreateCRLSessionLocal;
import se.anatom.ejbca.ca.crl.ICreateCRLSessionLocalHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.CertificateDataBean;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.common.ExtendedPKCS10CertificationRequest;
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.exception.EjbcaException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.protocol.X509ResponseMessage;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

/**
 * Administrates and manages CAs in EJBCA system.
 *
 * @version $Id: CAAdminSessionBean.java,v 1.49 2006-01-02 15:23:07 anatom Exp $
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

 * @ejb.env-entry description="Password for OCSP keystores"
 *   name="OCSPKeyStorePass"
 *   type="java.lang.String"
 *   value="${ca.ocspkeystorepass}"
 *
 * @ejb.ejb-external-ref description="The CA entity bean"
 *   view-type="local"
 *   ejb-name="CADataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.ca.caadmin.ICADataLocalHome"
 *   business="se.anatom.ejbca.ca.caadmin.ICADataLocal"
 *   link="CAData"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   business="se.anatom.ejbca.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ejb-name="AuthorizationSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome"
 *   business="se.anatom.ejbca.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ejb-name="CertificateStoreSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome"
 *   business="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ejb-name="RSASignSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.sign.ISignSessionLocalHome"
 *   business="se.anatom.ejbca.ca.store.ISignSessionLocal"
 *   link="RSASignSession"
 *
 * @ejb.ejb-external-ref description="The CRL Create bean"
 *   view-type="local"
 *   ejb-name="CreateCRLSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.crl.ICreateCRLSessionLocalHome"
 *   business="se.anatom.ejbca.ca.crl.ICreateCRLSessionLocal"
 *   link="CreateCRLSession"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   remote-class="se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   remote-class="se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal"
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
     *  @see se.anatom.ejbca.ca.caadmin.CAInfo
     *  @see se.anatom.ejbca.ca.caadmin.X509CAInfo
     *  
     * @ejb.interface-method
     * @jboss.method-attributes transaction-timeout="900"
     */
    public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException, CATokenOfflineException, CATokenAuthenticationFailedException{
    	int castatus = SecConst.CA_OFFLINE;
        // Check that administrat has superadminsitrator rights.
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException ade){
            getLogSession().log (admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to create CA",ade);
            throw new AuthorizationDeniedException("Administrator not authorized to create CA");
        }
                // Check that CA doesn't already exists
        try{
            int caid = cainfo.getCAId();
            if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA already exists.");
                throw new CAExistsException();
            }
            cadatahome.findByPrimaryKey(new Integer(caid));
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA already exists.");
            throw new CAExistsException();
        }catch(javax.ejb.FinderException fe) {}

        try{
            cadatahome.findByName(cainfo.getName());
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA name already exists.");
            throw new CAExistsException("CA Name already exists");
        }catch(javax.ejb.FinderException fe) {}

        // Create CAToken
        CAToken catoken = null;
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        if(catokeninfo instanceof SoftCATokenInfo){
            try{
                catoken = new SoftCAToken();
                ((SoftCAToken) catoken).generateKeys(catokeninfo);
            }catch(Exception e){
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when creating CA token.",e);
                throw new EJBException(e);
            }
        }
        if(catokeninfo instanceof HardCATokenInfo){
        	catoken = new HardCATokenContainer();
        	((HardCATokenContainer) catoken).updateCATokenInfo(catokeninfo);
        	try{
        		catoken.activate(((HardCATokenInfo) catokeninfo).getAuthenticationCode());
        	}catch(CATokenAuthenticationFailedException ctaf){
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when creating hard CA token. Authorization code was wrong.",ctaf);
        		throw ctaf;
        	}catch(CATokenOfflineException ctoe){
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when creating hard CA token. CA token is offline.",ctoe);
        		throw ctoe;
        	}
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
              	getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Root CA.",e);
            	throw e;
              }catch(Exception fe){
                 getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Root CA.",fe);
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
            		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Sub CA.",e);
            		throw e;
            	}catch(Exception fe){
            		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Sub CA.",fe);
            		throw new EJBException(fe);
            	}
            }

            // Set Certificate Chain
            x509ca.setCertificateChain(certificatechain);

        }

        //	Publish CA certificates.

           int certtype = CertificateDataBean.CERTTYPE_SUBCA;
           if(ca.getSignedBy() == CAInfo.SELFSIGNED)
          	  certtype = CertificateDataBean.CERTTYPE_ROOTCA;
           getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), certtype);



		     if(castatus ==SecConst.CA_ACTIVE){
		     	// activate External CA Services
		     	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
		     	while(iter.hasNext()){
		     	  ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
		     	  if(info instanceof OCSPCAServiceInfo){
		     	  	try{
		     	  	  ca.initExternalService(OCSPCAService.TYPE, ca);
		     	  	  ArrayList ocspcertificate = new ArrayList();
		     	  	  ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(OCSPCAService.TYPE)).getOCSPSignerCertificatePath().get(0));
					  getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), CertificateDataBean.CERTTYPE_ENDENTITY);
				    }catch(Exception fe){
					  getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
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
            getLogSession().log(admin, ca.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED,"CA created successfully, status: " + castatus);
        }catch(javax.ejb.CreateException e){
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when trying to create CA.");
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
     *  @see se.anatom.ejbca.ca.caadmin.CAInfo
     *  @see se.anatom.ejbca.ca.caadmin.X509CAInfo
     *  
     * @ejb.interface-method
     */
    public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException{
        boolean ocsprenewcert = false;

        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to edit CA",e);
            throw new AuthorizationDeniedException("Not authorized to edit CA with caid = " + cainfo.getCAId());
        }

        // Check if OCSP Certificate is about to be renewed.
        Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
        while(iter.hasNext()){
          Object next = iter.next();
          if(next instanceof OCSPCAServiceInfo)
            ocsprenewcert = ((OCSPCAServiceInfo) next).getRenewFlag();
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
              getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), CertificateDataBean.CERTTYPE_ENDENTITY);
            }
            // Log Action
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"");
        }catch(Exception fe) {
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Edit CA.",fe);
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
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to remove CA",e);
            throw new AuthorizationDeniedException("Not authorized to remove CA with caid = " + caid);
        }
        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            // Remove CA
            cadata.remove();
            // Remove an eventual CA token from the token registry
            HardCATokenManager.instance().addCAToken(caid, null);
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA Removed");
        }catch(Exception e) {
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to remove CA.",e);
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
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to rename CA",e);
                throw new AuthorizationDeniedException("Not authorized to rename CA with caid = " + caid);
            }

            try{
                CADataLocal cadatanew = cadatahome.findByName(newname);
                cadatanew.getCaId();
                throw new CAExistsException(" CA name " + newname + " already exists.");
            }catch(javax.ejb.FinderException fe) {
                // new CA doesn't exits, it's ok to rename old one.
                cadata.setName(newname);
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA : " + oldname + " renamed to " + newname);
            }
        }catch(javax.ejb.FinderException fe) {
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to rename CA.");
            throw new EJBException(fe);
        }
    } // renewCA

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
            CATokenInfo catokeninfo = cadata.getCA().getCAToken().getCATokenInfo();
            if(catokeninfo instanceof HardCATokenInfo && ((HardCATokenInfo) catokeninfo).getCATokenStatus() == IHardCAToken.STATUS_OFFLINE){
                cadata.setStatus(SecConst.CA_OFFLINE);
            }
            cainfo = cadata.getCA().getCAInfo();
        } catch(javax.ejb.FinderException fe) {             
            // ignore
            log.debug("Can nog find CA with name: "+name);
        } catch(Exception e) {
            log.error("Error getting CA info: ", e);
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
            CATokenInfo catokeninfo = cadata.getCA().getCAToken().getCATokenInfo();
            if(catokeninfo instanceof HardCATokenInfo && ((HardCATokenInfo) catokeninfo).getCATokenStatus() == IHardCAToken.STATUS_OFFLINE){
                cadata.setStatus(SecConst.CA_OFFLINE);
            }
            cainfo = cadata.getCA().getCAInfo();
        } catch(javax.ejb.FinderException fe) {
            // ignore
            log.debug("Can nog find CA with id: "+caid);
        } catch(Exception e){
            log.error("Error getting CA info: ", e);
            throw new EJBException(e);
        }        
        return cainfo;
    } // getCAInfo

    /**
     * Returns a HashMap containing mappings of caid to CA name of all CAs in the system.
     * 
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
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Not authorized to make certificate request for CA",e);
            throw new AuthorizationDeniedException("Not authorized to make certificate request for CA with caid = " + caid);
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
                    
                    ExtendedPKCS10CertificationRequest req = new ExtendedPKCS10CertificationRequest("SHA1WithRSA",
                            CertTools.stringToBcX509Name(ca.getSubjectDN()), ca.getCAToken().getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN), attributes, ca.getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN));
                    
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
                    getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: cannot create certificate request for internal CA");
                    throw new EJBException(new EjbcaException("Error: cannot create certificate request for internal CA"));
                }
            }catch(CATokenOfflineException e) {
                ca.setStatus(SecConst.CA_OFFLINE);
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when creating certificate request",e);
                throw e;
            }
        }catch(CATokenOfflineException e) {
            throw e;
        }catch(CertPathValidatorException e) {
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when creating certificate request",e);
            throw e;
        }catch(Exception e){
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when creating certificate request",e);
            throw new EJBException(e);
        }
        
        getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"Certificate request generated successfully.");
        
        return returnval;
    } // makeRequest

    /**
     *  Receives a certificate response from an external CA and sets the newly created CAs status to active.
     *  
     * @ejb.interface-method
     */
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
    	// check authorization
    	Certificate cacert = null;
    	// Check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Not authorized to recieve certificate responce for CA",e);
    		throw new AuthorizationDeniedException("Not authorized to recieve certificate responce for CA with caid = " + caid);
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
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util. Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: illegal response message.");
    				throw new EJBException(new EjbcaException("Error: illegal response message."));
    			}

    			// if issuer is insystem CA or selfsigned, then generate new certificate.
    			if(ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
    				// check the validity of the certificate chain.

    				// Check that DN is the equals the request.
    				if(!CertTools.getSubjectDN((X509Certificate) cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))){
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: Subject DN of recieved certificate doesn't match request");
    					throw new EJBException(new EjbcaException("Error: Subject DN of recieved certificate doesn't match request"));
    				}

    				ArrayList cachain = new ArrayList();
    				cachain.add(cacert);
    				cachain.addAll(ca.getRequestCertificateChain());

    				ca.setCertificateChain(createCertChain(cachain));
    				// Set statuses.
    				cadata.setStatus(SecConst.CA_ACTIVE);

    				// Publish CA Cert
    				int certtype = CertificateDataBean.CERTTYPE_SUBCA;
    		           if(ca.getSignedBy() == CAInfo.SELFSIGNED)
    		          	  certtype = CertificateDataBean.CERTTYPE_ROOTCA;
    		        ArrayList cacertcol = new ArrayList();
    		        cacertcol.add(cacert);
    				getSignSession().publishCACertificate(admin, cacertcol, ca.getCRLPublishers(), certtype);

    				if(ca instanceof X509CA){
    					cadata.setExpireTime(((X509Certificate) cacert).getNotAfter().getTime());
    				}

    				if(cadata.getStatus() ==SecConst.CA_ACTIVE){
    					// activate External CA Services
    					Iterator iter = ca.getExternalCAServiceTypes().iterator();
    					while(iter.hasNext()){
    						int type = ((Integer) iter.next()).intValue();
    						try{
    							ca.initExternalService(type, ca);
    							ArrayList ocspcertificate = new ArrayList();
    							ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(OCSPCAService.TYPE)).getOCSPSignerCertificatePath().get(0));
    							getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), CertificateDataBean.CERTTYPE_ENDENTITY);
    						}catch(CATokenOfflineException e){
    							ca.setStatus(SecConst.CA_OFFLINE);
    							getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Initialize ExternalCAService.",e);
    							throw e;
    						}catch(Exception fe){
    							getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Initialize ExternalCAService.",fe);
    							throw new EJBException(fe);
    						}
    					}
    					//  create initial CRL
    					this.getCRLCreateSession().run(admin,ca.getSubjectDN());
    				}

    				cadata.setCA(ca);
    			}else{
    				// Cannot create certificate request for internal CA
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: can't recieve certificate responce for internal CA");
    				throw new EJBException(new EjbcaException("Error: can't recieve certificate responce for internal CA"));
    			}

    		}catch(CATokenOfflineException e){
    			ca.setStatus(SecConst.CA_OFFLINE);
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: can't recieve certificate responce for internal CA", e);
    			throw e;
    		}
    	}catch(Exception e){
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: can't recieve certificate responce for internal CA", e);
    		throw new EJBException(e);
    	}

    	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"Certificate responce recieved successfully");
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
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to process CA",e);
    		throw new AuthorizationDeniedException("Not authorized to process a CA  ");
    	}

    	// Check that CA doesn't already exists
    	try{
    		int caid = cainfo.getCAId();
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
    			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
    			throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
    		}
    		cadatahome.findByPrimaryKey(new Integer(caid));
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
    		throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
    	}catch(javax.ejb.FinderException fe) {}

    	try{
    		cadatahome.findByName(cainfo.getName());
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
    		throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
    	}catch(javax.ejb.FinderException fe) {}

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

    				if(cainfo instanceof X509CAInfo){
    					// Create X509CA
    					ca = new X509CA((X509CAInfo) cainfo);
    					ca.setCertificateChain(certchain);
    					ca.setCAToken(new NullCAToken());
    				}

    				// set status to active
    				cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);

    				// Publish CA certificates.
    			    getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), CertificateDataBean.CERTTYPE_SUBCA);

    			}catch(CATokenOfflineException e){
    				signca.setStatus(SecConst.CA_OFFLINE);
    				getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Process  CA.",e);
    				throw e;
    			}
    		}catch(Exception e){
    			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Process  CA.",e);
    			throw new EJBException(e);
    		}

    	}

    	if(certchain != null)
    		getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA processed successfully");
    	else
    		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA");

    	return returnval;
    } // processRequest

    /**
     *  Renews a existing CA certificate using the same keys as before. Data  about new CA is taken
     *  from database.
     * 
     *  @param certificateresponce should be set with new certificatechain if CA is signed by external
     *         RootCA, otherwise use the null value.
     *          
     * @ejb.interface-method
     */
    public void renewCA(Admin admin, int caid, IResponseMessage responsemessage)  throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
    	debug(">CAAdminSession, renewCA(), caid=" + caid);
    	Collection cachain = null;
    	Certificate cacertificate = null;
    	// check authorization
    	try{
    		getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
    	}catch(AuthorizationDeniedException e){
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to renew CA",e);
    		throw new AuthorizationDeniedException("Not authorized to renew CA with caid = " + caid);
    	}

    	// Get CA info.
    	CADataLocal cadata = null;
    	try{
    		cadata = this.cadatahome.findByPrimaryKey(new Integer(caid));
    		CA ca = cadata.getCA();
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
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: illegal response message.");
    					throw new EJBException(new EjbcaException("Error: illegal response message."));
    				}

    				// Check that DN is the equals the request.
    				if(!CertTools.getSubjectDN((X509Certificate) cacertificate).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))){
    					getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: Subject DN of recieved certificate doesn't match request");
    					throw new EJBException(new EjbcaException("Error: Subject DN of recieved certificate doesn't match request"));
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
                int certtype = CertificateDataBean.CERTTYPE_SUBCA;
                if(ca.getSignedBy() == CAInfo.SELFSIGNED)
 			      certtype = CertificateDataBean.CERTTYPE_ROOTCA;
                 ArrayList cacert = new ArrayList();
                 cacert.add(ca.getCACertificate());
     			 getSignSession().publishCACertificate(admin, cacert, ca.getCRLPublishers(), certtype);


    		}catch(CATokenOfflineException e){
    			ca.setStatus(SecConst.CA_OFFLINE);
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Renew CA.",e);
    			throw e;
    		}
    	}catch(Exception e){
    		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Renew CA.",e);
    		throw new EJBException(e);
    	}

    	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA Renew Successfully.");
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
			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to revoke CA",e);
			throw new AuthorizationDeniedException("Not authorized to revoke CA with caid = " + caid);
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
		    getCertificateStoreSession().revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);

            getCRLCreateSession().run(admin, issuerdn);

			cadata.setRevokationReason(reason);
			cadata.setRevokationDate(new Date());
			cadata.setStatus(SecConst.CA_REVOKED);
			ca.setStatus(SecConst.CA_REVOKED);
			ca.setCA(cadata);

        }catch(Exception e){
		   getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAREVOKED,"An error occured when revoking  CA " + ca.getName(),e);
           throw new EJBException(e);
        }

		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAREVOKED,"CA " + ca.getName() + " revoked sucessfully, reason: " + reason);
    } // revokeCA

    /**
     * Method that should be used when upgrading from a older version of EJBCA. i.e. >3.0
     *
     * @param a byte array of old server p12 file.
     * @param keystorepass used to unlock the keystore.
     * @param privkeypass used to unlock the private key.
     * 
     * @ejb.interface-method
     */
    public void upgradeFromOldCAKeyStore(Admin admin, String caname, byte[] p12file, char[] keystorepass,
                                         char[] privkeypass, String privatekeyalias){
        try{
            // check authorization
            if(admin.getAdminType() !=  Admin.TYPE_CACOMMANDLINE_USER)
              getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");

            // load keystore
            java.security.KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(p12file),keystorepass);

            Certificate[] certchain = KeyTools.getCertChain(keystore, privatekeyalias);
            if (certchain.length < 1) {
                log.error("Cannot load certificate chain with alias "+privatekeyalias);
                throw new Exception("Cannot load certificate chain with alias "+privatekeyalias);
            }

            ArrayList certificatechain = new ArrayList();
            for(int i=0;i< certchain.length;i++){
                certificatechain.add(certchain[i]);
            }

            X509Certificate cacertificate = (X509Certificate) certchain[0];

            PrivateKey p12privatekey = (PrivateKey) keystore.getKey( privatekeyalias, privkeypass);
            PublicKey p12publickey = cacertificate.getPublicKey();

            CAToken catoken = new SoftCAToken();
            ((SoftCAToken) catoken).importKeysFromP12(p12privatekey, p12publickey);

            // Create a X509CA
			int signedby = CAInfo.SIGNEDBYEXTERNALCA;
            int certprof = SecConst.CERTPROFILE_FIXED_SUBCA;
			String description = "Imported external signed CA";
            if(certchain.length == 1) {
				if (verifyIssuer(cacertificate, cacertificate)) {
					signedby = CAInfo.SELFSIGNED;
					certprof = SecConst.CERTPROFILE_FIXED_ROOTCA;
					description = "Imported root CA";
				} else {
					// A less strict strategy can be to assume certificate signed
					// by an external CA. Useful if admin user forgot to create a full
					// certificate chain in PKCS#12 package.
					log.error("Cannot import CA " + cacertificate.getSubjectDN().getName()
							+ ": certificate " + cacertificate.getSerialNumber()
							+ " is not self-signed.");
					throw new Exception("Cannot import CA "
							+ cacertificate.getSubjectDN().getName()
							+ ": certificate is not self-signed. Check "
							+ "certificate chain in PKCS#12");
				}
			} else if (certchain.length > 1){
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
						if (verifyIssuer(cacertificate, superCaCert)) {
							signedby = caid;
							description = "Imported sub CA";
							break;
						}
					}
				}					
            }

            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
			extendedcaservices.add(
			  new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
			                        "CN=OCSPSignerCertificate, " + cacertificate.getSubjectDN().toString(),
			                        "",
			                        2048,
			                        OCSPCAServiceInfo.KEYALGORITHM_RSA));


			int validity = (int)((cacertificate.getNotAfter().getTime() - cacertificate.getNotBefore().getTime()) / (24*3600*1000));
            X509CAInfo cainfo = new X509CAInfo(cacertificate.getSubjectDN().toString(),
                                               caname, SecConst.CA_ACTIVE,
                                               "", certprof,
                                               validity,
                                               cacertificate.getNotAfter(), // Expiretime
                                               CAInfo.CATYPE_X509,
                                               signedby,
                                               certificatechain,
                                               catoken.getCATokenInfo(),
                                               description,
                                               -1, null, // revokationreason, revokationdate
                                               "", // PolicyId
                                               24, // CRLPeriod
                                               new ArrayList(),
                                               true, // Authority Key Identifier
                                               false, // Authority Key Identifier Critical
                                               true, // CRL Number
                                               false, // CRL Number Critical
                                               true, // Finish User
			                                   extendedcaservices);

            X509CA ca = new X509CA(cainfo);
            ca.setCAToken(catoken);
            ca.setCertificateChain(certificatechain);

            //  Publish CA certificates.
            int certtype = CertificateDataBean.CERTTYPE_SUBCA;
            if(ca.getSignedBy() == CAInfo.SELFSIGNED)
              certtype = CertificateDataBean.CERTTYPE_ROOTCA;
            getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), certtype);

            // activate External CA Services
            Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
            while(iter.hasNext()){
                ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
                if(info instanceof OCSPCAServiceInfo){
                    try{
                        ca.initExternalService(OCSPCAService.TYPE, ca);
                        ArrayList ocspcertificate = new ArrayList();
                        ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(OCSPCAService.TYPE)).getOCSPSignerCertificatePath().get(0));
                        getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), CertificateDataBean.CERTTYPE_ENDENTITY);
                    }catch(Exception fe){
                        getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
                        throw new EJBException(fe);
                    }
                }
            }
            
            // Store CA in database.
            cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_ACTIVE, ca);
            this.getCRLCreateSession().run(admin,cainfo.getSubjectDN());
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED,"CA imported successfully from old P12 file, status: " + ca.getStatus());
        }catch(Exception e){
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"An error occured when trying to import CA from old P12 file", e);
            throw new EJBException(e);
        }

    } // upgradeFromOldCAKeyStore

    /**
     *  Method returning a Collection of Certificate of all CA certificates known to the system.
     *  
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAllCACertificates(Admin admin){
      ArrayList returnval = new ArrayList();

      try{
        Collection result = cadatahome.findAll();
        Iterator iter = result.iterator();
        while(iter.hasNext()){
           CADataLocal cadatalocal = (CADataLocal) iter.next();
           returnval.add(cadatalocal.getCA().getCACertificate());
        }
      }catch(javax.ejb.FinderException fe){}
        catch(UnsupportedEncodingException uee){
        	throw new EJBException(uee);
        }

      return returnval;
    } // getAllCACertificates

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
            getLogSession().log (admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to activate CA token.",ade);
            throw new AuthorizationDeniedException("Administrator not authorized to activate CA token.");
        }

    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to activate CA with caid " + caid + ". CA activation not available.");
    			throw new CATokenAuthenticationFailedException("Error when trying to activate CA with caid " + caid + ". CA activation not available.");
    		}
    		CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
    		if(cadata.getStatus() == SecConst.CA_OFFLINE){
        		try {
    				cadata.getCA().getCAToken().activate(authorizationcode);
    				cadata.setStatus(SecConst.CA_ACTIVE);
    				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA " + cadata.getName() + " activated successfully.");
    			} catch (IllegalKeyStoreException e) {
                    throw new EJBException(e);
    			} catch (UnsupportedEncodingException e) {
                    throw new EJBException(e);
    			}
    		}else{
				getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"CA " + cadata.getName() + " must have the status 'offline' in order to be activated");
				throw new CATokenAuthenticationFailedException("CA must have the status 'offline' in order to be activated");
    		}
    	}catch(javax.ejb.FinderException fe) {
    	   getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to activate CA with caid " + caid + ". CA could not be found.");
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
            getLogSession().log (admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to deactivate CA token.",ade);
            throw new AuthorizationDeniedException("Administrator not authorized to deactivate CA token.");
        }

    	try{
    		if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
                // This should never happen.
    			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to deactivate CA with caid " + caid + ". CA deactivation not available.");
    			throw new EjbcaException("Error when trying to deactivate CA with caid " + caid + ". CA deactivation not available.");
    		}
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(caid));
            if(cadata.getStatus() == SecConst.CA_ACTIVE){
            	try {
            		cadata.getCA().getCAToken().deactivate();
            		cadata.setStatus(SecConst.CA_OFFLINE);
            		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA " + cadata.getName() + "have been deactivated successfully.");
            	} catch (IllegalKeyStoreException e) {
            		throw new EJBException(e);
            	} catch (UnsupportedEncodingException e) {
            		throw new EJBException(e);
            	}
            }else{
            	getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to deactivate CA  " + cadata.getName() + ". CA is not active");
            	throw new EjbcaException("Wrong user status of CA.");
            }
    	}catch(javax.ejb.FinderException fe) {
    	   getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to deactivate CA with caid " + caid + ". CA could not be found.");
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
            returnval = returnval || (((Integer) pubiter.next()).intValue() == publisherid);
          }
        }
      }catch(javax.ejb.FinderException fe){}
       catch(java.io.UnsupportedEncodingException e){}

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
     * @throws UnsupportedEncodingException if there is an error getting the CA from the CADataLocal
     * @throws EJBException embedding a CertificateExpiredException or a CertificateNotYetValidException if the certificate has expired or is not yet valid 
     */
    private void checkSignerValidity(Admin admin, CADataLocal signcadata) throws UnsupportedEncodingException {
    	// Check validity of signers certificate
    	X509Certificate signcert = (X509Certificate) signcadata.getCA().getCACertificate();
    	try{
    		signcert.checkValidity();
    	}catch(CertificateExpiredException ce){
    		// Signers Certificate has expired.
    		signcadata.setStatus(SecConst.CA_EXPIRED);
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " has expired",ce);
    		throw new EJBException(ce);
    	}catch(CertificateNotYetValidException cve){
    		getLogSession().log(admin, signcadata.getCaId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " is not yet valid",cve);
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
  	    else
		  cacertmap.put(cert.getIssuerDN().toString(),cert);
  	 }

  	 if(rootca == null)
  	   throw new CertPathValidatorException("No root CA certificate found in certificatelist");

  	 returnval.add(0,rootca);
  	 X509Certificate currentcert = rootca;
  	 int i =0;
  	 while(certlist.size() != returnval.size() && i <= certlist.size()){
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
