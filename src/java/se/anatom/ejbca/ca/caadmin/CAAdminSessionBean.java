package se.anatom.ejbca.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;


import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.IJobRunnerSessionHome;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAService;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.exception.EjbcaException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.protocol.X509ResponseMessage;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.IUserAdminSessionLocalHome;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

/**
 * Administrates and manages CAs in EJBCA system.
 *
 * @version $Id: CAAdminSessionBean.java,v 1.9 2003-11-23 09:47:54 anatom Exp $
 */
public class CAAdminSessionBean extends BaseSessionBean {
    
    /** Var holding JNDI name of datasource */
    private String dataSource = "";
    
    /** The local home interface of CAData.*/
    private CADataLocalHome cadatahome;
    
    /** The local interface of the log session bean */
    private ILogSessionLocal logsession;
    
    /** The local interface of the authorization session bean */
    private IAuthorizationSessionLocal authorizationsession;
    
    /** The local interface of the user admin session bean */
    private IUserAdminSessionLocal useradminsession;
    
    /** The local interface of the certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession;
    
    /** The local interface of the sign session bean */
    private ISignSessionLocal signsession;
    

    
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        cadatahome = (CADataLocalHome)lookup("java:comp/env/ejb/CADataLocal");
        // Install BouncyCastle provider
        CertTools.installBCProvider();
        debug("<ejbCreate()");
    }
    
    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    
    
    /** Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
            try{
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
                logsession = logsessionhome.create();
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
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal",IAuthorizationSessionLocalHome.class);
                authorizationsession = authorizationsessionhome.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession
    
    /** Gets connection to user admin session bean
     * @return Connection
     */
    private IUserAdminSessionLocal getUserAdminSession() {
        if(useradminsession == null){
            try{
                IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) lookup("java:comp/env/ejb/UserAdminSessionLocal",IUserAdminSessionLocalHome.class);
                useradminsession = useradminsessionhome.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return useradminsession;
    } //getUserAdminSession
    
    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
        if(certificatestoresession == null){
            try{
                ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) lookup("java:comp/env/ejb/CertificateStoreSessionLocal",ICertificateStoreSessionLocalHome.class);
                certificatestoresession = certificatestoresessionhome.create();
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
                ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) lookup("java:comp/env/ejb/SignSessionLocal",ISignSessionLocalHome.class);
                signsession = signsessionhome.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return signsession;
    } //getCertificateStoreSession

        
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException{
    	Collection certpublishers = null;
        // Check that administrat has superadminsitrator rights.
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException ade){
            getLogSession().log (admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to create CA",ade);
            throw new AuthorizationDeniedException("Administrator not authorized to create CA");
        }
                // Check that CA doesn't already exists
        try{
            int caid = cainfo.getCAId();            
            if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
                getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA already exists.");
                throw new CAExistsException();
            }
            cadatahome.findByPrimaryKey(new Integer(caid));
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA already exists.");
            throw new CAExistsException();
        }catch(javax.ejb.FinderException fe) {}
        
        try{
            cadatahome.findByName(cainfo.getName());
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"CA name already exists.");
            throw new CAExistsException("CA Name already exists");
        }catch(javax.ejb.FinderException fe) {}
        
        // Create CAToken
        CAToken catoken = null;
        CATokenInfo catokeninfo = cainfo.getCATokenInfo();
        if(catokeninfo instanceof SoftCATokenInfo){
            try{
                catoken = new SoftCAToken();
                ((SoftCAToken) catoken).generateKeys((SoftCATokenInfo) catokeninfo);
            }catch(Exception e){
                getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when creating CA token.",e);
                throw new EJBException(e);
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
            certpublishers = certprofile.getPublisherList();
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
               
                UserAuthData cadata = new UserAuthData("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), x509cainfo.getSubjectAltName(), null, 
                                                       0,  cainfo.getCertificateProfileId());
                cacertificate = ca.generateCertificate(cadata, catoken.getPublicSignKey(),-1, cainfo.getValidity(), certprofile);
                                                
                // Build Certificate Chain
                certificatechain = new ArrayList();
                certificatechain.add(cacertificate);
                
                // set status to active
                x509ca.setStatus(SecConst.CA_ACTIVE);                
              }catch(Exception fe){
                 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Root CA.",fe);
                 throw new EJBException(fe);                                     
              }
            }
            if(cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){
				certificatechain = new ArrayList();       
                // set status to waiting certificate response.
                x509ca.setStatus(SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
            }
            
            if(cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0){
                // Create CA signed by other internal CA.
                try{
                  CADataLocal signcadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getSignedBy()));   
                  CA signca = signcadata.getCA();
                  // Check validity of signers certificate
                  X509Certificate signcert = (X509Certificate) signca.getCACertificate();                  
                 try{
                   signcert.checkValidity();                   
                 }catch(CertificateExpiredException ce){
                   // Signers Certificate has expired.   
                   signcadata.setStatus(SecConst.CA_EXPIRED);  
                   getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Signing CA " + signcadata.getSubjectDN() + " has expired",ce);
                   throw new EJBException(ce);   
                 }catch(CertificateNotYetValidException cve){			  
				   getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Signing CA " + signcadata.getSubjectDN() + " is not yet valid",cve);
				   throw new EJBException(cve);				    
			   }
                 
                  // Create cacertificate                 
                  Certificate cacertificate = null;
                                
                  UserAuthData cadata = new UserAuthData("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), x509cainfo.getSubjectAltName(), null, 
                                                       0,  cainfo.getCertificateProfileId());
                  cacertificate = signca.generateCertificate(cadata, catoken.getPublicSignKey(), -1, cainfo.getValidity(), certprofile);
                
                  // Build Certificate Chain
                  Collection rootcachain = signca.getCertificateChain();
                  certificatechain = new ArrayList();
                  certificatechain.add(cacertificate);
                  certificatechain.addAll(rootcachain);
                  // set status to active
                  x509ca.setStatus(SecConst.CA_ACTIVE);                  
                }catch(Exception fe){
                   getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create Sub CA.",fe);
                   throw new EJBException(fe);                    
                } 
                  
            }
            
            // Set Certificate Chain
            x509ca.setCertificateChain(certificatechain);
            
        }
       
        //	Publish CA certificates.
             if(certpublishers != null){
               int certtype = SecConst.CERTTYPE_SUBCA;	
               if(ca.getSignedBy() == CAInfo.SELFSIGNED)
			     certtype = SecConst.CERTTYPE_ROOTCA;  
			   getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), certtype);
             }
             
		     if(ca.getStatus() ==SecConst.CA_ACTIVE){
		     	// activate External CA Services
		     	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
		     	while(iter.hasNext()){
		     	  ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
		     	  if(info instanceof OCSPCAServiceInfo){
		     	  	try{
		     	  	  ca.initExternalService(OCSPCAService.TYPE, ca);
		     	  	  ArrayList ocspcertificate = new ArrayList();
		     	  	  ocspcertificate.add(((OCSPCAServiceInfo) ca.getExtendedCAServiceInfo(OCSPCAService.TYPE)).getOCSPSignerCertificatePath().get(0));
					  getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), SecConst.CERTTYPE_ENDENTITY);	   
				    }catch(Exception fe){
					  getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Create ExternalCAService.",fe);
					  throw new EJBException(fe);                                     
				    }
		     	  }
		     	}
		     }
        // Store CA in database.
       try{
            cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), ca.getStatus(), ca);
            getLogSession().log(admin, ca.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED,"CA created successfully, status: " + ca.getStatus());                        
        }catch(javax.ejb.CreateException e){
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when trying to create CA.");
            throw new EJBException(e);
        } 
        
        
    } // createCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
            CA ca = (CA) cadata.getCA();
            
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
              getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), SecConst.CERTTYPE_ENDENTITY);                                         
            }
            // Log Action
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"");
        }catch(Exception fe) {
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Edit CA.",fe);
            throw new EJBException(fe);
        }
    } // editCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
            
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA Removed");
        }catch(Exception e) {
            getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to remove CA.",e);
            throw new EJBException(e);
        }
    } // removeCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException{
        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByName(oldname);
            // Check authorization
            int caid = ((Integer) cadata.getCAId()).intValue();
            try{
                getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
            }catch(AuthorizationDeniedException e){
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to rename CA",e);
                throw new AuthorizationDeniedException("Not authorized to rename CA with caid = " + caid);
            }
            
            try{
                CADataLocal cadatanew = cadatahome.findByName(newname);
                throw new CAExistsException(" CA name " + newname + " already exists.");
            }catch(javax.ejb.FinderException fe) {
                // new CA doesn't exits, it's ok to rename old one.
                cadata.setName(newname);
                getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA : " + oldname + " renamed to " + newname);
            }
        }catch(javax.ejb.FinderException fe) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when trying to rename CA.");
            throw new EJBException(fe);
        }
    } // renewCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public CAInfo getCAInfo(Admin admin, String name) {
        CAInfo cainfo = null;
        try{
            CADataLocal cadata = cadatahome.findByName(name);
			if(cadata.getStatus() == SecConst.CA_ACTIVE && new Date(cadata.getExpireTime()).before(new Date())){
			  cadata.setStatus(SecConst.CA_EXPIRED);
			}            
            authorizedToCA(admin,cadata.getCAId().intValue());
            cainfo = cadata.getCA().getCAInfo();                       
        }catch(javax.ejb.FinderException fe) {}        
         catch(Exception e){
           throw new EJBException(e);   
         }
        
        return cainfo;
    } // getCAInfo
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
        }catch(javax.ejb.FinderException fe) {}
         catch(Exception e){
           throw new EJBException(e);   
         }
        
        return cainfo;
    } // getCAInfo


    
    public HashMap getCAIdToNameMap(Admin admin){        		
        HashMap returnval = new HashMap();
        try{
            Collection result = cadatahome.findAll();            
            Iterator iter = result.iterator();
            while(iter.hasNext()){                                
                CADataLocal cadata = (CADataLocal) iter.next();                       
                returnval.put(cadata.getCAId(), cadata.getName());                                                   
            }
        }catch(javax.ejb.FinderException fe){}        
        		
        
        return returnval;
    }
    
    /**
     *  Method returning id's of all CA's avaible to the system. i.e. not have status 
     * "external" or "waiting for certificate response"
     *      
     * @return a Collection (Integer) of available CA id's
     */
    
    public Collection getAvailableCAs(Admin admin){
		ArrayList returnval = new ArrayList();
		try{
			Collection result = cadatahome.findAll();            
			Iterator iter = result.iterator();
			while(iter.hasNext()){                                
				CADataLocal cadata = (CADataLocal) iter.next();
				if(cadata.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE && cadata.getStatus() != SecConst.CA_EXTERNAL)                
				  returnval.add(cadata.getCAId());                                                   
			}
		}catch(javax.ejb.FinderException fe){}        
        
		return returnval;    	    	
    }
    
        
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException{
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
            
		// if issuer is insystem CA or selfsigned, then generate new certificate.
		  if(ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA){


			ca.setRequestCertificateChain(createCertChain(cachain));
		    		    		   
		     // generate PKCS10CertificateRequest
		     // TODO implement PKCS10 Certificate Request arributes.
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
					CertTools.stringToBcX509Name(ca.getSubjectDN()), ca.getCAToken().getPublicSignKey(), attributes, ca.getCAToken().getPrivateSignKey());
					   
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
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException{
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
				   getSignSession().publishCACertificate(admin, ocspcertificate, ca.getCRLPublishers(), SecConst.CERTTYPE_ENDENTITY);	   				   
				 }catch(Exception fe){
				   getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Couldn't Initialize ExternalCAService.",fe);
				   throw new EJBException(fe);                                     				   
				 }
			   }
			}
						 
			cadata.setCA(ca); 			
		    }else{                
		    // Cannot create certificate request for internal CA
			  getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: can't recieve certificate responce for internal CA"); 
			  throw new EJBException(new EjbcaException("Error: can't recieve certificate responce for internal CA"));
		    }    
		
        
		}catch(Exception e){
			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error: can't recieve certificate responce for internal CA");
		   throw new EJBException(e);
		}          
        
		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"Certificate responce recieved successfully");                		                
    } // recieveResponse
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
   public IResponseMessage processRequest(Admin admin, CAInfo cainfo, IRequestMessage requestmessage) 
                                    throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException {
        CA ca = null;
        Collection certchain = null;                                   
        Collection certpublishers = null; 	
        IResponseMessage returnval = null;
        // check authorization
		try{
		   getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
	    }catch(AuthorizationDeniedException e){
		 	getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to process CA",e);
			throw new AuthorizationDeniedException("Not authorized to process a CA  ");
		}

		// Check that CA doesn't already exists
       try{
	      int caid = cainfo.getCAId();            
	      if(caid >=0 && caid <= CAInfo.SPECIALCAIDBORDER){
		    getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
		    throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
	     }
	     cadatahome.findByPrimaryKey(new Integer(caid));
	     getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
	     throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
       }catch(javax.ejb.FinderException fe) {}
        
       try{
	     cadatahome.findByName(cainfo.getName());
	     getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA " + cainfo.getName() +". CA already exists.");
	     throw new CAExistsException("Error when processing CA " + cainfo.getName() +". CA already exists.");
       }catch(javax.ejb.FinderException fe) {}
		
		//get signing CA
		if(cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0){			
			try{
			  CADataLocal signcadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getSignedBy()));   
			  CA signca = signcadata.getCA();
			  // Check validity of signers certificate
			  X509Certificate signcert = (X509Certificate) signca.getCACertificate();                  
			 try{
			   signcert.checkValidity();                   
			 }catch(CertificateExpiredException ce){
			 // Signers Certificate has expired.   
			 signcadata.setStatus(SecConst.CA_EXPIRED);  
			 getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " has expired",ce);
			 throw new EJBException(ce);   
		   }catch(CertificateNotYetValidException cve){			  
			 getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " is not yet valid",cve);
			 throw new EJBException(cve);				    
		 }
			 
			 // Get public key from request
			 PublicKey publickey = requestmessage.getRequestPublicKey();
			 
			  // Create cacertificate                 
			 Certificate cacertificate = null;
                                
              if(cainfo instanceof X509CAInfo){                 
			    UserAuthData cadata = new UserAuthData("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), ((X509CAInfo) cainfo).getSubjectAltName(), null, 
												   0,  cainfo.getCertificateProfileId());
                CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, cainfo.getCertificateProfileId());
				certpublishers = certprofile.getPublisherList();												   
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
				  X509CAInfo x509cainfo = (X509CAInfo) cainfo;
				  // Create X509CA
				  ca = new X509CA((X509CAInfo) cainfo);
				  ca.setCertificateChain(certchain);
				  ca.setCAToken(new NullCAToken());
			  }
			  
			  // set status to active
			  ca.setStatus(SecConst.CA_EXTERNAL);   
			  cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);
			  
			   // Publish CA certificates.
			  if(certpublishers != null)
 		        getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), SecConst.CERTTYPE_SUBCA);
			                 
			}catch(Exception e){
			   getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Process  CA.",e);
			   throw new EJBException(e);                    
			} 
                  		                        
	   }										 
	   
	   if(certchain != null)	        
	     getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA processed successfully");      
       else 
	     getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Error when processing CA");
	     
        return returnval;
    } // processRequest
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void renewCA(Admin admin, int caid, IResponseMessage responsemessage)  throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException{
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
            
        // if issuer is insystem CA or selfsigned, then generate new certificate.
          if(ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA){
            if(ca.getSignedBy() == CAInfo.SELFSIGNED){
			   // create selfsigned certificate			   
               if( ca instanceof X509CA){               
			     UserAuthData cainfodata = new UserAuthData("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), ((X509CA) ca).getSubjectAltName(), null, 
														  0,  ca.getCertificateProfileId());
               
                 CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());														  
				 cacertificate = ca.generateCertificate(cainfodata, ca.getCAToken().getPublicSignKey(),-1, ca.getValidity(), certprofile);
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
					 // Check validity of signers certificate
					 X509Certificate signcert = (X509Certificate) signca.getCACertificate();                  
					try{
					  signcert.checkValidity();                   
					}catch(CertificateExpiredException ce){
			        	// Signers Certificate has expired.   
				       signcadata.setStatus(SecConst.CA_EXPIRED);  
				       getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " has expired",ce);
				       throw new EJBException(ce);   
			         }catch(CertificateNotYetValidException cve){			  
				         getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Signing CA " + signcadata.getSubjectDN() + " is not yet valid",cve);
				         throw new EJBException(cve);				    
			          }
					 // Create cacertificate                 					 
				     if( ca instanceof X509CA){               
				       UserAuthData cainfodata = new UserAuthData("nobody", ca.getSubjectDN(), ca.getSubjectDN().hashCode(), ((X509CA) ca).getSubjectAltName(), null, 
					 									   0,  ca.getCertificateProfileId());
               
				      CertificateProfile certprofile = getCertificateStoreSession().getCertificateProfile(admin, ca.getCertificateProfileId());														  
				      cacertificate = signca.generateCertificate(cainfodata, ca.getCAToken().getPublicSignKey(),-1, ca.getValidity(), certprofile);
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
          
		}catch(Exception e){
			getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CAEDITED,"Couldn't Renew CA.",e);
		   throw new EJBException(e);
		}  
		
		getLogSession().log(admin, caid, LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CAEDITED,"CA Renew Successfully.");        
                            
    } // renewCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
							
             // Revoke all certificates generated by CA
		    getCertificateStoreSession().revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);				

			// Revoke CA certificate 
			getCertificateStoreSession().revokeCertificate(admin, cadata.getCACertificate(), reason);
				
			InitialContext jndicontext = new InitialContext();
            IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
            home.create().run(admin, issuerdn);
			
				
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
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void upgradeFromOldCAKeyStore(Admin admin, String caname, byte[] p12file, char[] keystorepass,
                                         char[] privkeypass, String privatekeyalias){
        try{
            // check authorization
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
            int signedby = CAInfo.SELFSIGNED;
            int certprof = SecConst.CERTPROFILE_FIXED_ROOTCA;
            if(certchain.length > 1){
                signedby = CAInfo.SIGNEDBYEXTERNALCA;
                certprof = SecConst.CERTPROFILE_FIXED_SUBCA; 
            }    
            
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
			extendedcaservices.add(
			  new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
			                        "CN=OCSPSignerCertificate, " + cacertificate.getSubjectDN().toString(),
			                        "",
			                        2048,
			                        OCSPCAServiceInfo.KEYALGORITHM_RSA));
                
                
            X509CAInfo cainfo = new X509CAInfo(cacertificate.getSubjectDN().toString(),
                                               caname, SecConst.CA_ACTIVE,
                                               "", certprof,
                                               (int) ((cacertificate.getNotAfter().getTime() - cacertificate.getNotBefore().getTime()) / (24/3600)), 
                                               cacertificate.getNotAfter(), // Expiretime                                              
                                               CAInfo.CATYPE_X509,
                                               signedby,
                                               (Collection) certificatechain,
                                               catoken.getCATokenInfo(),
                                               "Old Imported EJBCA version",
                                               -1, null, // revokationreason, revokationdate
                                               "", // PolicyId
                                               24, // CRLPeriod
                                               (Collection) new ArrayList(),
                                               true, // Authority Key Identifier
                                               false, // Authority Key Identifier Critical
                                               true, // CRL Number
                                               false, // CRL Number Critical
                                               true, // Finish User
			                                   extendedcaservices);
            
            X509CA ca = new X509CA(cainfo);
            ca.setCAToken(catoken);
            ca.setCertificateChain(certificatechain);
            ca.setStatus(SecConst.CA_ACTIVE);
            
            // Store CA in database.
            cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(),  ca.getStatus(), (CA) ca);
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED,"CA imported successfully from old P12 file, status: " + ca.getStatus());
        }catch(Exception e){
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"An error occured when trying to import CA from old P12 file", e);
            throw new EJBException(e);
        }
        
    } // upgradeFromOldCAKeyStore
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
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
    
    private boolean authorizedToCA(Admin admin, int caid){
      boolean returnval = false;
      try{        
        returnval = getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + caid);
      }catch(AuthorizationDeniedException e){}    
      return returnval;  
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
	    CertPath certpath = CertificateFactory.getInstance("X.509").generateCertPath(calist);
	    
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
