package se.anatom.ejbca.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.IUserAdminSessionLocalHome;
import se.anatom.ejbca.util.KeyTools;

/**
 * Administrates and manages CAs in EJBCA system.
 *
 * @version $Id: CAAdminSessionBean.java,v 1.3 2003-10-03 14:34:20 herrvendil Exp $
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
        
        
        // Install BouncyCastle provider if it doesnt exists
      //  if( Security.getProvider("BC") == null){
          Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
          Security.addProvider(BCJce);
      //  }  

        
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
            System.out.println("CAADMINSESSION createCA : caid = " + cainfo.getCAId() + ", subject=" + cainfo.getSubjectDN());
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
                                
                System.out.println("CAADMINSESSION: adding " + ((X509Certificate) cacertificate).getSubjectDN().toString());
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
                 }catch(Exception e){
                   // Signers Certificate has expired.   
                   signcadata.setStatus(SecConst.CA_EXPIRED);  
                   getLogSession().log(admin, signcadata.getCAId().intValue(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Signing CA " + signcadata.getSubjectDN() + " has expired",e);
                   throw new CertificateExpiredException("Signing CA " + signcadata.getSubjectDN() + " has expired");   
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
        
        // Store CA in database.
       try{
            cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), ca.getStatus(), ca);
            getLogSession().log(admin, ca.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_INFO_CACREATED,"CA created successfully, status: " + ca.getStatus());                        
        }catch(javax.ejb.CreateException e){
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CACREATED,"Error when trying to create CA.");
            throw new EJBException(e);
        } 
        
       // Publish CA certificates.
        getSignSession().publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSignedBy() == CAInfo.SELFSIGNED);
        
    } // createCA
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException{
        
        // Check authorization
        try{
            getAuthorizationSession().isAuthorizedNoLog(admin,"/super_administrator");
        }catch(AuthorizationDeniedException e){
            getLogSession().log(admin, cainfo.getCAId(), LogEntry.MODULE_CA,  new java.util.Date(), null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Administrator isn't authorized to edit CA",e);
            throw new AuthorizationDeniedException("Not authorized to edit CA with caid = " + cainfo.getCAId());
        }
        
        // Get CA from database
        try{
            CADataLocal cadata = cadatahome.findByPrimaryKey(new Integer(cainfo.getCAId()));
            CA ca = (CA) cadata.getCA();
            
            // Update CA values
            ca.updateCA(cainfo);
            // Store CA in database
            cadata.setCA(ca);
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
            authorizedToCA(admin,cadata.getCAId().intValue());
            cainfo = cadata.getCA().getCAInfo();
            
            System.out.println("CAADMINSESSIONBEAN, getCAInfo, Certificatechain size : " + cainfo.getCertificateChain().size());
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
            cainfo = cadata.getCA().getCAInfo();
        }catch(javax.ejb.FinderException fe) {}
         catch(Exception e){
           throw new EJBException(e);   
         }
        
        return cainfo;
    } // getCAInfo
    
    public HashMap getCAIdToNameMap(Admin admin){
        System.out.println("CAAdminSessionBean : >getCAIdToNameMap "); 
        HashMap returnval = new HashMap();
        try{
            Collection result = cadatahome.findAll();
            System.out.println("CAAdminSessionBean : result size " + result.size()); 
            Iterator iter = result.iterator();
            while(iter.hasNext()){                                
                CADataLocal cadata = (CADataLocal) iter.next();                
                returnval.put(cadata.getCAId(), cadata.getName());                                                   
            }
        }catch(javax.ejb.FinderException fe){}
        System.out.println("CAAdminSessionBean : <getCAIdToNameMap : size " + returnval.keySet().size());
        
        return returnval;
    }
    
        
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException{
        // Check authorization
        
        // TODO
        return null;
    } // makeRequest
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException{
        // check authorization
        
        // TOOD
    } // recieveResponse
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
   public Collection processRequest(Admin admin, String username, String password, IRequestMessage requestmessage) 
                                    throws CADoesntExistsException, AuthorizationDeniedException{
        // check authorization
        
        // TODO
        return null;
    } // processRequest
    
    /**
     *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
     */
    public void renewCA(Admin admin, int caid, IResponseMessage responsemessage)  throws CADoesntExistsException, AuthorizationDeniedException{
        // check authorization
        
        // TODO
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
        
        // Revoke all certificates generated by CA
        certificatestoresession.revokeAllCertByCA(admin, issuerdn, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE); 
                        
        // Set CA status to Revoked.
        ca.setStatus(SecConst.CA_REVOKED);        
        try{
			CA cadata = ca.getCA();
			
			// Revoke CA certificate 
			certificatestoresession.revokeCertificate(admin, cadata.getCACertificate(), reason);
				
			cadata.setRevokationReason(reason);
			cadata.setRevokationDate(new Date());
			ca.setCA(cadata);
        }catch(UnsupportedEncodingException uee){
           throw new EJBException(uee);
        }                 
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
                                               true); // Finish User
            
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
    
    
} //CAAdminSessionBean
