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

package se.anatom.ejbca.authorization;

import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.naming.NamingException;

import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.util.CertTools;

/**
 * A java bean handling the athorization to ejbca.
 *
 * The main metod are isAthorized and authenticate.
 *
 * @version $Id: Authorizer.java,v 1.10 2004-08-06 07:46:28 anatom Exp $
 */
public class Authorizer extends Object implements java.io.Serializable{
    
    
    
    /** Creates new EjbcaAthorization */
    public Authorizer(Collection admingroups, AdminGroupDataLocalHome  admingrouphome,
            ILogSessionLocal logsession, ICertificateStoreSessionLocal certificatestoresession, 
            IRaAdminSessionLocal raadminsession, ICAAdminSessionLocal caadminsession, Admin admin, int module) 
    throws NamingException, CreateException, RemoteException {
        accesstree = new AccessTree();
        authorizationproxy = new AuthorizationProxy(admingrouphome, accesstree);
        buildAccessTree(admingroups);
        this.logsession = logsession;
        this.module=module;
        this.certificatesession = certificatestoresession;
        this.raadminsession = raadminsession;
        this.caadminsession = caadminsession;                 
        
    }
    
    // Public methods.
    
    /**
     * Method to check if a user is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException {
        
        if(admin == null)
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        
        AdminInformation admininformation = admin.getAdminInformation();
        
        if(!authorizationproxy.isAuthorized(admininformation, resource)  && !authorizationproxy.isAuthorized(admininformation, "/super_administrator")){
            if(!admininformation.isSpecialUser()) {
                logsession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
            } else {
                logsession.log(admin, ILogSessionLocal.INTERNALCAID, module,   new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
            }
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        }
        if(!admininformation.isSpecialUser()) {
            logsession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogEntry.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);       
        } else {
            logsession.log(admin, ILogSessionLocal.INTERNALCAID,  module, new java.util.Date(),null, null, LogEntry.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);
        }
        
        return true;
    }
    
    
    /**
     * Method to check if a user is authorized to a resource without performing any logging
     *
     * @param AdminInformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException {
        if(admin == null)
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        
        // Check in accesstree.
        if(!authorizationproxy.isAuthorized(admin.getAdminInformation(), resource)  && !authorizationproxy.isAuthorized(admin.getAdminInformation(), "/super_administrator")){
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        }
        return true;
    }
    
    /**
     * Method to check if a group is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isGroupAuthorized(Admin admin, int pk, String resource) throws AuthorizationDeniedException {
        if(admin == null)
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        
        AdminInformation admininformation = admin.getAdminInformation();
        
        if(!authorizationproxy.isGroupAuthorized(admininformation, pk, resource)){
            if(!admininformation.isSpecialUser()) {
                logsession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
            } else {
                logsession.log(admin, ILogSessionLocal.INTERNALCAID, module,   new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
            }
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        }
        if(!admininformation.isSpecialUser()) {
            logsession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogEntry.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);       
        } else {
            logsession.log(admin, ILogSessionLocal.INTERNALCAID,  module, new java.util.Date(),null, null, LogEntry.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        }
        
        return true;
    }
    
    
    /**
     * Method to check if a group is authorized to a resource without performing any logging
     *
     * @param AdminInformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isGroupAuthorizedNoLog(Admin admin, int pk, String resource) throws AuthorizationDeniedException {
        if(admin == null)
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        
        // Check in accesstree.
        if(!authorizationproxy.isGroupAuthorized(admin.getAdminInformation(), pk, resource)) {
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        }
        return true;
    }
    
    
    
    /**
     * Method that authenticates a certificate by verifying signature, checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated.
     * @throws AuthenticationFailedException if authentication failed.
     */
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException {
        
        // Check Validity
        try{
            certificate.checkValidity();
        }catch(Exception e){
            throw new AuthenticationFailedException("Your certificates vality has expired.");
        }
        
        // TODO
        /*     // Vertify Signature
         boolean verified = false;
         for(int i=0; i < this.cacertificatechain.length; i++){
         try{
         //            log.debug("Authorizer: authenticate : Comparing : "  + CertTools.getIssuerDN(certificate) + " With " + CertTools.getSubjectDN((X509Certificate) cacertificatechain[i]));
          //            if(LDAPDN.equals(CertTools.getIssuerDN(certificate), CertTools.getSubjectDN((X509Certificate) cacertificatechain[i]))){
           certificate.verify(cacertificatechain[i].getPublicKey());
           verified = true;
           //            }
            }catch(Exception e){}
            }
            if(!verified)
            throw new AuthenticationFailedException("Your certificate cannot be verified by CA certificate chain.");
            */
        // Check if certificate is revoked.
        RevokedCertInfo revinfo = certificatesession.isRevoked(new Admin(certificate), CertTools.getIssuerDN(certificate),certificate.getSerialNumber());
        if (revinfo == null) {
            // Certificate missing
            throw new AuthenticationFailedException("Your certificate cannot be found in database.");
        } else if (revinfo.getReason() != RevokedCertInfo.NOT_REVOKED) {
            // Certificate revoked
            throw new AuthenticationFailedException("Your certificate have been revoked.");
        }
    }
    
    /**
     * Method used to return an ArrayList of Integers indicating which CAids a administrator
     * is authorized to access.
     */
    
    public Collection getAuthorizedCAIds(Admin admin){         
        ArrayList returnval = new ArrayList();  
        Iterator iter = caadminsession.getAvailableCAs(admin).iterator();      
        
        while(iter.hasNext()){
            Integer caid = (Integer) iter.next();
            try{           
                isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + caid.toString());               
                returnval.add(caid); 
            }catch(AuthorizationDeniedException e){}
        }                         
        return returnval;
    }		   
    
    /**
     * Method used to return an Collection of Integers indicating which end entity profiles
     * the administrator is authorized to view.
     *
     * @param admin, the administrator 
     * @rapriviledge should be one of the end entity profile authorization constans defined in AvailableAccessRules.
     */ 
    
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge){
        ArrayList returnval = new ArrayList();  
        Iterator iter = raadminsession.getEndEntityProfileIdToNameMap(admin).keySet().iterator();  
        
        while(iter.hasNext()){
            Integer profileid = (Integer) iter.next();
            try{
                isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + profileid + rapriviledge);     
                returnval.add(profileid); 
            }catch(AuthorizationDeniedException e){}
            
        }
        
        return returnval;
    }
    
    /** Metod to load the access data from database. */
    public void buildAccessTree(Collection admingroups){
        accesstree.buildTree(admingroups);
        authorizationproxy.clear();
    }
    
    // Private metods
    
    
    // Private fields.
    private AccessTree            accesstree;
    private Certificate[]         cacertificatechain;
    private int                   module;
    
    private ICertificateStoreSessionLocal  certificatesession;
    private ILogSessionLocal               logsession;
    private IRaAdminSessionLocal           raadminsession;
    private ICAAdminSessionLocal           caadminsession;
    private AuthorizationProxy             authorizationproxy;
}
