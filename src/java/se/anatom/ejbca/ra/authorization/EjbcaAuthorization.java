/*
 * EjbcaAthorization.java
 *
 * Created on den 23 mars 2002, 17:34
 */

package se.anatom.ejbca.ra.authorization;

import java.beans.*;
import javax.naming.*;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import javax.rmi.PortableRemoteObject;

import org.ietf.ldap.LDAPDN;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;

import se.anatom.ejbca.ra.GlobalConfiguration;

/**
 * A java bean handling the athorization to ejbca.
 * 
 * The main metod are isAthorized and authenticate.
 *
 * @author  TomSelleck
 */
public class EjbcaAuthorization extends Object implements java.io.Serializable{
       
    /** Creates new EjbcaAthorization */
    public EjbcaAuthorization(UserGroup[] usergroups, GlobalConfiguration globalconfiguration) throws NamingException, CreateException, RemoteException {         
        getParameters(globalconfiguration);
        accesstree = new AccessTree(opendirectories);       
        buildAccessTree(usergroups); 
        
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome)
                                                               javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);  
        certificatesession = certificatesessionhome.create();
       
        ISignSessionHome signhome = (ISignSessionHome) PortableRemoteObject.narrow(jndicontext.lookup("RSASignSession"),
                                                                                   ISignSessionHome.class );  
        ISignSessionRemote signsession = signhome.create();        
        this.cacertificatechain = signsession.getCertificateChain();  
        
    }
    
    // Public methods.
    
    /**
     * Method to check if a user is authorized to a resource
     *
     * @param userinformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @returns true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(UserInformation userinformation, String resource) throws AuthorizationDeniedException {
        // Check in accesstree. 
       if(accesstree.isAuthorized(userinformation, resource) == false)
         throw  new AuthorizationDeniedException();  
        return true;
    }    
    
    /**
     * Method that authenticates a certificate by verifying signature, checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated. 
     *
     * @throws AuthenticationFailedException if authentication failed. 
     */
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException {
        
      // Check Validity
        try{
          certificate.checkValidity();
        }catch(Exception e){
           throw new AuthenticationFailedException("Your certificates vality has expired.");
        }
        
      // Vertify Signature
        boolean verified = false;
        for(int i=0; i < this.cacertificatechain.length; i++){
           try{ 
//            System.out.println("EjbcaAuthorization: authenticate : Comparing : "  + certificate.getIssuerDN() + " With " + ((X509Certificate) cacertificatechain[i]).getSubjectDN());    
//            if(LDAPDN.equals(certificate.getIssuerDN().toString(), ((X509Certificate) cacertificatechain[i]).getSubjectDN().toString())){          
               certificate.verify(cacertificatechain[i].getPublicKey());
               verified = true;
//            }    
           }catch(Exception e){}   
        }
        if(!verified)
           throw new AuthenticationFailedException("Your certificate cannot be verified by CA certificate chain.");    
        
      // Check if certificate is revoked.
        try{
          if(certificatesession.isRevoked(certificate.getIssuerDN().toString(),certificate.getSerialNumber()) != null){
            // Certificate revoked
            throw new AuthenticationFailedException("Your certificate have been revoked.");
          }
         }
         catch(RemoteException e){
            throw new AuthenticationFailedException("Your certificate cannot be found in database.");
         }
        
    }
     
    /** Metod to load the access data from database. */
    public void buildAccessTree(UserGroup[] usergroups){
      accesstree.buildTree(usergroups, opendirectories);
    }
    
    // Private metods 
    
    /** Method to retrieve parameters from configuration part.*/
    private void getParameters(GlobalConfiguration globalconfiguration){
        // Get a copy of global values. 
        opendirectories = new String[globalconfiguration.getOpenDirectories().length];
        System.arraycopy(globalconfiguration .getOpenDirectories(),0,opendirectories,0,
                         globalconfiguration .getOpenDirectories().length);
    }
    

    // Private fields.
    
    private String[]              opendirectories;
    private AccessTree            accesstree;  
    private Certificate[]         cacertificatechain;
    
    private ICertificateStoreSessionRemote certificatesession;      
    private ISignSessionRemote             signsession; 
}
