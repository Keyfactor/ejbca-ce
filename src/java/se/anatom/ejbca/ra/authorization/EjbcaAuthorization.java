/*
 * EjbcaAthorization.java
 *
 * Created on den 23 mars 2002, 17:34
 */

package se.anatom.ejbca.ra.authorization;

import java.beans.*;
import java.security.cert.X509Certificate;
import java.io.IOException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**
 * A java bean handling the athorization to JSP pages.
 * 
 * The main metod are isAthorized.
 *
 * @author  Philip Vendil
 */
public class EjbcaAuthorization extends Object implements java.io.Serializable {
       
    /** Creates new EjbcaAthorization */
    public EjbcaAuthorization(UserGroup[] usergroups, GlobalConfiguration globalconfiguration) {
        this.globalconfiguration = globalconfiguration;        
        getParameters();
        accesstree = new AccessTree(baseurl, opendirectories);
        loadAccessData(usergroups);
    }
    
    // Public methods.
    
    /** EjbcaAthorization beans main method. Checks if a user have access to a specific url. */ 
    public boolean isAuthorized(X509Certificate certificate, String url) throws AuthorizationDeniedException {
        // Check in accesstree. 
       if(accesstree.isAuthorized(certificate, url) == false)
         throw  new AuthorizationDeniedException();  
        return true;
    }    
     

    
    // Private metods 
    
    /** Method to retrieve parameters from configuration part.*/
    private void getParameters(){
        // Get a copy of global values.
        opendirectories = new String[globalconfiguration .getOpenDirectories().length];
        System.arraycopy(globalconfiguration .getOpenDirectories(),0,opendirectories,0,
                         globalconfiguration .getOpenDirectories().length);
        baseurl=  new String(globalconfiguration .getBaseUrl());  
    }
    

    
    /** Metod to load the access data from database. */
    private void loadAccessData(UserGroup[] usergroups){
      accesstree.buildTree(usergroups, opendirectories);
    }

    // Private fields.
    
    private String                baseurl;
    private String[]              opendirectories;
    private AccessTree            accesstree;
    private GlobalConfiguration   globalconfiguration;    
}
