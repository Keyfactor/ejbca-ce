/*
 * AuthorizationDataHandler.java
 *
 * Created on den 12 april 2002, 13:03
 */

package se.anatom.ejbca.webdist.webconfiguration;

import java.io.IOException;
import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import se.anatom.ejbca.ra.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.ra.authorization.IAuthorizationSessionRemote;
/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 */
public class AuthorizationDataHandler {
   

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(GlobalConfiguration globalconfiguration) throws RemoteException, NamingException, FinderException, CreateException{
       InitialContext jndicontext = new InitialContext();
       IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"), 
                                                                                 IAuthorizationSessionHome.class);
       authorizationsession = authorizationsessionhome.create();               
       Collection names = authorizationsession.getAvailableAccessRules();
       if(names.size()==0){    
          Vector rules = new Vector();
          String[] defaultrules = globalconfiguration.getDefaultAvailableDirectories();
          for(int i = 0; i < defaultrules.length ; i++){
            rules.addElement( defaultrules[i]);  
          }
         authorizationsession.addAvailableAccessRules(rules);
       }
    }
        
    /**
     * Method to add an access rule.
     */ 

    public void addAvailableAccessRule(String name) throws RemoteException{
      authorizationsession.addAvailableAccessRule(name);
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */ 
    
    public void addAvailableAccessRules(Collection names) throws RemoteException{
      authorizationsession.addAvailableAccessRules(names);        
    } //  addAvailableAccessRules
 
    /**
     * Method to remove an access rule.
     */ 

    public void removeAvailableAccessRule(String name)  throws RemoteException{
      authorizationsession.removeAvailableAccessRule(name);
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */ 
    
    public void removeAvailableAccessRules(Collection names)  throws RemoteException{
      authorizationsession.removeAvailableAccessRules(names);
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */ 
    
    public Collection getAvailableAccessRules() throws RemoteException{
       return authorizationsession.getAvailableAccessRules();
    } // getAvailableAccessRules
    
    /**
     * Checks wheither an access rule exists in the database.
     */ 
    
    public boolean existsAvailableAccessRule(String name) throws RemoteException{
      return authorizationsession.existsAvailableAccessRule(name);
    } // existsAvailableAccessRule
    
    
    // Private fields
    private IAuthorizationSessionRemote authorizationsession; 
}
