/*
 * AvailableDirectories.java
 *
 * Created on den 16 mars 2002, 16:35
 */

package se.anatom.ejbca.ra.authorization;

import java.util.Vector;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * 
 *
 * @author  Philip Vendil
 */
public class AvailableDirectories {
        
    /** Creates a new instance of AvailableDirectories */
    public AvailableDirectories(GlobalConfiguration globalconfiguration) throws NamingException, CreateException, RemoteException {   
      this.profilegroupendings=globalconfiguration.getProfileGroupEndings();
      this.profilegroupprefix= globalconfiguration.getProfileGroupPrefix();

      InitialContext jndicontext = new InitialContext();     
      Object objl = jndicontext.lookup("RaAdminSession");
      IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(objl, 
                                                                       IRaAdminSessionHome.class);
      raadminsession = raadminsessionhome.create();
      
      objl = jndicontext.lookup("AuthorizationSession");
      IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(objl, 
                                                                       IAuthorizationSessionHome.class);
      authorizationsession = authorizationsessionhome.create();
 
    }
    // Public methods 
    /** Returns all the directories and subdirectories from the given subdirectory */
    public String[] getDirectories()  {
      Vector directories = new Vector();
      String[] dummy = {};
      
      insertAvailableRules(directories);
      insertAvailableProfileGroupRules(directories);
      
      Collections.sort(directories);
      return (String[]) directories.toArray(dummy);  
    }
    
    // Private methods
    private void insertAvailableRules(Vector directories) {
      try{  
        directories.addAll(authorizationsession.getAvailableAccessRules());  
      }catch(RemoteException e){}
    }
    
    private void insertAvailableProfileGroupRules(Vector directories){
      try{  
        Collection profilegroupnames = raadminsession.getProfileGroupNames();
        if(profilegroupnames != null){
          Iterator i = profilegroupnames.iterator();
      
          while(i.hasNext()){
            String groupname = (String) i.next();
            directories.addElement(profilegroupprefix + "/" + groupname);
            for(int j=0;j < profilegroupendings.length; j++){
              directories.addElement(profilegroupprefix + "/" + groupname+profilegroupendings[j]);             
            }        
          }
        }
      }catch(RemoteException e){}  
    }
    // Private fields
    private String[] profilegroupendings;
    private String profilegroupprefix;
    private IRaAdminSessionRemote raadminsession;
    private IAuthorizationSessionRemote authorizationsession;
}
