/*
 * EndEntityProfileDataHandler.java
 *
 * Created on den 12 april 2002, 13:03
 */

package se.anatom.ejbca.webdist.rainterface;

import java.io.IOException;
import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileDoesntExistsException;
import se.anatom.ejbca.log.Admin;
/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 */
public class EndEntityProfileDataHandler {

    public static final String EMPTY_PROFILE        = IRaAdminSessionRemote.EMPTY_ENDENTITYPROFILE;    
    /** Creates a new instance of EndEntityProfileDataHandler */
    public EndEntityProfileDataHandler(Admin administrator) throws RemoteException, NamingException, FinderException, CreateException{
       InitialContext jndicontext = new InitialContext();
       IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
       raadminsession = raadminsessionhome.create();        
       this.administrator = administrator;
          
    }
        
       /** Method to add a end entity profile. Throws EndEntityProfileExitsException if profile already exists  */
    public void addEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileExistsException, RemoteException {
      if(!raadminsession.addEndEntityProfile(administrator, name,profile))   
        throw new EndEntityProfileExistsException(name);
    }
      
       /** Method to change a end entity profile. Throws EndEntityProfileDoesntExitsException if profile cannot be found */     
    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileDoesntExistsException, RemoteException {
       if(!raadminsession.changeEndEntityProfile(administrator, name,profile))
         throw new EndEntityProfileDoesntExistsException(name); 
    }
    
    /** Method to remove a end entity profile.*/ 
    public void removeEndEntityProfile(String name) throws RemoteException{
        raadminsession.removeEndEntityProfile(administrator, name);
    }
    
    /** Metod to rename a end entity profile */
    public void renameEndEntityProfile(String oldname, String newname) throws EndEntityProfileExistsException, RemoteException{
      if(!raadminsession.renameEndEntityProfile(administrator, oldname,newname))   
        throw new EndEntityProfileExistsException(newname);
    }
    
    
      /** Method to get a reference to a end entityprofile.*/ 
    public EndEntityProfile getEndEntityProfile(String name) throws RemoteException {
        return raadminsession.getEndEntityProfile(administrator, name);
    }  
    
      /** Method to get a reference to a end entity profile.*/ 
    public EndEntityProfile getEndEntityProfile(int id) throws RemoteException {
        return raadminsession.getEndEntityProfile(administrator, id);
    }      
          
    /** Returns the number of end entity profiles i database. */
    public int getNumberOfEndEntityProfiles() throws RemoteException {
      return raadminsession.getNumberOfEndEntityProfiles(administrator);
    }
    
    /** Returns an array containing all the profiles names.*/
     public String[] getEndEntityProfileNames() throws RemoteException {
      String[] dummy={}; 
      TreeMap result = raadminsession.getEndEntityProfiles(administrator);      
      return (String[]) result.keySet().toArray(dummy);  
    }
    
    /** Returns an array containing all the profiles.*/
    public EndEntityProfile[] getEndEntityProfiles() throws RemoteException {
      EndEntityProfile[] dummy={}; 
      TreeMap result = raadminsession.getEndEntityProfiles(administrator);      
      return (EndEntityProfile[]) result.values().toArray(dummy);   
    }
         
      
    public void cloneEndEntityProfile(String originalname, String newname) throws EndEntityProfileExistsException, RemoteException{         
      // Check if original profile already exists. 
      if(!raadminsession.cloneEndEntityProfile(administrator, originalname,newname)){
        throw new EndEntityProfileExistsException(newname);        
      }       
    }
    
    public int getEndEntityProfileId(String profilename) throws RemoteException{
      return raadminsession.getEndEntityProfileId(administrator, profilename);  
    }
       
    public EndEntityProfile getLastEndEntityProfile(String lastprofile) throws RemoteException{
      return raadminsession.getEndEntityProfile(administrator, lastprofile);
    }
    
    private IRaAdminSessionRemote raadminsession; 
    private Admin                 administrator;
}
