/*
 * ProfileDataHandler.java
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
import se.anatom.ejbca.ra.raadmin.Profile;
import se.anatom.ejbca.ra.raadmin.ProfileExistsException;
import se.anatom.ejbca.ra.raadmin.ProfileDoesntExistsException;
/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 */
public class ProfileDataHandler {

    public static final String EMPTY_PROFILE        = IRaAdminSessionRemote.EMPTY_PROFILE;    
    /** Creates a new instance of ProfileDataHandler */
    public ProfileDataHandler() throws   RemoteException, NamingException, FinderException, CreateException{
       InitialContext jndicontext = new InitialContext();
       IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
       raadminsession = raadminsessionhome.create();               
          
    }
        
       /** Method to add a profile. Throws ProfileExitsException if profile already exists  */
    public void addProfile(String name, Profile profile) throws ProfileExistsException, RemoteException {
      if(!raadminsession.addProfile(name,profile))   
        throw new ProfileExistsException(name);
    }
      
       /** Method to change a  profile. Throws ProfileDoesntExitsException if profile cannot be found */     
    public void changeProfile(String name, Profile profile) throws ProfileDoesntExistsException, RemoteException {
       if(!raadminsession.changeProfile(name,profile))
         throw new ProfileDoesntExistsException(name); 
    }
    
    /** Method to remove a profile.*/ 
    public void removeProfile(String name) throws RemoteException{
        raadminsession.removeProfile(name);
    }
    
    /** Metod to rename a profile */
    public void renameProfile(String oldname, String newname) throws ProfileExistsException, RemoteException{
      if(!raadminsession.renameProfile(oldname,newname))   
        throw new ProfileExistsException(newname);
    }
    
    
      /** Method to get a reference to a profile.*/ 
    public Profile getProfile(String name) throws RemoteException {
        return raadminsession.getProfile(name);
    }  
    
      /** Method to get a reference to a profile.*/ 
    public Profile getProfile(int id) throws RemoteException {
        return raadminsession.getProfile(id);
    }      
          
    /** Returns the number of profiles i database. */
    public int getNumberOfProfiles() throws RemoteException {
      return raadminsession.getNumberOfProfiles();
    }
    
    /** Returns an array containing all the profiles names.*/
     public String[] getProfileNames() throws RemoteException {
      String[] dummy={}; 
      TreeMap result = raadminsession.getProfiles();      
      return (String[]) result.keySet().toArray(dummy);  
    }
    
    /** Returns an array containing all the profiles.*/
    public Profile[] getProfiles() throws RemoteException {
      Profile[] dummy={}; 
      TreeMap result = raadminsession.getProfiles();      
      return (Profile[]) result.values().toArray(dummy);   
    }
         
    public String[][][] getProfilesAsStrings() throws RemoteException{
      int numberofprofiles = raadminsession.getNumberOfProfiles(); 
      String[][][] returnvalue = new String[numberofprofiles][1][1];
      TreeMap profiles = raadminsession.getProfiles();
      Iterator j = profiles.keySet().iterator();
      for(int i=0 ; i < numberofprofiles ; i++){
         returnvalue[i] = ((Profile) profiles.get((String) j.next())).getAllValues();   
      }        
      return returnvalue;  
    }
    
     public String[][] getProfileAsStrings(String name) throws RemoteException{
      Profile profile = raadminsession.getProfile(name);  
      String[][] returnvalue = new String[1][1];
      returnvalue = profile.getAllValues();   
      return returnvalue;  
    }   
    
    public void cloneProfile(String originalname, String newname) throws ProfileExistsException, RemoteException{         
      // Check if original profile already exists. 
      if(!raadminsession.cloneProfile(originalname,newname)){
        throw new ProfileExistsException(newname);        
      }       
    }
    
    public int getProfileId(String profilename) throws RemoteException{
      return raadminsession.getProfileId(profilename);  
    }
   
    public String[][] getLastProfileAsString(String lastprofile) throws RemoteException{
      return raadminsession.getProfile(lastprofile).getAllValues();  
    }
    
    public Profile getLastProfile(String lastprofile) throws RemoteException{
      return raadminsession.getProfile(lastprofile);
    }
    
    private IRaAdminSessionRemote raadminsession; 
}
