package se.anatom.ejbca.webdist.webconfiguration;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
/**
 * A class handling the storage of a admins preferences. Currently all admin preferences are
 * saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id: AdminPreferenceDataHandler.java,v 1.8 2002/09/12 18:14:15 herrvendil Exp $
 */
public class AdminPreferenceDataHandler {

    /** Creates a new instance of AdminPreferences */
    public AdminPreferenceDataHandler(Admin administrator) throws RemoteException, NamingException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                               IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();
        this.administrator = administrator;
    }

    /** Retrieves the admin from the database or null if the admin doesn't exists. */
    public AdminPreference getAdminPreference(String certificatefingerprint) throws RemoteException {
     AdminPreference returnvalue=null;

      try{
         returnvalue = raadminsession.getAdminPreference(administrator, certificatefingerprint);
      }catch(Exception e) {
         returnvalue=null;
      }
      return returnvalue;
    }

    /** Adds a admin preference to the database */
    public void addAdminPreference(String certificatefingerprint, AdminPreference adminpreference)
                                  throws AdminExistsException, RemoteException {
      if(!raadminsession.addAdminPreference(administrator, certificatefingerprint, adminpreference))
        throw new AdminExistsException("Admin already exists in the database.");
    }

    /** Changes the admin preference for the given admin. */
    public void changeAdminPreference(String certificatefingerprint, AdminPreference adminpreference)
                              throws AdminDoesntExistException, RemoteException {
      if(!raadminsession.changeAdminPreference(administrator, certificatefingerprint, adminpreference))
        throw new AdminDoesntExistException("Admin doesn't exists in the database.");

    }
    
    /** Changes the admin preference for the given admin, without performing any logging. */
    public void changeAdminPreferenceNoLog(String certificatefingerprint, AdminPreference adminpreference)
                              throws AdminDoesntExistException, RemoteException {
      if(!raadminsession.changeAdminPreferenceNoLog(administrator, certificatefingerprint, adminpreference))
        throw new AdminDoesntExistException("Admin doesn't exists in the database.");

    }    

    /** Checks if admin preference exists in database. */
    public boolean existsAdminPreference(String certificatefingerprint) throws RemoteException {
      return raadminsession.existsAdminPreference(administrator, certificatefingerprint);

    }
    
    /** Returns the default administrator preference. */
    public AdminPreference getDefaultAdminPreference() throws RemoteException{
      return raadminsession.getDefaultAdminPreference(administrator);  
    }
    
    /** Saves the default administrator preference. */
    public void saveDefaultAdminPreference(AdminPreference adminpreference) throws RemoteException{
      raadminsession.saveDefaultAdminPreference(administrator, adminpreference);  
    }
    
    
    private IRaAdminSessionRemote raadminsession;
    private Admin                 administrator;
}
