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
 
package org.ejbca.ui.web.admin.configuration;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * A class handling the storage of a admins preferences. Currently all admin preferences are
 * saved to a database.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AdminPreferenceDataHandler implements java.io.Serializable {

    /** Creates a new instance of AdminPreferences */
    public AdminPreferenceDataHandler(Admin administrator) throws RemoteException, NamingException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                               IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();
        this.administrator = administrator;
    }

    /** Retrieves the admin from the database or null if the admin doesn't exists. */
    public AdminPreference getAdminPreference(String certificatefingerprint) {
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
      if(!raadminsession.addAdminPreference(administrator, certificatefingerprint, adminpreference)) {
        throw new AdminExistsException("Admin already exists in the database.");
      }
    }

    /** Changes the admin preference for the given admin. */
    public void changeAdminPreference(String certificatefingerprint, AdminPreference adminpreference)
                              throws AdminDoesntExistException, RemoteException {
      if(!raadminsession.changeAdminPreference(administrator, certificatefingerprint, adminpreference)) {
        throw new AdminDoesntExistException("Admin does not exist in the database.");
      }
    }
    
    /** Changes the admin preference for the given admin, without performing any logging. */
    public void changeAdminPreferenceNoLog(String certificatefingerprint, AdminPreference adminpreference)
                              throws AdminDoesntExistException, RemoteException {
      if(!raadminsession.changeAdminPreferenceNoLog(administrator, certificatefingerprint, adminpreference)) {
        throw new AdminDoesntExistException("Admin does not exist in the database.");
      }
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
