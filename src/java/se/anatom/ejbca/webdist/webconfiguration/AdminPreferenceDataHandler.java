package se.anatom.ejbca.webdist.webconfiguration;

import java.math.BigInteger;
import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * A class handling the storage of a admins preferences. Currently all admin preferences are saved
 * to a database.
 *
 * @author Philip Vendil
 * @version $Id: AdminPreferenceDataHandler.java,v 1.8 2002/09/12 18:14:15 herrvendil Exp $
 */
public class AdminPreferenceDataHandler {
    /**
     * Creates a new instance of AdminPreferences
     *
     * @param administrator DOCUMENT ME!
     */
    public AdminPreferenceDataHandler(Admin administrator)
        throws RemoteException, NamingException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                    "RaAdminSession"), IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();
        this.administrator = administrator;
    }

    /**
     * Retrieves the admin from the database or null if the admin doesn't exists.
     *
     * @param certificateserialnumber DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference(BigInteger certificateserialnumber)
        throws RemoteException {
        AdminPreference returnvalue = null;

        try {
            returnvalue = raadminsession.getAdminPreference(administrator, certificateserialnumber);
        } catch (Exception e) {
            returnvalue = null;
        }

        return returnvalue;
    }

    /**
     * Adds a admin preference to the database
     *
     * @param certificateserialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     */
    public void addAdminPreference(BigInteger certificateserialnumber,
        AdminPreference adminpreference) throws AdminExistsException, RemoteException {
        if (!raadminsession.addAdminPreference(administrator, certificateserialnumber,
                    adminpreference)) {
            throw new AdminExistsException("Admin already exists in the database.");
        }
    }

    /**
     * Changes the admin preference for the given admin.
     *
     * @param certificateserialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     */
    public void changeAdminPreference(BigInteger certificateserialnumber,
        AdminPreference adminpreference) throws AdminDoesntExistException, RemoteException {
        if (!raadminsession.changeAdminPreference(administrator, certificateserialnumber,
                    adminpreference)) {
            throw new AdminDoesntExistException("Admin doesn't exists in the database.");
        }
    }

    /**
     * Changes the admin preference for the given admin, without performing any logging.
     *
     * @param certificateserialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     */
    public void changeAdminPreferenceNoLog(BigInteger certificateserialnumber,
        AdminPreference adminpreference) throws AdminDoesntExistException, RemoteException {
        if (!raadminsession.changeAdminPreferenceNoLog(administrator, certificateserialnumber,
                    adminpreference)) {
            throw new AdminDoesntExistException("Admin doesn't exists in the database.");
        }
    }

    /**
     * Checks if admin preference exists in database.
     *
     * @param certificateserialnumber DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean existsAdminPreference(BigInteger certificateserialnumber)
        throws RemoteException {
        return raadminsession.existsAdminPreference(administrator, certificateserialnumber);
    }

    /**
     * Returns the default administrator preference.
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getDefaultAdminPreference()
        throws RemoteException {
        return raadminsession.getDefaultAdminPreference(administrator);
    }

    /**
     * Saves the default administrator preference.
     *
     * @param adminpreference DOCUMENT ME!
     */
    public void saveDefaultAdminPreference(AdminPreference adminpreference)
        throws RemoteException {
        raadminsession.saveDefaultAdminPreference(administrator, adminpreference);
    }

    private IRaAdminSessionRemote raadminsession;
    private Admin administrator;
}
