package se.anatom.ejbca.webdist.rainterface;

import java.rmi.RemoteException;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileDoesntExistsException;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @version $Id: EndEntityProfileDataHandler.java,v 1.5 2003-07-24 08:43:33 anatom Exp $
 */
public class EndEntityProfileDataHandler {
    public static final String EMPTY_PROFILE = IRaAdminSessionRemote.EMPTY_ENDENTITYPROFILE;

    /**
     * Creates a new instance of EndEntityProfileDataHandler
     *
     * @param administrator DOCUMENT ME!
     */
    public EndEntityProfileDataHandler(Admin administrator)
        throws RemoteException, NamingException, FinderException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                    "RaAdminSession"), IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();
        this.administrator = administrator;
    }

    /**
     * Method to add a end entity profile. Throws EndEntityProfileExitsException if profile already
     * exists
     *
     * @param name DOCUMENT ME!
     * @param profile DOCUMENT ME!
     */
    public void addEndEntityProfile(String name, EndEntityProfile profile)
        throws EndEntityProfileExistsException, RemoteException {
        if (!raadminsession.addEndEntityProfile(administrator, name, profile)) {
            throw new EndEntityProfileExistsException(name);
        }
    }

    /**
     * Method to change a end entity profile. Throws EndEntityProfileDoesntExitsException if
     * profile cannot be found
     *
     * @param name DOCUMENT ME!
     * @param profile DOCUMENT ME!
     */
    public void changeEndEntityProfile(String name, EndEntityProfile profile)
        throws EndEntityProfileDoesntExistsException, RemoteException {
        if (!raadminsession.changeEndEntityProfile(administrator, name, profile)) {
            throw new EndEntityProfileDoesntExistsException(name);
        }
    }

    /**
     * Method to remove a end entity profile.
     *
     * @param name DOCUMENT ME!
     */
    public void removeEndEntityProfile(String name) throws RemoteException {
        raadminsession.removeEndEntityProfile(administrator, name);
    }

    /**
     * Metod to rename a end entity profile
     *
     * @param oldname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     */
    public void renameEndEntityProfile(String oldname, String newname)
        throws EndEntityProfileExistsException, RemoteException {
        if (!raadminsession.renameEndEntityProfile(administrator, oldname, newname)) {
            throw new EndEntityProfileExistsException(newname);
        }
    }

    /**
     * Method to get a reference to a end entityprofile.
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(String name)
        throws RemoteException {
        return raadminsession.getEndEntityProfile(administrator, name);
    }

    /**
     * Method to get a reference to a end entity profile.
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(int id)
        throws RemoteException {
        return raadminsession.getEndEntityProfile(administrator, id);
    }

    /**
     * Returns the number of end entity profiles i database.
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfEndEntityProfiles() throws RemoteException {
        return raadminsession.getNumberOfEndEntityProfiles(administrator);
    }

    /**
     * Returns an array containing all the profiles names.
     *
     * @return DOCUMENT ME!
     */
    public String[] getEndEntityProfileNames() throws RemoteException {
        String[] dummy = {  };
        TreeMap result = raadminsession.getEndEntityProfiles(administrator);

        return (String[]) result.keySet().toArray(dummy);
    }

    /**
     * Returns an array containing all the profiles.
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile[] getEndEntityProfiles() throws RemoteException {
        EndEntityProfile[] dummy = {  };
        TreeMap result = raadminsession.getEndEntityProfiles(administrator);

        return (EndEntityProfile[]) result.values().toArray(dummy);
    }

    /**
     * DOCUMENT ME!
     *
     * @param originalname DOCUMENT ME!
     * @param newname DOCUMENT ME!
     *
     * @throws EndEntityProfileExistsException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public void cloneEndEntityProfile(String originalname, String newname)
        throws EndEntityProfileExistsException, RemoteException {
        // Check if original profile already exists.
        if (!raadminsession.cloneEndEntityProfile(administrator, originalname, newname)) {
            throw new EndEntityProfileExistsException(newname);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param profilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public int getEndEntityProfileId(String profilename)
        throws RemoteException {
        return raadminsession.getEndEntityProfileId(administrator, profilename);
    }

    /**
     * DOCUMENT ME!
     *
     * @param lastprofile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public EndEntityProfile getLastEndEntityProfile(String lastprofile)
        throws RemoteException {
        return raadminsession.getEndEntityProfile(administrator, lastprofile);
    }

    private IRaAdminSessionRemote raadminsession;
    private Admin administrator;
}
