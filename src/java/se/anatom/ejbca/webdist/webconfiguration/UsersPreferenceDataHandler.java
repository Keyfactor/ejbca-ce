package se.anatom.ejbca.webdist.webconfiguration;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.UserPreference;
import se.anatom.ejbca.log.Admin;
/**
 * A class handling the storage of user preferences. Currently all user preferences are
 * save to a database.
 *
 * @author  Philip Vendil
 * @version $Id: UsersPreferenceDataHandler.java,v 1.8 2002-09-12 18:14:15 herrvendil Exp $
 */
public class UsersPreferenceDataHandler {

    /** Creates a new instance of UsersPreferences */
    public UsersPreferenceDataHandler(Admin administrator) throws RemoteException, NamingException, CreateException {
        InitialContext jndicontext = new InitialContext();
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                               IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create(administrator);
    }

    /** Retrieves the user from the database or null if the user doesn't exists. */
    public UserPreference getUserPreference(BigInteger certificateserialnumber) throws RemoteException {
     UserPreference returnvalue=null;

      try{
         returnvalue = raadminsession.getUserPreference(certificateserialnumber);
      }catch(Exception e) {
         returnvalue=null;
      }
      return returnvalue;
    }

    /** Adds a user preference to the database */
    public void addUserPreference(BigInteger certificateserialnumber, UserPreference userpreference)
                                  throws UserExistsException, RemoteException {
      if(!raadminsession.addUserPreference(certificateserialnumber, userpreference))
        throw new UserExistsException("User already exists in the database.");
    }

    /** Changes the user preference for the given user. */
    public void changeUserPreference(BigInteger certificateserialnumber, UserPreference userpreference)
                              throws UserDoesntExistException, RemoteException {
      if(!raadminsession.changeUserPreference(certificateserialnumber, userpreference))
        throw new UserDoesntExistException("User doesn't exists in the database.");

    }

    /** Checks if user preference exists in database. */
    public boolean existsUserPreference(BigInteger certificateserialnumber) throws RemoteException {
      return raadminsession.existsUserPreference(certificateserialnumber);

    }
    private IRaAdminSessionRemote raadminsession;
}
