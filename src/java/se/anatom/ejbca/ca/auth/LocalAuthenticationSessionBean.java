
package se.anatom.ejbca.ca.auth;

import java.rmi.*;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ra.UserDataPK;
import se.anatom.ejbca.ra.UserDataRemote;
import se.anatom.ejbca.ra.UserDataHome;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;

/**
 * Authenticates users towards a user database.
 *
 * @version $Id: LocalAuthenticationSessionBean.java,v 1.10 2002-07-26 09:36:41 anatom Exp $
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {

    /** home interface to user entity bean */
    private UserDataHome userHome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        // Look up the UserDataLocal entity bean home interface
        userHome = (UserDataHome)lookup("java:comp/env/ejb/UserData", UserDataHome.class);
        debug("<ejbCreate()");
    }

   /**
    * Implements IAuthenticationSession::authenticateUser.
    * Implements a mechanism that queries a local database directly. Only allows authentication when user status is
    * STATUS_NEW, STATUS_FAILED or STATUS_INPROCESS.
    */
    public UserAuthData authenticateUser(String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">authenticateUser("+username+", hiddenpwd)");
        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataRemote data = userHome.findByPrimaryKey(pk);
            int status = data.getStatus();
            if ( (status == UserDataRemote.STATUS_NEW) || (status == UserDataRemote.STATUS_FAILED) || (status == UserDataRemote.STATUS_INPROCESS) ) {
                info("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());
                if (data.comparePassword(password) == false)
                {
                    error("Got request for user '"+username+"' with invalid password.");
                    throw new AuthLoginException("Wrong password for user.");
                }
                info("Authenticated user "+username);
                UserAuthData ret = new UserAuthData(data.getUsername(), data.getSubjectDN(), data.getSubjectEmail(), data.getType());
                debug("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            } else {
                error("Got request for user '"+username+"' with status '"+status+"', NEW, FAILED or INPROCESS required.");
                throw new AuthStatusException("User "+username+" has status '"+status+"', NEW, FAILED or INPROCESS required.");
            }
        } catch (ObjectNotFoundException oe) {
            error("Got request for nonexisting user '"+username+"'.");
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
            throw new EJBException(e.toString());
        }
    } //authenticateUser

   /**
    * Implements IAuthenticationSession::finishUser.
    * Implements a mechanism that uses a local database directly to set users status to UserDataRemote.STATUS_GENERATED.
    */
    public void finishUser(String username, String password) throws ObjectNotFoundException {
        debug(">finishUser("+username+", hiddenpwd)");
        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataRemote data = userHome.findByPrimaryKey(pk);
            data.setStatus(UserDataRemote.STATUS_GENERATED);
            info("Changed status of user '"+username+"' to STATUS_GENERATED.");
            debug("<finishUser("+username+", hiddenpwd)");
        } catch (ObjectNotFoundException oe) {
            error("Got request for nonexisting user '"+username+"'.");
            throw oe;
        } catch (Exception e) {
            throw new EJBException(e.toString());
        }
    } //finishUser
}
