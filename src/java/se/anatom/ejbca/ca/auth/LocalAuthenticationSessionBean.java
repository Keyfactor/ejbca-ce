
package se.anatom.ejbca.ca.auth;

import java.rmi.*;

import javax.ejb.*;
import java.util.Date;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ra.UserDataPK;
import se.anatom.ejbca.ra.UserDataRemote;
import se.anatom.ejbca.ra.UserDataHome;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.LogEntry;

/**
 * Authenticates users towards a user database.
 *
 * @version $Id: LocalAuthenticationSessionBean.java,v 1.18 2003-01-12 17:16:31 anatom Exp $
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {

    /** home interface to user entity bean */
    private UserDataHome userHome = null;

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;


    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        // Look up the UserDataLocal entity bean home interface
        userHome = (UserDataHome)lookup("java:comp/env/ejb/UserData", UserDataHome.class);

        try{
          ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);
          logsession = logsessionhome.create();
        }catch(Exception e){
          throw new EJBException(e);
        }
        debug("<ejbCreate()");
    }

   /**
    * Implements IAuthenticationSession::authenticateUser.
    * Implements a mechanism that queries a local database directly. Only allows authentication when user status is
    * STATUS_NEW, STATUS_FAILED or STATUS_INPROCESS.
    */
    public UserAuthData authenticateUser(Admin admin, String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">authenticateUser("+username+", hiddenpwd)");
        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataRemote data = userHome.findByPrimaryKey(pk);
            int status = data.getStatus();
            if ( (status == UserDataRemote.STATUS_NEW) || (status == UserDataRemote.STATUS_FAILED) || (status == UserDataRemote.STATUS_INPROCESS) ) {
                debug("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());
                if (data.comparePassword(password) == false)
                {
                  try{
                    logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for user with invalid password.");
                  }catch(RemoteException re){
                    throw new EJBException(re);
                  }
                  throw new AuthLoginException("Wrong password for user.");
                }
                 try{
                   logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_USERAUTHENTICATION,"Authenticated user.");
                 }catch(RemoteException re){
                   throw new EJBException(re);
                 }
                UserAuthData ret = new UserAuthData(data.getUsername(), data.getSubjectDN(), data.getSubjectAltName(), data.getSubjectEmail(), data.getType(), data.getCertificateProfileId());
                debug("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            } else {
               try{
                 logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request with status '"+status+"', NEW, FAILED or INPROCESS required.");
               }catch(RemoteException re){
                 throw new EJBException(re);
               }
                throw new AuthStatusException("User "+username+" has status '"+status+"', NEW, FAILED or INPROCESS required.");
            }
        } catch (ObjectNotFoundException oe) {
            try{
               logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user.");
            }catch(RemoteException re){
               throw new EJBException(re);
            }
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
    public void finishUser(Admin admin, String username, String password) throws ObjectNotFoundException {
        debug(">finishUser("+username+", hiddenpwd)");
        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataRemote data = userHome.findByPrimaryKey(pk);
            data.setStatus(UserDataRemote.STATUS_GENERATED);
            data.setTimeModified((new Date()).getTime());
            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Changed status to STATUS_GENERATED.");
            debug("<finishUser("+username+", hiddenpwd)");
        } catch (ObjectNotFoundException oe) {
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user.");
            }catch(RemoteException re){
              throw new EJBException(re);
            }
            throw oe;
        } catch (Exception e) {
            throw new EJBException(e.toString());
        }
    } //finishUser
}
