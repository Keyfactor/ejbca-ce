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
 
package se.anatom.ejbca.ca.auth;

import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.UserDataLocal;
import se.anatom.ejbca.ra.UserDataLocalHome;
import se.anatom.ejbca.ra.UserDataPK;


/**
 * Authenticates users towards a user database.
 *
 * @version $Id: LocalAuthenticationSessionBean.java,v 1.26 2004-05-13 15:34:40 herrvendil Exp $
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {
    /** home interface to user entity bean */
    private UserDataLocalHome userHome = null;

    /** The remote interface of the log session bean */
    private ILogSessionLocal logsession;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");

        // Look up the UserDataLocal entity bean home interface
        userHome = (UserDataLocalHome)lookup("java:comp/env/ejb/UserDataLocal", UserDataLocalHome.class);

        try{
          ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
          logsession = logsessionhome.create();
        }catch(Exception e){
          throw new EJBException(e);
        }

        debug("<ejbCreate()");
    }

    /**
     * Implements IAuthenticationSession::authenticateUser. Implements a mechanism that queries a
     * local database directly. Only allows authentication when user status is STATUS_NEW,
     * STATUS_FAILED or STATUS_INPROCESS.
     *
     * @param admin administrator performing this task
     * @param username username to be authenticated
     * @param password password for user to be authenticated
     *
     * @return UserData for authenticated user
     */
    public UserAuthData authenticateUser(Admin admin, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">authenticateUser(" + username + ", hiddenpwd)");

        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data = userHome.findByPrimaryKey(pk);
            int status = data.getStatus();
            if ( (status == UserDataLocal.STATUS_NEW) || (status == UserDataLocal.STATUS_FAILED) || (status == UserDataLocal.STATUS_INPROCESS) || (status == UserDataLocal.STATUS_KEYRECOVERY)) {
                debug("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());
                if (data.comparePassword(password) == false)
                {                  
                  logsession.log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for user with invalid password: "+username);                  
                  throw new AuthLoginException("Wrong password for user.");
                }
                 
                logsession.log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_USERAUTHENTICATION,"Authenticated user: "+username);
                UserAuthData ret = new UserAuthData(data.getUsername(), data.getClearPassword(), data.getSubjectDN(), data.getCAId(), data.getSubjectAltName(), data.getSubjectEmail(), data.getType(), data.getCertificateProfileId(), data.getExtendedInformation());
                debug("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            } else {               
                logsession.log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request with status '"+status+"', NEW, FAILED or INPROCESS required: "+username);               
                throw new AuthStatusException("User "+username+" has status '"+status+"', NEW, FAILED or INPROCESS required.");
            }
        } catch (ObjectNotFoundException oe) {            
            logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user: "+username);            
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
            error("Unexpected error in authenticateUser(): ", e);
            throw new EJBException(e.toString());
        }
    } //authenticateUser

    /**
     * Implements IAuthenticationSession::finishUser. Implements a mechanism that uses a local
     * database directly to set users status to UserDataRemote.STATUS_GENERATED.
     *
     * @param admin administrator performing this task
     * @param username username to be finished
     * @param password password for user to be finished
     */
    public void finishUser(Admin admin, String username, String password)
        throws ObjectNotFoundException {
        debug(">finishUser(" + username + ", hiddenpwd)");

        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data = userHome.findByPrimaryKey(pk);
            data.setStatus(UserDataLocal.STATUS_GENERATED);
            data.setTimeModified((new Date()).getTime());
            logsession.log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Changed status to STATUS_GENERATED.");
            debug("<finishUser("+username+", hiddenpwd)");
        } catch (ObjectNotFoundException oe) {            
            logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user.");            
            throw oe;
        } catch (Exception e) {
            error("Unexpected error in finnishUser(): ", e);
            throw new EJBException(e.toString());
        }
    } //finishUser
}
