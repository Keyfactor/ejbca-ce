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
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocal;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.UserDataLocal;
import se.anatom.ejbca.ra.UserDataLocalHome;
import se.anatom.ejbca.ra.UserDataPK;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;


/**
 * Authenticates users towards a user database.
 *
 * @version $Id: LocalAuthenticationSessionBean.java,v 1.33 2005-04-11 09:17:53 anatom Exp $
 *
 * @ejb.bean
 *   display-name="AuthenticationSB"
 *   name="AuthenticationSession"
 *   jndi-name="AuthenticationSession"
 *   local-jndi-name="AuthenticationSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.ejb-external-ref
 *   description="The User entity bean"
 *   view-type="local"
 *   ejb-name="UserDataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.ca.store.UserDataLocalHome"
 *   business="se.anatom.ejbca.ca.store.UserDataLocal"
 *   link="UserData"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   business="se.anatom.ejbca.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref
 *   description="The RA Admin session bean"
 *   view-type="local"
 *   ejb-name="RaAdminSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Key Recovery Session Bean"
 *   view-type="local"
 *   ejb-name="KeyRecoverySessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocalHome"
 *   business="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocal"
 *   link="KeyRecoverySession"  
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.ca.auth.IAuthenticationSessionLocalHome"
 *   remote-class="se.anatom.ejbca.ca.auth.IAuthenticationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.ca.auth.IAuthenticationSessionLocal"
 *   remote-class="se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote"
 *
 * @ejb.security-identity run-as="InternalUser"
 *
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {
    /** home interface to user entity bean */
    private UserDataLocalHome userHome = null;

    /** The remote interface of the log session bean */
    private ILogSessionLocal logsession;
    
    /** The local interface of the keyrecovery session bean */
    private IKeyRecoverySessionLocal keyrecoverysession = null;
    
    /** boolean indicating if keyrecovery should be used. */
    private boolean usekeyrecovery = true;
    

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     * @ejb.create-method
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        
        // Look up the UserDataLocal entity bean home interface
        userHome = (UserDataLocalHome)getLocator().getLocalHome(UserDataLocalHome.COMP_NAME);
        ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
        logsession = logsessionhome.create();
        
        debug("<ejbCreate()");
    }
    
    /**
     * Method returning the keyrecovery session if key recovery is configured in the globalconfiguration
     * else null is returned. 
     * 
     * @param admin
     * @return
     */
    private IKeyRecoverySessionLocal getKeyRecoverySession(Admin admin){
    	if(usekeyrecovery && keyrecoverysession == null){
    		try{
              IRaAdminSessionLocalHome raadminhome = (IRaAdminSessionLocalHome) getLocator().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);                            
              IRaAdminSessionLocal raadmin = raadminhome.create();        
              usekeyrecovery = (raadmin.loadGlobalConfiguration(admin)).getEnableKeyRecovery();

              if(usekeyrecovery){
                IKeyRecoverySessionLocalHome keyrecoveryhome = (IKeyRecoverySessionLocalHome) getLocator().getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
                keyrecoverysession = keyrecoveryhome.create();
              }
    		}catch(Exception e){
    			  error("Error in getKeyRecoverySession: ", e);
    	          throw new EJBException(e);
            }
    	}
    	
    	return keyrecoverysession;
    }

    /**
     * Authenticates a user to the user database and returns the user DN.
     *
     * @param username unique username within the instance
     * @param password password for the user
     *
     * @return UserAuthData, never returns null
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @ejb.interface-method
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
                  logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for user with invalid password: "+username);
                  throw new AuthLoginException("Wrong password for user.");
                }

                logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_USERAUTHENTICATION,"Authenticated user: "+username);
                UserAuthData ret = new UserAuthData(data.getUsername(), data.getClearPassword(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), data.getType(), data.getCertificateProfileId(), data.getExtendedInformation());
                debug("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            } else {
                logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request with status '"+status+"', NEW, FAILED or INPROCESS required: "+username);
                throw new AuthStatusException("User "+username+" has status '"+status+"', NEW, FAILED or INPROCESS required.");
            }
        } catch (ObjectNotFoundException oe) {
            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user: "+username);
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
     * Set the status of a user to finished, called when a user has been successfully processed. If
     * possible sets users status to UserData.STATUS_GENERATED, which means that the user cannot
     * be authenticated anymore. NOTE: May not have any effect of user database is remote.
     *
     * @param username unique username within the instance
     * @param password password for the user
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @ejb.interface-method
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
                                    
            // Reset key recoveryflag if keyrecovery is used.
            if(this.getKeyRecoverySession(admin) != null){            	
              getKeyRecoverySession(admin).unmarkUser(admin,username);
            }
            
            logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,"Changed status to STATUS_GENERATED.");
            debug("<finishUser("+username+", hiddenpwd)");
        } catch (ObjectNotFoundException oe) {
            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,"Got request for nonexisting user.");
            throw oe;
        } catch (Exception e) {
            error("Unexpected error in finnishUser(): ", e);
            throw new EJBException(e.toString());
        }
    } //finishUser
}
