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

package org.ejbca.core.ejb.ca.auth;

import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.UserDataLocal;
import org.ejbca.core.ejb.ra.UserDataLocalHome;
import org.ejbca.core.ejb.ra.UserDataPK;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;





/**
 * Authenticates users towards a user database.
 *
 * @version $Id: LocalAuthenticationSessionBean.java,v 1.9 2007-11-23 17:46:33 anatom Exp $
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
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionRemote"
 *
 * @ejb.ejb-external-ref
 *   description="The User Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The User entity bean"
 *   view-type="local"
 *   ref-name="ejb/UserDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.UserDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.UserDataLocal"
 *   link="UserData"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref
 *   description="The RA Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Key Recovery Session Bean"
 *   view-type="local"
 *   ref-name="ejb/KeyRecoverySessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome"
 *   business="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal"
 *   link="KeyRecoverySession"  
 *
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {

    /** home interface to user entity bean */
    private UserDataLocalHome userHome = null;
    
    /** interface to user admin session bean */
    private IUserAdminSessionLocal usersession = null;
    
    /** The remote interface of the log session bean */
    private ILogSessionLocal logsession;
    
    /** The local interface of the keyrecovery session bean */
    private IKeyRecoverySessionLocal keyrecoverysession = null;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
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
        
        userHome = (UserDataLocalHome)getLocator().getLocalHome(UserDataLocalHome.COMP_NAME);
        ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
        logsession = logsessionhome.create();
        IUserAdminSessionLocalHome usersessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
        usersession = usersessionhome.create();
        
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
    	if(keyrecoverysession == null){
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
     * @return UserDataVO, never returns null
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @ejb.interface-method
     */
    public UserDataVO authenticateUser(Admin admin, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        debug(">authenticateUser(" + username + ", hiddenpwd)");

        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data = userHome.findByPrimaryKey(pk);
            int status = data.getStatus();
            if ( (status == UserDataConstants.STATUS_NEW) || (status == UserDataConstants.STATUS_FAILED) || (status == UserDataConstants.STATUS_INPROCESS) || (status == UserDataConstants.STATUS_KEYRECOVERY)) {
                debug("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());
                if (data.comparePassword(password) == false)
                {
                	String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                	logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,msg);
                	throw new AuthLoginException(msg);
                }

            	String msg = intres.getLocalizedMessage("authentication.authok", username);            	
                logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_USERAUTHENTICATION,msg);
                UserDataVO ret = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), 
                		data.getStatus(), data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId(),
                		new Date(data.getTimeCreated()), new Date(data.getTimeModified()), data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());  
                ret.setPassword(data.getClearPassword());                             
                debug("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            }
        	String msg = intres.getLocalizedMessage("authentication.wrongstatus", new Integer(status), username);            	
            logsession.log(admin, data.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,msg);
            throw new AuthStatusException("User "+username+" has status '"+status+"', NEW, FAILED or INPROCESS required.");
        } catch (ObjectNotFoundException oe) {
        	String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,msg);
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("error.unknown");            	
            error(msg, e);
            throw new EJBException(e);
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
    public void finishUser(Admin admin, String username, String password) throws ObjectNotFoundException {
        debug(">finishUser(" + username + ", hiddenpwd)");

        try {
            // Change status of the user with username username
        	UserDataVO data = usersession.findUser(admin, username);
        	if (data == null) {
        		throw new FinderException("User '"+username+"' can not be found.");
        	}
        	// This admin can be the public web user, which may not be allowed to change status,
        	// this is a bit ugly, but what can a man do...
        	Admin statusadmin = new Admin(Admin.TYPE_INTERNALUSER);
        	usersession.setUserStatus(statusadmin, username, UserDataConstants.STATUS_GENERATED);
        	String msg = intres.getLocalizedMessage("authentication.statuschanged", username);            	
            logsession.log(admin, data.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_INFO_CHANGEDENDENTITY,msg);
            debug("<finishUser("+username+", hiddenpwd)");
        } catch (FinderException e) {
        	String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(),username, null, LogEntry.EVENT_ERROR_USERAUTHENTICATION,msg);
            throw new ObjectNotFoundException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			// Should never happen
            error("AuthorizationDeniedException: ", e);
            throw new EJBException(e);
		} catch (ApprovalException e) {
			// Should never happen
            error("ApprovalException: ", e);
            throw new EJBException(e);
		} catch (WaitingForApprovalException e) {
			// Should never happen
            error("ApprovalException: ", e);
            throw new EJBException(e);
		}
    } //finishUser
}
