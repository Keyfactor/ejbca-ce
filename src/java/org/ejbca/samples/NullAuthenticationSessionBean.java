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

package org.ejbca.samples;

import java.util.ArrayList;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;




/**
 * Approves all authentication requests that contain a DN as the username, password is ignored and
 * the username is returned as DN. Could be useful for demo purposes to give out certificates to anyone.
 * 
 * To install it must replace the current org.ejbca.core.model.authorization.LocalAuthorizationSessionBean
 * which will require some work from your part.
 *
 * @ejb.bean
 *   display-name="AuthenticationSB"
 *   name="AuthenticationSession"
 *   jndi-name="AuthenticationSession"
 *   local-jndi-name="AuthenticationSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *   generate="false"
 *
 * @ejb.transaction type="Supports"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 * 
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.samples.IAuthenticationSessionLocalHome"
 *   remote-class="org.ejbca.samples.IAuthenticationSessionHome"
 *   generate="none"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.samples.IAuthenticationSessionLocal"
 *   remote-class="org.ejbca.samples.IAuthenticationSessionRemote"
 *   generate="none"
 *
 *
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "NullAuthenticationSession")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NullAuthenticationSessionBean {
    private static final Logger log = Logger.getLogger(NullAuthenticationSessionBean.class);
    
    /** The remote interface of the log session bean */
    @EJB
    private LogSessionRemote logsession;


    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        log.trace(">ejbCreate()");

        log.trace("<ejbCreate()");
    }

    /**
     * Implements IAuthenticationSession::authenticateUser. Implements a mechanism that does no
     * real authentication. Returns the username as DN is the username contains a DN. Only returns
     * entities of type USER_ENDUSER. STATUS_NEW, STATUS_FAILED or STATUS_INPROCESS.
     *
     * @param admin administrator performing this task
     * @param username username to be authenticated
     * @param password password for user to be authenticated
     *
     * @return UserData for authenticated user
     */
    public UserDataVO authenticateUser(Admin admin, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
        log.trace(">authenticateUser(" + username + ", hiddenpwd)");

        try {
            // Does the username contain a DN?
            String dn = CertTools.stringToBCDNString(username);

            if ((dn != null) && (dn.length() > 0)) {
            	String email = null;
                ArrayList emails = CertTools.getEmailFromDN(dn);
                if (emails.size() > 0) {
                	email = (String)emails.get(0);
                }
            
                  logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,"NULL-Authenticated user");
               

                String altName = (email == null) ? null : ("rfc822Name=" + email);

                // Use default certificate profile 0
                UserDataVO ret = new UserDataVO(username, dn, admin.getCaId(), altName, email, UserDataConstants.STATUS_NEW, SecConst.USER_ENDUSER, SecConst.PROFILE_NO_PROFILE, SecConst.PROFILE_NO_PROFILE, 
                		                        null, null, SecConst.TOKEN_SOFT_BROWSERGEN,0,null);
                ret.setPassword(password);
                log.trace("<authenticateUser("+username+", hiddenpwd)");
                return ret;
            }
         
              logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,"User does not contain a DN.");
           

            throw new AuthLoginException("User " + username + " does not contain a DN.");
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
            throw new EJBException(e.toString());
        }
    } //authenticateUser

    /**
     * Implements IAuthenticationSession::finishUser. Does nothing...
     *
     * @param admin administrator performing this task
     * @param username username to be finished
     * @param password password for user to be finished
     */
    public void finishUser(Admin admin, String username, String password)
        throws ObjectNotFoundException {
        log.trace(">finishUser(" + username + ", hiddenpwd)");
        log.trace("<finishUser(" + username + ", hiddenpwd)");
    } //finishUser
}
