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
 
package se.anatom.ejbca;

import javax.ejb.EJBException;
import javax.ejb.SessionBean;
import javax.ejb.SessionContext;
import javax.naming.*;
import javax.rmi.PortableRemoteObject;

import org.apache.log4j.Logger;
import se.anatom.ejbca.util.ServiceLocator;


/**
 * Base for Session Beans providing common features, new Session Beans should extend this.
 *
 * @version $Id: BaseSessionBean.java,v 1.13 2005-02-11 13:12:14 anatom Exp $
 */
public class BaseSessionBean implements SessionBean {

    /** Log4j instance for actual implementation class */
    public transient Logger log;
    private transient SessionContext ctx;

    /** Cached initial context to save JNDI lookups */
    transient InitialContext cacheCtx = null;

    /**
     * Initializes logging mechanism per instance
     */
    public BaseSessionBean() {
        log = Logger.getLogger(this.getClass());
    }

    /**
     * Logs a message with priority DEBUG
     *
     * @param msg Message
     */
    public void debug(String msg) {
        log.debug(msg);
    }

    /**
     * Logs a message and an exception with priority DEBUG
     *
     * @param msg Message
     * @param t Exception
     */
    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    /**
     * Logs a message with priority INFO
     *
     * @param msg Message
     */
    public void info(String msg) {
        log.info(msg);
    }

    /**
     * Logs a message and an exception with priority INFO
     *
     * @param msg Message
     * @param t Exception
     */
    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    /**
     * Logs a message with priority WARN
     *
     * @param msg Message
     */
    public void warn(String msg) {
        log.warn(msg);
    }

    /**
     * Logs a message and an exception with priority WARN
     *
     * @param msg Message
     * @param t Exception
     */
    public void warn(String msg, Throwable t) {
        log.warn(msg, t);
    }

    /**
     * Logs a message with priority ERROR
     *
     * @param msg Message
     */
    public void error(String msg) {
        log.error(msg);
    }

    /**
     * Logs a message and an exception with priority ERROR
     *
     * @param msg Message
     * @param t Exception
     */
    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }

    /**
     * Gets InitialContext
     *
     * @return InitialContext
     * @deprecated Use #getLocator()
     */
    public InitialContext getInitialContext() {
        try {
            if (cacheCtx == null) {
                cacheCtx = new InitialContext();
            }
            return cacheCtx;
        } catch (NamingException e) {
            throw new EJBException(e);
        }
    }

    /**
     * Looks up a JNDI name using the (cached) InitialContext
     *
     * @param jndiName the JNDI name to lookup.
     * @param type the class type to narrow the object to.
     *
     * @return Object that can be casted to 'type'.
     * @deprecated Use #getLocator()
     */
    public Object lookup(String jndiName, Class type) {
        Object ref = lookup(jndiName);
        return PortableRemoteObject.narrow(ref, type);
    }

    /**
     * Looks up a JNDI name using the (cached) InitialContext
     *
     * @param jndiName the JNDI name to lookup.
     *
     * @return Object that can be casted to 'type'.
     * @deprecated Use #getLocator()
     */
    public Object lookup(String jndiName) {
        return getLocator().getObject(jndiName);
    }

    /**
     * Activates bean, creates log for base session.
     *
     * @throws javax.ejb.EJBException on error
     * @throws java.rmi.RemoteException on error
     */
    public void ejbActivate() throws javax.ejb.EJBException, java.rmi.RemoteException {
        log = Logger.getLogger(this.getClass());
    }

    /**
     * Removes bean, does nothing for base session.
     *
     * @throws javax.ejb.EJBException on error
     * @throws java.rmi.RemoteException on error
     */
    public void ejbRemove() throws javax.ejb.EJBException, java.rmi.RemoteException {
    }

    /**
     * Passivates bean, does nothing for base session.
     *
     * @throws javax.ejb.EJBException on error
     * @throws java.rmi.RemoteException on error
     */
    public void ejbPassivate() throws javax.ejb.EJBException, java.rmi.RemoteException {
    }

    /**
     * Sets current session context
     *
     * @param ctx current session context
     *
     * @throws javax.ejb.EJBException on error
     * @throws java.rmi.RemoteException on error
     */
    public void setSessionContext(final javax.ejb.SessionContext ctx)
        throws javax.ejb.EJBException, java.rmi.RemoteException {
        this.ctx = ctx;
    }

    /**
     * Get session contect
     *
     * @return current session context
     */
    public SessionContext getSessionContext() {
        return ctx;
    }

    /**
     * return the environment entries locator
     * @return return the environment entries locator
     */
    protected ServiceLocator getLocator() {
        return ServiceLocator.getInstance();
    }
    
}
