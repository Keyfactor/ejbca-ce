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
 
package org.ejbca.core.ejb;

import javax.ejb.SessionBean;
import javax.ejb.SessionContext;
import javax.naming.InitialContext;

import org.apache.log4j.Logger;



/**
 * Base for Session Beans providing common features, new Session Beans should extend this.
 *
 * @version $Id$
 * 
 * TODO: This class should not implement SessionBean.
 */
public class BaseSessionBean implements SessionBean {

    /** Log4j instance for actual implementation class */
    public transient Logger log;
    private SessionContext ctx;

    /** Cached initial context to save JNDI lookups */
    transient InitialContext cacheCtx = null;

    /**
     * Initializes logging mechanism per instance
     */
    public BaseSessionBean() {
        log = Logger.getLogger(this.getClass());
    }

    /**
     * Logs a message with priority TRACE
     *
     * @param msg Message
     */
    public void trace(String msg) {
        log.trace(msg);
    }

    /**
     * Logs a message and an exception with priority TRACE
     *
     * @param msg Message
     * @param t Exception
     */
    public void trace(String msg, Throwable t) {
        log.trace(msg, t);
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
