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

import se.anatom.ejbca.util.SimpleSequenceGenerator;
import se.anatom.ejbca.util.ServiceLocator;

import javax.ejb.EntityBean;
import javax.ejb.EntityContext;
import javax.ejb.EJBLocalHome;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;


/**
 * Base class for entity beans implementing required methods and helpers.
 *
 * @version $Id: BaseEntityBean.java,v 1.6 2005-03-13 14:14:20 anatom Exp $
 */
public class BaseEntityBean implements EntityBean {

	/** Log4j instance for actual implementation class */
	public transient Logger log;
	protected EntityContext ctx;

    /**
     * Creates a new BaseEntityBean object.
     */
    public BaseEntityBean() {
        super();
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
     * Sets current entity context
     *
     * @param ctx current entity context
     */
    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Removes (nulls) current entity context
     */
    public void unsetEntityContext() {
        this.ctx = null;
    }

    /**
     * Activates bean, does nothing for base entity.
     */
    public void ejbActivate() {
        // Not implemented.
    }

    /**
     * Passivates bean, does nothing for base entity.
     */
    public void ejbPassivate() {
        // Not implemented.
    }

    /**
     * Loads bean, does nothing for base entity.
     */
    public void ejbLoad() {
        // Not implemented.
    }

    /**
     * Stores bean, does nothing for base entity.
     */
    public void ejbStore() {
        // Not implemented.
    }

    /**
     * Removes bean, does nothing for base entity.
     */
    public void ejbRemove() {
        // Not implemented.
    }

    /**
     * Return the next valid sequence this EJB primary key assuming the primary key
     * is an Integer object (The findByPrimaryKey(Integer pk) should exist in the local home interface.
     * @return the next valid sequence for that EJB primary key
     * @throws EJBException if it cannot find a valid sequence count for that bean
     */
    protected Integer getNextSequence() throws EJBException {
        EJBLocalHome home = ctx.getEJBLocalHome();
        return SimpleSequenceGenerator.getNextCount(home);
    }

    /**
     * Helper method to retrieve the locator
     * @return
     */
    protected ServiceLocator getLocator() {
        return ServiceLocator.getInstance();
    }
}
