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


/**
 * Base class for entity beans implementing required methods and helpers.
 *
 * @version $Id: BaseEntityBean.java,v 1.5 2004-11-08 21:10:36 sbailliez Exp $
 */
public class BaseEntityBean implements EntityBean {

    protected transient EntityContext ctx;

    /**
     * Creates a new BaseEntityBean object.
     */
    public BaseEntityBean() {
        super();
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
