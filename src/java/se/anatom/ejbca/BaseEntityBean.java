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

import javax.ejb.EntityBean;
import javax.ejb.EntityContext;


/**
 * Base class for entity beans implementing required methods and helpers.
 *
 * @version $Id: BaseEntityBean.java,v 1.4 2004-04-16 07:39:01 anatom Exp $
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
}
