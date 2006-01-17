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

package org.ejbca.core.ejb.authorization;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.authorization.AccessRule;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Access rule
 * rule (accept of decline)
 * isrecursive
 * </pre>
 *
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents an access rule"
 *   display-name="AccessRuleDataEB"
 *   name="AccessRulesData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="AccessRulesDataBean"
 *
 * @ejb.pk
 *   generate="false"
 *   class="org.ejbca.core.ejb.authorization.AccessRulesPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "AccessRulesData"
 * 
 * @ejb.transaction type="Supports"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.authorization.AccessRulesDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.authorization.AccessRulesDataLocal"
 *
 * @version $Id: AccessRulesDataBean.java,v 1.1 2006-01-17 20:30:04 anatom Exp $
 */
public abstract class AccessRulesDataBean extends BaseEntityBean
{
    /**
     * @ejb.persistence column-name="pK"
     * @ejb.pk-field
     */
    public abstract int getPrimKey();
    public abstract void setPrimKey(int primKey);

	/**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
	 */
    public abstract String getAccessRule();
    public abstract void setAccessRule(String accessrule);

	/**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
	 */
    public abstract int getRule();
    public abstract void setRule(int rule);

	/**
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
	 */
    public abstract boolean getIsRecursive();
    public abstract void setIsRecursive(boolean isrecursive);

	/**
     * Return the access rule transfer object
     * @return the access rule transfer object
     * @ejb.interface-method
	 */
    public  AccessRule getAccessRuleObject() {
        return new AccessRule(getAccessRule(), getRule(), getIsRecursive());
    }

	/**
	 *
     * @ejb.create-method
	 */
    public AccessRulesPK ejbCreate(String admingroupname, int caid, String accessrule, int rule, boolean isrecursive) throws CreateException {
        AccessRulesPK ret = new AccessRulesPK(admingroupname, caid, new AccessRule(accessrule, rule, isrecursive));
        setPrimKey(ret.primKey);
        setAccessRule(accessrule);
        setRule(rule);
        setIsRecursive(isrecursive);
        debug("Created accessrule : "+ accessrule);
        return ret;
    }

    public void ejbPostCreate(String admingroupname, int caid, String accessrule, int rule, boolean isrecursive) {
        // Do nothing. Required method.
    }

}
