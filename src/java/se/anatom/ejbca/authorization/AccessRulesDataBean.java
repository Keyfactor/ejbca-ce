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

package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Access rule
 * rule (accept of decline)
 * isrecursive
 *
 * </pre>
 *
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents an access rule"
 *   display-name="AccessRuleDataEB"
 *   name="AccessRulesData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="AccessRulesDataBean"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk
 *   class="se.anatom.ejbca.authorization.AccessRulesPK"
 *   extends="java.lang.Object"
 *   implements="java.io.Serializable"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.authorization.AccessRulesDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.authorization.AccessRulesDataLocal"
 *
 * @todo Write migration script
 */
public abstract class AccessRulesDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AccessRulesDataBean.class);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract String getAdminGroupName();

    /**
     * @ejb.persistence
     */
    public abstract void setAdminGroupName(String admingroupname);

    /**
     * @ejb.persistence
     * @ejb.pk-field
     * @ejb.interface-method view-type="local"
     */
    public abstract int getCaId();

    /**
     * @ejb.persistence
     */
    public abstract void setCaId(int caid);

	/**
     * @ejb.pk-field
	 * @ejb.persistence
     * @ejb.interface-method
	 */
    public  abstract AccessRule getAccessRuleObject();

	/**
	 * @ejb.persistence
	 */
    public abstract void setAccessRuleObject(AccessRule accessrule);

	/**
	 *
     * @ejb.create-method
	 */
    public AccessRulesPK ejbCreate(String admingroupname, int caid, AccessRule accessrule) throws CreateException {
        setAdminGroupName(admingroupname);
        setCaId(caid);
        setAccessRuleObject(accessrule);
        log.debug("Created accessrule : "+ accessrule.getAccessRule());
        return null;
    }

    public void ejbPostCreate(String admingroupname, int caid, AccessRule accessrule) {
        // Do nothing. Required method.
    }

}
