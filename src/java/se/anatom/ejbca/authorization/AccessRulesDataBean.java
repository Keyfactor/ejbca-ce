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
 *   generate="false"
 *   display-name="This enterprise bean entity represents an access rule"
 *   name="AccessRulesData"
 *   local-jndi-name="AccessRulesData"
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
 */
public abstract class AccessRulesDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AccessRulesDataBean.class);

	/**
	 * @ejb.persistence
	 */
    public abstract int getPK();
	
	/**
	 * @ejb.persistence
	 */
	public abstract void setPK(int pK);

	/**
     * @ejb.pk-field
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
	 */
    public abstract String getAccessRule();

	/**
	 * @ejb.persistence
	 */
    public abstract void setAccessRule(String accessrule);

	/**
	 * @ejb.persistence
	 */
    public abstract int getRule();

	/**
	 * @ejb.persistence
	 */
    public abstract void setRule(int rule);

	/**
	 * @ejb.persistence
	 */
    public abstract boolean getIsRecursive();

	/**
	 * @ejb.persistence
	 */
    public abstract void setIsRecursive(boolean isrecursive);    
    
	/**
	 *
     * @ejb.create-method
	 */
    public AccessRulesPK ejbCreate(String admingroupname, int caid, AccessRule accessrule) throws CreateException {
        AccessRulesPK pk = new AccessRulesPK(admingroupname, caid, accessrule);

        setPK(pk.hashCode());
        setAccessRule(accessrule.getAccessRule());
        setRule(accessrule.getRule());
        setIsRecursive(accessrule.isRecursive());
        log.debug("Created accessrule : "+ accessrule.getAccessRule());
        return pk;
    }

    public void ejbPostCreate(String admingroupname, int caid, AccessRule accessrule) {
        // Do nothing. Required method.
    }
    
	/**
     * @ejb.interface-method view-type="local"
     */
    public  AccessRule getAccessRuleObject(){
      return new AccessRule(getAccessRule(), getRule(), getIsRecursive()); 
    }
    
	/**    
     * @ejb.interface-method view-type="local"
     */
    public void setAccessRuleObject(AccessRule accessrule){
      setAccessRule(accessrule.getAccessRule());
      setRule(accessrule.getRule());  
      setIsRecursive(accessrule.isRecursive());  
    }
}
