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
 * @version $Id: AccessRulesDataBean.java,v 1.2 2004-04-16 07:38:57 anatom Exp $
 */
public abstract class AccessRulesDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AccessRulesDataBean.class);

    public abstract int getPK();
    public abstract void setPK(int pK);

    public abstract String getAccessRule();
    public abstract void setAccessRule(String accessrule);

    public abstract int getRule();
    public abstract void setRule(int rule);

    public abstract boolean getIsRecursive();
    public abstract void setIsRecursive(boolean isrecursive);    
    

    //
    // Fields required by Container
    //
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
    

    public  AccessRule getAccessRuleObject(){
      return new AccessRule(getAccessRule(), getRule(), getIsRecursive()); 
    }
    
    public void setAccessRuleObject(AccessRule accessrule){
      setAccessRule(accessrule.getAccessRule());
      setRule(accessrule.getRule());  
      setIsRecursive(accessrule.isRecursive());  
    }
}
