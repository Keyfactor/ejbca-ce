package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Directory
 * Access rule
 * </pre>
 *
 **/

public abstract class AccessRulesDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance( AccessRulesDataBean.class.getName() );
    protected EntityContext  ctx;

    public abstract AccessRulesPK getPK();
    public abstract void setPK(AccessRulesPK pk);
    
    public abstract String getDirectory();
    public abstract void setDirectory(String directory);
    
    public abstract AccessRule getAccessRule();
    public abstract void setAccessRule(AccessRule accessrule);
    
    //
    // Fields required by Container
    //


    public AccessRulesPK ejbCreate(String usergroupname, String directory, AccessRule accessrule) throws CreateException {
        AccessRulesPK pk = new AccessRulesPK(usergroupname, directory);
        
        setPK(pk);
        setDirectory(directory);
        setAccessRule(accessrule);
        log.debug("Created available accessrule "+ directory);
        return pk;
    }

    public void ejbPostCreate(String usergroupname, String directory, AccessRule accessrule) {
        // Do nothing. Required.
    }

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

