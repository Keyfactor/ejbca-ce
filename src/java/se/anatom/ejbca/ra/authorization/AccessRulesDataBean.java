package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Resource
 * Access rule
 * </pre>
 *
 **/

public abstract class AccessRulesDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance( AccessRulesDataBean.class.getName() );
    protected EntityContext  ctx;

    public abstract int getPK();
    public abstract void setPK(int pK);

    public abstract String getResource();
    public abstract void setResource(String resource);

    public abstract AccessRule getAccessRule();
    public abstract void setAccessRule(AccessRule accessrule);

    //
    // Fields required by Container
    //


    public AccessRulesPK ejbCreate(String usergroupname, String resource, AccessRule accessrule) throws CreateException {
        AccessRulesPK pk = new AccessRulesPK(usergroupname, resource);

        setPK(pk.hashCode());
        setResource(resource);
        setAccessRule(accessrule);
        log.debug("Created available accessrule "+ resource);
        return pk;
    }

    public void ejbPostCreate(String usergroupname, String resource, AccessRule accessrule) {
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

