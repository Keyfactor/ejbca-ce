package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Resource
 * Access rule
 * </pre>
 *
 * @version $Id: AccessRulesDataBean.java,v 1.6 2003-03-01 14:48:56 anatom Exp $
 */
public abstract class AccessRulesDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AccessRulesDataBean.class);

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
}
