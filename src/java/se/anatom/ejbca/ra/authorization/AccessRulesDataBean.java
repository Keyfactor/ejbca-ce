package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing
 * accessrules in EJBCA authorization module Information stored:
 * <pre>
 * Resource
 * Access rule
 * </pre>
 *
 * @version $Id: AccessRulesDataBean.java,v 1.8 2003-07-24 08:43:31 anatom Exp $
 */
public abstract class AccessRulesDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(AccessRulesDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getPK();

    /**
     * DOCUMENT ME!
     *
     * @param pK DOCUMENT ME!
     */
    public abstract void setPK(int pK);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getResource();

    /**
     * DOCUMENT ME!
     *
     * @param resource DOCUMENT ME!
     */
    public abstract void setResource(String resource);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract AccessRule getAccessRule();

    /**
     * DOCUMENT ME!
     *
     * @param accessrule DOCUMENT ME!
     */
    public abstract void setAccessRule(AccessRule accessrule);

    //
    // Fields required by Container
    //
    public AccessRulesPK ejbCreate(String usergroupname, String resource, AccessRule accessrule)
        throws CreateException {
        AccessRulesPK pk = new AccessRulesPK(usergroupname, resource);

        setPK(pk.hashCode());
        setResource(resource);
        setAccessRule(accessrule);
        log.debug("Created available accessrule " + resource);

        return pk;
    }

    /**
     * DOCUMENT ME!
     *
     * @param usergroupname DOCUMENT ME!
     * @param resource DOCUMENT ME!
     * @param accessrule DOCUMENT ME!
     */
    public void ejbPostCreate(String usergroupname, String resource, AccessRule accessrule) {
        // Do nothing. Required.
    }
}
