package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see AccessRulesDataBean
 */
public interface AccessRulesDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param usergroupname DOCUMENT ME!
     * @param resource DOCUMENT ME!
     * @param accessrule DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public AccessRulesDataLocal create(String usergroupname, String resource, AccessRule accessrule)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public AccessRulesDataLocal findByPrimaryKey(AccessRulesPK pk)
        throws FinderException;
}
