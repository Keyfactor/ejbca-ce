package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AccessRulesDataBean
 **/
public interface AccessRulesDataLocalHome extends javax.ejb.EJBLocalHome {

    public AccessRulesDataLocal create(String usergroupname, String resource, AccessRule accessrule)
        throws CreateException;
    public AccessRulesDataLocal findByPrimaryKey(AccessRulesPK pk)
        throws FinderException;
}
