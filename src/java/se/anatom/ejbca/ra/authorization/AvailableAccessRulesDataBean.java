package se.anatom.ejbca.ra.authorization;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

import javax.ejb.CreateException;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing
 * available accessrules in EJBCA authorization module Information stored:
 * <pre>
 * Name
 * </pre>
 *
 * @version $Id: AvailableAccessRulesDataBean.java,v 1.5 2003-06-26 11:43:24 anatom Exp $
 */
public abstract class AvailableAccessRulesDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(AvailableAccessRulesDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getName();

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     */
    public abstract void setName(String name);

    //
    // Fields required by Container
    //
    public String ejbCreate(String name) throws CreateException {
        setName(name);
        log.debug("Created available accessrule " + name);

        return null;
    }

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     */
    public void ejbPostCreate(String name) {
        // Do nothing. Required.
    }
}
