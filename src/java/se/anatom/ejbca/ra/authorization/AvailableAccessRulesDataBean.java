package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing available accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Name
 * </pre>
 *
 * @version $Id: AvailableAccessRulesDataBean.java,v 1.4 2003-03-01 14:48:56 anatom Exp $
 */

public abstract class AvailableAccessRulesDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(AvailableAccessRulesDataBean.class);

    public abstract String getName();
    public abstract void setName(String name);
    
    //
    // Fields required by Container
    //


    public String ejbCreate(String name) throws CreateException {

        setName(name);
        log.debug("Created available accessrule "+ name);
        return null;
    }

    public void ejbPostCreate(String name) {
        // Do nothing. Required.
    }
}
