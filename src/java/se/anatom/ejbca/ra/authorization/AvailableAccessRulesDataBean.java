package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.Logger;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing available accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Name
 * </pre>
 *
 * @version $Id: AvailableAccessRulesDataBean.java,v 1.2 2003-02-12 11:23:18 scop Exp $
 */

public abstract class AvailableAccessRulesDataBean implements javax.ejb.EntityBean {

    private static Logger log = Logger.getLogger(AvailableAccessRulesDataBean.class);
    protected EntityContext  ctx;

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
