package se.anatom.ejbca.ra.raadmin;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;
import se.anatom.ejbca.ra.raadmin.UserPreference;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing ra admin  user preference.
 * Information stored:
 * <pre>
 * Id  (BigInteger SerialNumber)
 * UserPreference
 * </pre>
 *
 * @version $Id: UserPreferencesDataBean.java,v 1.5 2002-07-22 22:59:11 herrvendil Exp $
 **/

public abstract class UserPreferencesDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance(UserPreferencesDataBean.class.getName() );
    protected EntityContext  ctx;

    public abstract String getId();
    public abstract void setId(String id);
    public abstract UserPreference getUserPreference();
    public abstract void setUserPreference(UserPreference userpreference);


    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of raadmin userpreferences.
     * @param id the serialnumber.
     * @param userpreference is the UserPreference.
     * @return UserPreferenceDataPK primary key
     *
     **/

    public String ejbCreate(String id, UserPreference userpreference) throws CreateException {

        setId(id);
        setUserPreference(userpreference);

        log.debug("Created user preference "+id);
        return id;
    }

    public void ejbPostCreate(String id, UserPreference userpreference) {
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

