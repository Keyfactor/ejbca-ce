package se.anatom.ejbca.ra.raadmin;

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing
 * admin preference. Information stored:
 * <pre>
 * Id  (BigInteger SerialNumber)
 * AdminPreference
 * </pre>
 *
 * @version $Id: AdminPreferencesDataBean.java,v 1.7 2003-07-24 08:43:32 anatom Exp $
 */
public abstract class AdminPreferencesDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(AdminPreferencesDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(String id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the admin preference and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference() {
        AdminPreference returnval = new AdminPreference();
        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the admin preference to database.
     *
     * @param adminpreference DOCUMENT ME!
     */
    public void setAdminPreference(AdminPreference adminpreference) {
        setData((HashMap) adminpreference.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of admin preferences.
     *
     * @param id the serialnumber.
     * @param adminpreference is the AdminPreference.
     *
     * @return the primary key
     */
    public String ejbCreate(String id, AdminPreference adminpreference)
        throws CreateException {
        setId(id);
        setAdminPreference(adminpreference);

        log.debug("Created admin preference " + id);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     */
    public void ejbPostCreate(String id, AdminPreference adminpreference) {
        // Do nothing. Required.
    }
}
