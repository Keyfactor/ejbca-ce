package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;


/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocal.java,v 1.3 2003-06-26 11:43:25 anatom Exp $
 */
public interface EndEntityProfileDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getProfileName();

    /**
     * DOCUMENT ME!
     *
     * @param profilename DOCUMENT ME!
     */
    public void setProfileName(String profilename);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getProfile();

    /**
     * DOCUMENT ME!
     *
     * @param profile DOCUMENT ME!
     */
    public void setProfile(EndEntityProfile profile);
}
