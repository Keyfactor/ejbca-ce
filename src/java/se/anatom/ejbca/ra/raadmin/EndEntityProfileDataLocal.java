package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocal.java,v 1.2 2003-01-12 17:16:33 anatom Exp $
 **/

public interface EndEntityProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getProfileName();

    public void setProfileName(String profilename);

    public EndEntityProfile getProfile();

    public void setProfile(EndEntityProfile profile);
}

