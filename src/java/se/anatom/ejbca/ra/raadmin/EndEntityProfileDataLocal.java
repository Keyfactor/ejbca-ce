package se.anatom.ejbca.ra.raadmin;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocal.java,v 1.1 2002-10-24 20:09:34 herrvendil Exp $
 **/

public interface EndEntityProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getProfileName();

    public void setProfileName(String profilename);

    public EndEntityProfile getProfile();

    public void setProfile(EndEntityProfile profile);
}

