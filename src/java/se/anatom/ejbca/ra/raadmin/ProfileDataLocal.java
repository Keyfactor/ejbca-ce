package se.anatom.ejbca.ra.raadmin;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.raadmin.Profile;

/**
 * For docs, see UserPreferencesDataBean
 **/

public interface ProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods
    
    public Integer getId();
    
    public String getProfileName();
    
    public void setProfileName(String profilename);
    
    public Profile getProfile();

    public void setProfile(Profile profile);
}

