package se.anatom.ejbca.ra.raadmin;
import java.rmi.RemoteException;

import se.anatom.ejbca.webdist.rainterface.Profile;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface ProfileDataLocal extends javax.ejb.EJBLocalObject {

    // public methods
    
    public String getProfileName(); 
    
    public Profile getProfile();

    public void setProfile(Profile profile);
}

