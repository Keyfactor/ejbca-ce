package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

import se.anatom.ejbca.webdist.rainterface.Profile;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface ProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public ProfileDataLocal create(String profilename, Profile profile)

        throws CreateException;



    public ProfileDataLocal findByPrimaryKey(String pk)

        throws FinderException;
    
}

