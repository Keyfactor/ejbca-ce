package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

import se.anatom.ejbca.ra.raadmin.Profile;

/**
 * For docs, see UserPreferencesDataBean
 **/

public interface ProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public ProfileDataLocal create(Integer id, String profilename, Profile profile)
        throws CreateException;

    public ProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;
    
    public ProfileDataLocal findByProfileName(String name)
        throws FinderException;
        
    public Collection findAll()
        throws FinderException;  
}

