package se.anatom.ejbca.ra.raadmin;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface ProfileGroupDataLocalHome extends javax.ejb.EJBLocalHome {

    public ProfileGroupDataLocal create(String profilegroupname)
        throws CreateException;



    public ProfileGroupDataLocal findByPrimaryKey(String profilegroupname)
        throws FinderException;
    
    public Collection findAllProfileGroupName()
        throws FinderException;    

}

