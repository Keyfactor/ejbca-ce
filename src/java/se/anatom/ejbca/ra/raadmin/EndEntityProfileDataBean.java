package se.anatom.ejbca.ra.raadmin;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.HashMap;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a end entity profile in the ra.
 * Information stored:
 * <pre>
 *  id (Primary key)
 * Profile name
 * Profile data
 * </pre>
 *
 * @version $Id: EndEntityProfileDataBean.java,v 1.3 2003-02-28 09:32:17 koen_serry Exp $
 */
public abstract class EndEntityProfileDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(EndEntityProfileDataBean.class);

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getProfileName();
    public abstract void setProfileName(String profilename);

    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
    /** 
     * Method that returns the end entity profiles and updates it if nessesary.
     */    
    
    public EndEntityProfile getProfile(){
      EndEntityProfile returnval = new EndEntityProfile();
      returnval.loadData((Object) getData());
      return returnval;              
    }
    
    /** 
     * Method that saves the admin preference to database.
     */    
    public void setProfile(EndEntityProfile profile){
       setData((HashMap) profile.saveData());          
    }

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a end entity profile.
     * @param profilename.
     * @param profile is the EndEntityProfile.
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String profilename, EndEntityProfile profile) throws CreateException {
        setId(id);
        setProfileName(profilename);
        setProfile(profile);
        log.debug("Created profile "+ profilename );
        return id;
    }

    public void ejbPostCreate(Integer id, String profilename, EndEntityProfile profile) {
        // Do nothing. Required.
    }
}
