package se.anatom.ejbca.ra.raadmin;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.HashMap;
import org.apache.log4j.*;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

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
 * @version $Id: EndEntityProfileDataBean.java,v 1.1 2002-10-24 20:09:32 herrvendil Exp $
 **/

public abstract class EndEntityProfileDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(EndEntityProfileDataBean.class.getName() );


    protected EntityContext  ctx;
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

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

