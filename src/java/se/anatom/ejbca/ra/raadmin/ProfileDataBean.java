package se.anatom.ejbca.ra.raadmin;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;
import se.anatom.ejbca.ra.raadmin.Profile;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a profile in the ra web interface.
 * Information stored:
 * <pre>
 *  id (Primary key)
 * Profile name
 * Profile data
 * </pre>
 *
 **/

public abstract class ProfileDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(ProfileDataBean.class.getName() );


    protected EntityContext  ctx;
    public abstract Integer getId();
    public abstract void setId(Integer id);
    
    public abstract String getProfileName();
    public abstract void setProfileName(String profilename);
    
    public abstract Profile getProfile();
    public abstract void setProfile(Profile profile);

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a raadmin profile.
     * @param profilename.
     * @param profile is the Profile.
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String profilename, Profile profile) throws CreateException {
        setId(id);
        setProfileName(profilename);
        setProfile(profile);
        log.debug("Created profile "+ profilename );
        return id;
    }

    public void ejbPostCreate(Integer id, String profilename, Profile profile) {
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

