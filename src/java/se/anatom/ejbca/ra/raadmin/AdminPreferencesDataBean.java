package se.anatom.ejbca.ra.raadmin;

import java.util.HashMap;
import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;
import se.anatom.ejbca.ra.raadmin.AdminPreference;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing admin preference.
 * Information stored:
 * <pre>
 * Id  (BigInteger SerialNumber)
 * AdminPreference
 * </pre>
 *
 * @version $Id: AdminPreferencesDataBean.java,v 1.2 2003-01-12 17:16:33 anatom Exp $
 **/

public abstract class AdminPreferencesDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance(AdminPreferencesDataBean.class.getName() );
    protected EntityContext  ctx;

    public abstract String getId();
    public abstract void setId(String id);
    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
    /** 
     * Method that returns the admin preference and updates it if nessesary.
     */    
    
    public AdminPreference getAdminPreference(){
      AdminPreference returnval = new AdminPreference();
      returnval.loadData((Object) getData());
      return returnval;              
    }
    
    /** 
     * Method that saves the admin preference to database.
     */    
    public void setAdminPreference(AdminPreference adminpreference){
       setData((HashMap) adminpreference.saveData());          
    }


    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of admin preferences.
     * @param id the serialnumber.
     * @param adminpreference is the AdminPreference.
     * @return the primary key
     *
     **/

    public String ejbCreate(String id, AdminPreference adminpreference) throws CreateException {

        setId(id);
        setAdminPreference(adminpreference);

        log.debug("Created admin preference "+id);
        return id;
    }

    public void ejbPostCreate(String id, AdminPreference adminpreference) {
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

