package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;
import se.anatom.ejbca.ca.store.certificateprofiles.*;
import java.util.HashMap;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a certificate type in the ra web interface.
 * Information stored:
 * <pre>
 *  id (Primary key)
 * CertificateProfile name
 * CertificateProfile data
 * </pre>
 *
 * @version $Id: ProfileDataBean.java,v 1.4 2002/07/22 10:38:48 anatom Exp $
 **/

public abstract class CertificateProfileDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(CertificateProfileDataBean.class.getName() );


    protected EntityContext  ctx;
    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getCertificateProfileName();
    public abstract void setCertificateProfileName(String certificateprofilename);

    public abstract HashMap getData();
    public abstract void setData(HashMap data);    
    
    
    /** 
     * Method that returns the certificate profiles and updates it if nessesary.
     */    
    
    public CertificateProfile getCertificateProfile(){
      CertificateProfile returnval = new CertificateProfile();
      returnval.loadData((Object) getData());
      return returnval;              
    }
    
    /** 
     * Method that saves the certificate profile to database.
     */    
    public void setCertificateProfile(CertificateProfile profile){
       setData((HashMap) profile.saveData());          
    }   
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a raadmin profile.
     * @param certificateprofilename.
     * @param certificateprofile is the CertificateProfile.
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String certificateprofilename, CertificateProfile certificateprofile) throws CreateException {
        setId(id);
        setCertificateProfileName(certificateprofilename);
        setCertificateProfile(certificateprofile);
        log.debug("Created certificateprofile "+ certificateprofilename );
        return id;
    }

    public void ejbPostCreate(Integer id, String certificateprofilename, CertificateProfile certificateprofile) {
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

