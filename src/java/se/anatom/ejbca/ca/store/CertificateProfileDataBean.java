package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
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
 */
public abstract class CertificateProfileDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(CertificateProfileDataBean.class);

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
      CertificateProfile returnval = null;   
      switch(((Integer)(((HashMap) getData()).get(CertificateProfile.TYPE))).intValue()){
          case CertificateProfile.TYPE_ROOTCA :
            returnval = new RootCACertificateProfile();
            break;
          case CertificateProfile.TYPE_CA :
            returnval =  new CACertificateProfile();      
            break;  
          case CertificateProfile.TYPE_ENDENTITY  :
          default :
            returnval = new EndUserCertificateProfile();
      }      

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
}
