package se.anatom.ejbca.hardtoken;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.EnhancedEIDProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.SwedishEIDProfile;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token issuer in the ra.
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  name (of the hard token profile)
 *  updatecount, help counter incremented each profile update used to check if a profile proxy class should update its data 
 *  hardtokenprofile (Data saved concerning the hard token profile)
 * </pre>
 *
 * @version $Id: HardTokenProfileDataBean.java,v 1.1 2003-12-05 14:50:27 herrvendil Exp $
 **/

public abstract class HardTokenProfileDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(HardTokenProfileDataBean.class);
    
    private HardTokenProfile profile = null;

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getName();
    public abstract void setName(String name);
    
	public abstract int getUpdateCounter();
	public abstract void setUpdateCounter(int updatecounter);
      

    public abstract String getData();
    public abstract void setData(String data);
    
    
   
    /** 
     * Method that returns the hard token profile data and updates it if nessesary.
     */    
    
    public HardTokenProfile getHardTokenProfile(){		
		        
  	  if(profile == null){
	    java.beans.XMLDecoder decoder;
		try {
		  decoder =
			new java.beans.XMLDecoder(
					new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
		} catch (UnsupportedEncodingException e) {
		  throw new EJBException(e);
		}
		HashMap data = (HashMap) decoder.readObject();
		decoder.close();
             
		switch (((Integer) (data.get(HardTokenProfile.TYPE))).intValue()) {
		  case SwedishEIDProfile.TYPE_SWEDISHEID :
		    profile = new SwedishEIDProfile();
		    break;
		  case EnhancedEIDProfile.TYPE_ENHANCEDEID:
		    profile =  new EnhancedEIDProfile();      
		    break;  		  
		}
		  
		profile.loadData(data);		  
	  }	
		                 
		return profile;                          
    }
    
    /** 
     * Method that saves the hard token profile data to database.
     */    
    public void setHardTokenProfile(HardTokenProfile hardtokenprofile){
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       
		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(hardtokenprofile.saveData());
		encoder.close();
		       
		try {
			System.out.println("Profiledata: \n" + baos.toString("UTF8"));
			setData(baos.toString("UTF8"));
		} catch (UnsupportedEncodingException e) {
          throw new EJBException(e);
		}
       
		this.profile = hardtokenprofile;    	       
        setUpdateCounter(getUpdateCounter() +1);          
    }
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String name, HardTokenProfile profile) throws CreateException {
        setId(id);
        setName(name);
        this.setUpdateCounter(0); 
        if(profile != null)           
          setHardTokenProfile(profile);
        
        log.debug("Created Hard Token Profile "+ name );
        return id;
    }

    public void ejbPostCreate(Integer id, String name, HardTokenProfile profile) {
        // Do nothing. Required.
    }
}
