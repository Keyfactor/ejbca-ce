/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

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
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a hard token profile with accompanying data"
 *   display-name="HardTokenProfileDataEB"
 *   name="HardTokenProfileData"
 *   jndi-name="HardTokenProfileData"
 *   local-jndi-name="HardTokenProfileDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenProfileDataBean"
 *   primkey-field="id"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenProfileDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenProfileDataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="se.anatom.ejbca.hardtoken.HardTokenProfileDataLocal findByName(java.lang.String name)"
 *   query="SELECT DISTINCT OBJECT(a) from HardTokenProfileDataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT DISTINCT OBJECT(a) from HardTokenProfileDataBean a"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *
 */
public abstract class HardTokenProfileDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(HardTokenProfileDataBean.class);

    private HardTokenProfile profile = null;

	/**
     * @ejb.pk-field
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

	/**
	 * @ejb.persistence
	 */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getName();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
	public abstract int getUpdateCounter();

    /**
     * @ejb.persistence
     */
	public abstract void setUpdateCounter(int updatecounter);

    /**
     * @ejb.persistence jdbc-type="BLOB" sql-type="VARBINARY(1100000)"
     */
    public abstract String getData();

    /**
     * @ejb.persistence
     */
    public abstract void setData(String data);



    /**
     * Method that returns the hard token profile data and updates it if nessesary.
     * @ejb.interface-method view-type="local"
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
     * @ejb.interface-method view-type="local"
     */
    public void setHardTokenProfile(HardTokenProfile hardtokenprofile){
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(hardtokenprofile.saveData());
		encoder.close();

		try {
            if (log.isDebugEnabled()) {
                log.debug("Profiledata: \n" + baos.toString("UTF8"));
            }
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
     * Passivates bean, resets profile data.
     */
    public void ejbPassivate() {
        this.profile = null;
    }


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     * @ejb.create-method view-type="local"
	 */
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
