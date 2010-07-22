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

package org.ejbca.core.ejb.hardtoken;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.util.Base64PutHashMap;


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
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.persistence table-name = "HardTokenProfileData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocal findByName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from HardTokenProfileDataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT OBJECT(a) from HardTokenProfileDataBean a"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *
 */
public abstract class HardTokenProfileDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(HardTokenProfileDataBean.class);

	/**
     * @ejb.pk-field
	 * @ejb.persistence column-name="id"
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

	/**
	 */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence column-name="name"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getName();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence column-name="updateCounter"
     * @ejb.interface-method view-type="local"
     */
	public abstract int getUpdateCounter();

    /**
     */
	public abstract void setUpdateCounter(int updatecounter);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="data"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getData();

    /**
     */
    public abstract void setData(String data);

    /**
     * Method that saves the hard token profile data to database.
     * @ejb.interface-method view-type="local"
     */
    public void setHardTokenProfile(HardTokenProfile hardtokenprofile){
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)hardtokenprofile.saveData());
        
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(a);
		encoder.close();

		try {
            if (log.isDebugEnabled()) {
            	if (baos.size() < 10000) {
                    log.debug("Profiledata: \n" + baos.toString("UTF8"));            		
            	} else {
            		log.debug("Profiledata larger than 10000 bytes, not displayed.");
            	}
            }
			setData(baos.toString("UTF8"));
		} catch (UnsupportedEncodingException e) {
          throw new EJBException(e);
		}

        setUpdateCounter(getUpdateCounter() +1);
    }


    //
    // Fields required by Container
    //


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
        if(profile != null) {
          setHardTokenProfile(profile);
        }
        log.debug("Created Hard Token Profile "+ name );
        return id;
    }

    public void ejbPostCreate(Integer id, String name, HardTokenProfile profile) {
        // Do nothing. Required.
    }
}
