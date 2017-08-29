/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.publisher;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.model.InternalEjbcaResources;


/**
 * The model holds additional data needed to be able to republish a certificate or CRL after publishing have failed.
 * This data will be stored in PublicFailQueueData. 
 *
 * @version $Id$
 */
public class PublisherQueueVolatileInformation extends UpgradeableDataHashMap implements Serializable, Cloneable {

	private static final long serialVersionUID = 3423544212169635898L;
    private static final Logger log = Logger.getLogger(PublisherQueueVolatileInformation.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    
    public static final float LATEST_VERSION = 1;    

    // private fields.
    
    // Because the UserData information may be volatile, usernames can be re-used for several different certificates
    // we will store the actual user data used when we tried to publish so we can be sure to use the same.
    /** Username, links to UserData */
    private static final String USERNAME = "username";
    /** Password if sent to publisher. */
    private static final String PASSWORD = "password";
    /** DN from UserData */
    private static final String USERDN = "userdn";
    /** ExtendedInformation from UserData */
    private static final String EXTENDEDINFORMATION = "extendedinformation";
        
    
    // Public constants

    // Public methods.
    /** Creates a new instance of EndEntity Profile */
    public PublisherQueueVolatileInformation() {
    }

    public String getUsername(){ 
    	String ret = (String) data.get(USERNAME);
    	if (ret == null) {
    		ret = "";
    	}
    	return ret;
    }
    public void setUsername(String username) {
    	if (username != null) {
    		data.put(USERNAME,username);
    	}
    }
    
    public String getPassword(){ 
    	String ret = (String) data.get(PASSWORD);
    	if (ret == null) {
    		ret = "";
    	}
    	return ret;
    }
    public void setPassword(String password) {
    	if (password != null) {
    		data.put(PASSWORD,password);
    	}
    }
    
    public String getUserDN(){ 
    	String ret = (String) data.get(USERDN);
    	if (ret == null) {
    		ret = "";
    	}
    	return ret;
    }
	public void setUserDN(String userDN) {
    	if (userDN != null) {
    		data.put(USERDN,userDN);
    	}
	}

	/**
	 *  
	 * @return ExtendedInformation or null if it does not exist
	 */
    public ExtendedInformation getExtendedInformation() {
    	String str = (String)data.get(EXTENDEDINFORMATION);
    	ExtendedInformation ret = null;
    	if (str != null) {
    		ret = EndEntityInformation.getExtendedInformationFromStringData(str);
    	}
    	return ret;
    }
    
    public void setExtendedInformation(ExtendedInformation ei) {
    	final String eidata = EndEntityInformation.extendedInformationToStringData(ei);
    	if (eidata != null) {
    		data.put(EXTENDEDINFORMATION, eidata);
    	}
    }
    
    @SuppressWarnings("unchecked")
    public Object clone() throws CloneNotSupportedException {
      PublisherQueueVolatileInformation clone = new PublisherQueueVolatileInformation();
      @SuppressWarnings("rawtypes")
    HashMap clonedata = (HashMap) clone.saveData();

      Iterator<Object> i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();
        clonedata.put(key, data.get(key));
      }

      clone.loadData(clonedata);
      return clone;
    }

    /** Function required by XMLEncoder to do a proper serialization. */
    public void setData( Object hmData ) { loadData(hmData); }
    /** Function required by XMLEncoder to do a proper serialization. */
    public Object getData() {return saveData();}
    
    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
    		// New version of the class, upgrade
			String msg = intres.getLocalizedMessage("publisher.queuedataupgrade", new Float(getVersion()));
            log.info(msg);
    		
    		data.put(VERSION, new Float(LATEST_VERSION));
    	}
    }
    
}
