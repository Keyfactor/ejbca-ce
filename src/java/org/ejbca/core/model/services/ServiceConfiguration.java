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
package org.ejbca.core.model.services;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;

/**
 * Value class used for persist the worker, interval and action configurations
 * to database
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: ServiceConfiguration.java,v 1.2 2006-10-01 17:46:25 herrvendil Exp $
 */
public class ServiceConfiguration extends UpgradeableDataHashMap implements Serializable, Cloneable {

	private static final float LATEST_VERSION = 1;
	
	private static final String INTERVALCLASSPATH = "INTERVALCLASSPATH";
	private static final String INTERVALPROPERTIES = "INTERVALPROPERTIES";
	private static final String WORKERCLASSPATH = "WORKERCLASSPATH";
	private static final String WORKERPROPERTIES = "WORKERPROPERTIES";
	private static final String ACTIONCLASSPATH = "ACTIONCLASSPATH";
	private static final String ACTIONPROPERTIES = "ACTIONPROPERTIES";
	private static final String DESCRIPTION = "DESCRIPTION";
	private static final String ACTIVE = "ACTIVE";
	
	/**
	 * Constructor used to create a new service configuration.
	 */
	public ServiceConfiguration(){
		setActive(false);
		setDescription("");
		setActionClassPath("");
		setActionProperties(new Properties());
		setWorkerClassPath("");
		setWorkerProperties(new Properties());
		setIntervalClassPath("");
		setIntervalProperties(new Properties());
	}
	
	
	/**
	 * @return the Action Class Path
	 */
	public String getActionClassPath() {
		return (String) data.get(ACTIONCLASSPATH);
	}

	/**
	 * @param actionClassPath the actionClassPath to set
	 */
	public void setActionClassPath(String actionClassPath) {
		data.put(ACTIONCLASSPATH,actionClassPath);
	}

	/**
	 * @return the actionProperties
	 */
	public Properties getActionProperties() {
		return (Properties) data.get(ACTIONPROPERTIES);
	}

	/**
	 * @param actionProperties the actionProperties to set
	 */
	public void setActionProperties(Properties actionProperties) {
		data.put(ACTIONPROPERTIES, actionProperties);
	}

	/**
	 * @return the active
	 */
	public boolean isActive() {
		return ((Boolean) data.get(ACTIVE)).booleanValue();
	}

	/**
	 * @param active the active to set
	 */
	public void setActive(boolean active) {
		data.put(ACTIVE, new Boolean(active));
	}

	/**
	 * @return the description
	 */
	public String getDescription() {
		return (String) data.get(DESCRIPTION);
	}

	/**
	 * @param description the description to set
	 */
	public void setDescription(String description) {
		data.put(DESCRIPTION, description);
	}

	/**
	 * @return the intervalClassPath
	 */
	public String getIntervalClassPath() {
		return (String) data.get(INTERVALCLASSPATH);
	}

	/**
	 * @param intervalClassPath the intervalClassPath to set
	 */
	public void setIntervalClassPath(String intervalClassPath) {
		data.put(INTERVALCLASSPATH,intervalClassPath);
	}

	/**
	 * @return the intervalProperties
	 */
	public Properties getIntervalProperties() {
		return (Properties) data.get(INTERVALPROPERTIES);
	}

	/**
	 * @param intervalProperties the intervalProperties to set
	 */
	public void setIntervalProperties(Properties intervalProperties) {
		data.put(INTERVALPROPERTIES, intervalProperties);
	}

	/**
	 * @return the workerClassPath
	 */
	public String getWorkerClassPath() {
		return (String) data.get(WORKERCLASSPATH);
	}

	/**
	 * @param workerClassPath the workerClassPath to set
	 */
	public void setWorkerClassPath(String workerClassPath) {
		data.put(WORKERCLASSPATH,workerClassPath);
	}

	/**
	 * @return the workerProperties
	 */
	public Properties getWorkerProperties() {
		return (Properties) data.get(WORKERPROPERTIES);
	}

	/**
	 * @param workerProperties the workerProperties to set
	 */
	public void setWorkerProperties(Properties workerProperties) {
		data.put(WORKERPROPERTIES, workerProperties);
	}

	public float getLatestVersion() {
		return LATEST_VERSION;
	}

	public void upgrade() {
       if(getVersion() != LATEST_VERSION){
    	   
       }		
	}
	
    public Object clone() throws CloneNotSupportedException {
        ServiceConfiguration clone = new ServiceConfiguration();
        HashMap clonedata = (HashMap) clone.saveData();

        Iterator i = (data.keySet()).iterator();
        while(i.hasNext()){
          Object key = i.next();
          clonedata.put(key, data.get(key));
        }

        clone.loadData(clonedata);
        return clone;
      }
	
	

}
