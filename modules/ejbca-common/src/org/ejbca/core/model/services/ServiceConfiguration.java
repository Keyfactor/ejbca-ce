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
package org.ejbca.core.model.services;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;

/**
 * Value class used for persist the worker, interval and action configurations
 * to database
 * 
 *
 * @version $Id$
 */
public class ServiceConfiguration extends UpgradeableDataHashMap implements Serializable, Cloneable {

    private static final long serialVersionUID = -3094484762673017432L;
    private static final Logger log = Logger.getLogger(ServiceConfiguration.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
	private static final float LATEST_VERSION = 6;
	
	private static final String INTERVALCLASSPATH = "INTERVALCLASSPATH";
	private static final String INTERVALPROPERTIES = "INTERVALPROPERTIES";
	private static final String WORKERCLASSPATH = "WORKERCLASSPATH";
	private static final String WORKERPROPERTIES = "WORKERPROPERTIES";
	private static final String ACTIONCLASSPATH = "ACTIONCLASSPATH";
	private static final String ACTIONPROPERTIES = "ACTIONPROPERTIES";
	private static final String DESCRIPTION = "DESCRIPTION";
	private static final String ACTIVE = "ACTIVE";
	private static final String HIDDEN = "HIDDEN";
	private static final String PINTONODES = "PINTONODES";
	private static final String RUNONALLNODES = "RUNONALLNODES";
	
	/**
	 * Constructor used to create a new service configuration.
	 */
	public ServiceConfiguration(){
		setActive(false);
		setHidden(false);
		setDescription("");
		setActionClassPath("");
		setActionProperties(new Properties());
		setWorkerClassPath("");
		setWorkerProperties(new Properties());
		setIntervalClassPath("");
		setIntervalProperties(new Properties());
		setRunOnAllNodes(false);
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
		data.put(ACTIVE, Boolean.valueOf(active));
	}
	
	public boolean isHidden() {
		return ((Boolean) data.get(HIDDEN)).booleanValue();
	}
	
	public void setHidden(boolean b) {
		data.put(HIDDEN, Boolean.valueOf(b));
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

	/**
	 * @return the list of nodes to pin this service to
	 */
	public String[] getPinToNodes() {
		String[] ret = (String[]) data.get(PINTONODES);
		if (ret == null) {
			ret = new String[0];
		}
		return ret;
	}

	/**
	 * @param nodes the list of nodes to pin this service (empty if no nodes)
	 */
	public void setPinToNodes(String[] nodes) {
	    if (log.isDebugEnabled()) {
	        log.debug("setPinToNodes: " + Arrays.toString(nodes));
	    }
		if (nodes == null) {
			nodes = new String[0];
		}
		data.put(PINTONODES, nodes);
	}

	public boolean isRunOnAllNodes() {
	    Boolean ret = (Boolean) data.get(RUNONALLNODES);
	    if (ret != null) {
	        return ((Boolean) data.get(RUNONALLNODES)).booleanValue();
	    }
	    return false;
	}

	public void setRunOnAllNodes(boolean b) {
	    data.put(RUNONALLNODES, Boolean.valueOf(b));
	}

	@Override
	public float getLatestVersion() {
		return LATEST_VERSION;
	}

	@Override
	public void upgrade() {
		if (Float.compare(LATEST_VERSION, getVersion()) > 0) {
            // New version of the class, upgrade
			String msg = intres.getLocalizedMessage("services.upgrade", new Float(getVersion()));
            log.info(msg);

            log.debug(LATEST_VERSION);
			// We changed the names of properties between v1 and v2, so we have to upgrade a few of them
            if (Float.compare(Float.valueOf(2), getVersion()) > 0) { // v2
	            log.debug("Upgrading to version 2");
				Properties prop = getWorkerProperties();
				if (prop != null) {
					String caids = prop.getProperty("worker.emailexpiration.caidstocheck");
					String timebeforexpire = prop.getProperty("worker.emailexpiration.timebeforeexpiring");
					String timeunit = prop.getProperty("worker.emailexpiration.timeunit");
					String sendtousers = prop.getProperty("worker.emailexpiration.sendtoendusers");
					String sendtoadmins = prop.getProperty("worker.emailexpiration.sendtoadmins");
					String usersubject = prop.getProperty("worker.emailexpiration.usersubject");
					String usermessage = prop.getProperty("worker.emailexpiration.usermessage");
					String adminsubject = prop.getProperty("worker.emailexpiration.adminsubject");
					String adminmessage = prop.getProperty("worker.emailexpiration.adminmessage");
					 
					if (caids != null) {
						prop.setProperty(IWorker.PROP_CAIDSTOCHECK, caids);
						prop.remove("worker.emailexpiration.caidstocheck");
					}
					if (timebeforexpire != null) {
						prop.setProperty(IWorker.PROP_TIMEBEFOREEXPIRING, timebeforexpire);
						prop.remove("worker.emailexpiration.timebeforeexpiring");
					}
					if (timeunit != null) {
						prop.setProperty(IWorker.PROP_TIMEUNIT, timeunit);
						prop.remove("worker.emailexpiration.timeunit");
					}
					if (sendtousers != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, sendtousers);
						prop.remove("worker.emailexpiration.sendtoendusers");
					}
					if (sendtoadmins != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, sendtoadmins);
						prop.remove("worker.emailexpiration.sendtoadmins");
					}
					if (usersubject != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT, usersubject);
						prop.remove("worker.emailexpiration.usersubject");
					}
					if (usermessage != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE, usermessage);
						prop.remove("worker.emailexpiration.usermessage");
					}
					if (adminsubject != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT, adminsubject);
						prop.remove("worker.emailexpiration.adminsubject");
					}
					if (adminmessage != null) {
						prop.setProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE, adminmessage);
						prop.remove("worker.emailexpiration.adminmessage");
					}
					setWorkerProperties(prop);
				}
				
	            if (Float.compare(Float.valueOf(3), getVersion()) > 0) { // v3
		            log.debug("Upgrading to version 3");
		            // The hidden field was added
		            setHidden(false);
				}
	            
	            if (Float.compare(Float.valueOf(4), getVersion()) > 0) { // v4
		            log.debug("Upgrading to version 4");
		            // The NEXTRUNTIMESTAMP and OLDRUNTIMESTAMP disappeared in version 4 but we don't do anything here. 
		            // This is handled in ServiceData.getServiceConfiguration when we check if the service is upgraded
				}
			}

            if (Float.compare(Float.valueOf(5), getVersion()) > 0) { // v5
	            log.debug("Upgrading to version 5");
	            // The PINTONODES field was added
            	setPinToNodes(null);
            }
            if (Float.compare(Float.valueOf(6), getVersion()) > 0) { // v6
                log.debug("Upgrading to version 6");
                // The RUNONALLNODES field was added
                setRunOnAllNodes(false);
            }

			data.put(VERSION, new Float(LATEST_VERSION));
		}		
	}
	
	@Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Object clone() throws CloneNotSupportedException {
        ServiceConfiguration clone = new ServiceConfiguration();
        HashMap clonedata = (HashMap) clone.saveData();

        Iterator<Object> i = (data.keySet()).iterator();
        while(i.hasNext()){
          Object key = i.next();
          clonedata.put(key, data.get(key));
        }

        clone.loadData(clonedata);
        return clone;
      }


	

}
