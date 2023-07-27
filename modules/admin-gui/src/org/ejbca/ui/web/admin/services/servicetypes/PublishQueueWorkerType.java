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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;

/**
 * Class managing the view of the Renew CA Worker
 * 
 *
 * @version $Id$
 */
public class PublishQueueWorkerType extends BaseEmailNotifyingWorkerType {
	
	private static final long serialVersionUID = -5012349995138960737L;

    public static final String NAME = "PUBLISHQUEUEWORKER";

    private static final String PUBLISHQUEUEPROCESSWORKER_SUB_PAGE = "publishqueueprocessworker.xhtml";
    
    private static final long MAX_JOBS_PER_QUEUE_WORKER = 200000L;
    
	private List<String> selectedPublisherIdsToCheck = new ArrayList<>();
	
	private long maxNumberOfEntriesToPublish = PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS;
	

	public PublishQueueWorkerType(){
		super(NAME, PUBLISHQUEUEPROCESSWORKER_SUB_PAGE, PublishQueueProcessWorker.class.getName());
		// No action available for this worker
		deleteAllCompatibleActionTypes();
		addCompatibleActionTypeName(NoActionType.NAME);				
	}
	
	
	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties
	 */
	@Override
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {
		Properties ret = super.getProperties(errorMessages);
		String publisherIdString = "";
		for(String pubid : selectedPublisherIdsToCheck) {
			if(!pubid.trim().equals("")){
			  if(publisherIdString.equals("")){
				  publisherIdString = pubid;
			  }else{
				  publisherIdString += ";"+pubid;
			  }
			}
		}
		if(maxNumberOfEntriesToPublish > MAX_JOBS_PER_QUEUE_WORKER) {
		    errorMessages.add("Number of entries to publish per interval may not exceed " + MAX_JOBS_PER_QUEUE_WORKER);
		}
		
		ret.setProperty(PublishQueueProcessWorker.PROP_PUBLISHER_IDS, publisherIdString);
		ret.setProperty(PublishQueueProcessWorker.PROP_MAX_WORKER_JOBS, Long.toString(maxNumberOfEntriesToPublish));
		return ret;
	}
	
	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	@Override
	public void setProperties(Properties properties) throws IOException {
		super.setProperties(properties);
		selectedPublisherIdsToCheck = new ArrayList<>();
		String[] publisherIdsToCheck = properties.getProperty(PublishQueueProcessWorker.PROP_PUBLISHER_IDS,"").split(";");
		for(int i=0;i<publisherIdsToCheck.length;i++){
			selectedPublisherIdsToCheck.add(publisherIdsToCheck[i]);
		}
		//Soft upgrade for this value introduced in 7.12.0. The default prior to this version was 20000, so the value will be set to the default. 
        if (properties.containsKey(PublishQueueProcessWorker.PROP_MAX_WORKER_JOBS)) {
            maxNumberOfEntriesToPublish = Integer.valueOf(properties.getProperty(PublishQueueProcessWorker.PROP_MAX_WORKER_JOBS));
        }
	}

    public List<String> getSelectedPublisherIdsToCheck() {
        return selectedPublisherIdsToCheck;
    }

    public void setSelectedPublisherIdsToCheck(List<String> selectedPublisherIdsToCheck) {
        this.selectedPublisherIdsToCheck = selectedPublisherIdsToCheck;
    }


    public long getMaxNumberOfEntriesToPublish() {
        return maxNumberOfEntriesToPublish;
    }


    public void setMaxNumberOfEntriesToPublish(long maxNumberOfEntriesToPublish) {
        this.maxNumberOfEntriesToPublish = maxNumberOfEntriesToPublish;
    }

}
