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

package org.ejbca.core.ejb.ca.publisher;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;


/**
 * Manages publisher queues which contains data to be republished, either because publishing failed or because publishing is done asynchonously. 
 *
 * @ejb.bean description="Session bean handling interface with publisher queue data"
 *   display-name="PublisherQueueSessionSB"
 *   name="PublisherQueueSession"
 *   jndi-name="PublisherQueueSession"
 *   local-jndi-name="PublisherQueueSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.ejb-external-ref description="The Publisher entity bean"
 *   view-type="local"
 *   ref-name="ejb/PublisherQueueDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocal"
 *   link="PublisherQueueData"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionRemote"
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PublisherQueueSessionBean extends BaseSessionBean {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /**
     * The local home interface of publisher entity bean.
     */
    private PublisherQueueDataLocalHome queuehome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        queuehome = (PublisherQueueDataLocalHome) getLocator().getLocalHome(PublisherQueueDataLocalHome.COMP_NAME);
    }


    /**
     * Adds an entry to the publisher queue.
	 *
	 * @param publisherId the publisher that this should be published to
	 * @param publishType the type of entry it is, {@link PublisherQueueData#PUBLISH_TYPE_CERT} or CRL
     * @throws CreateException if the entry can not be created
     *
     * @ejb.interface-method view-type="both"
     */
    public void addQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData) throws CreateException {
    	if (log.isTraceEnabled()) {
            log.trace(">addQueueData(publisherId: " + publisherId + ")");
    	}
    	queuehome.create(publisherId, publishType, fingerprint, queueData);
        trace("<addQueueData()");
    } // addEntry

    /**
     * Removes an entry from the publisher queue.
	 *
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeQueueData(String pk) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeQueueData(pk: " + pk + ")");
    	}
    	try {
			queuehome.remove(pk);
		} catch (EJBException e) {
			log.info(e);
		} catch (RemoveException e) {
			log.info(e);
		}
        trace("<removeQueueData()");
    } // addEntry

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a specific publisherId.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @throws CreateException if the entry can not be created
     *
     * @ejb.interface-method view-type="both"
     */
    public Collection getPendingEntriesForPublisher(int publisherId) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
    	}
    	Collection datas = null;
    	Collection ret = new ArrayList();
		try {
			datas = queuehome.findDataByPublisherIdAndStatus(publisherId, PublisherQueueData.STATUS_PENDING);
		} catch (FinderException e) {
			log.debug("No publisher queue entries found for publisher "+publisherId);
		}
		if (datas != null) {
	    	Iterator iter = datas.iterator();
	    	while (iter.hasNext()) {
	    		PublisherQueueDataLocal d = (PublisherQueueDataLocal)iter.next();
	    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), d.getTimeCreated(), d.getTimePublish(), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
	    		ret.add(pqd);
	    	}			
		}
        trace("<getPendingEntriesForPublisher()");
    	return ret;
    } // getPendingEntriesForPublisher

    /**
     * Finds all entries for a specific fingerprint.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @throws CreateException if the entry can not be created
     *
     * @ejb.interface-method view-type="both"
     */
    public Collection getEntriesByFingerprint(String fingerprint) {
    	if (log.isTraceEnabled()) {
            log.trace(">getEntriesByFingerprint(fingerprint: " + fingerprint + ")");
    	}
    	Collection datas = null;
    	Collection ret = new ArrayList();
		try {
			datas = queuehome.findDataByFingerprint(fingerprint);
		} catch (FinderException e) {
			log.debug("No publisher queue entries found for fingerprint "+fingerprint);
		}
		if (datas != null) {
	    	Iterator iter = datas.iterator();
	    	while (iter.hasNext()) {
	    		PublisherQueueDataLocal d = (PublisherQueueDataLocal)iter.next();
	    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), d.getTimeCreated(), d.getTimePublish(), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
	    		ret.add(pqd);
	    	}			
		}
        trace("<getEntriesByFingerprint()");
    	return ret;
    } // getEntriesByFingerprint

    
    /** Updates a record with new status
     * 
     * @param pk primary key of data entry
     * @param status status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to not update status
     * @param publishDate Date when successful publishing occurred or null if publishDate should not be updated
     * @param tryCounter an updated try counter, or -1 to not update counter
     * 
     * @ejb.interface-method view-type="both"
     */
    public void updateData(String pk, int status, Date publishDate, int tryCounter) {
    	if (log.isTraceEnabled()) {
            log.trace(">updateData(pk: " + pk + ", status: "+status+")");
    	}
    	try {
    		PublisherQueueDataLocal data = queuehome.findByPrimaryKey(pk);
    		if (status > 0) {
        		data.setPublishStatus(status);    			
    		}
    		if (publishDate != null) {
    			data.setTimePublish(publishDate);
    		}
    		if (tryCounter > -1) {
    			data.setTryCounter(tryCounter);
    		}
		} catch (FinderException e) {
			log.debug("Trying to set status on nonexisting data, pk: "+pk);
		}
        trace("<updateData()");
    }

} // LocalPublisherSessionBean
