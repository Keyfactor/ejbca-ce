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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.ejb.ca.store.CertificateData;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;

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
 * @ejb.env-entry description="JDBC datasource to be used"
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
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
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "PublisherQueueSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherQueueSessionBean implements PublisherQueueSessionRemote, PublisherQueueSessionLocal  {

	private static final Logger log = Logger.getLogger(PublisherQueueSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;

    /**
     * Adds an entry to the publisher queue.
	 *
	 * @param publisherId the publisher that this should be published to
	 * @param publishType the type of entry it is, {@link PublisherQueueData#PUBLISH_TYPE_CERT} or CRL
     * @throws CreateException if the entry can not be created
     *
     * @ejb.interface-method view-type="both"
     */
    public void addQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData, int publishStatus) throws CreateException {
    	if (log.isTraceEnabled()) {
            log.trace(">addQueueData(publisherId: " + publisherId + ")");
    	}
    	try {
        	entityManager.persist(new org.ejbca.core.ejb.ca.publisher.PublisherQueueData(publisherId, publishType, fingerprint, queueData, publishStatus));
    	} catch (Exception e) {
    		throw new CreateException(e.getMessage());
    	}
    	log.trace("<addQueueData()");
    }

    /**
     * Removes an entry from the publisher queue.
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeQueueData(String pk) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeQueueData(pk: " + pk + ")");
    	}
    	try {
    		org.ejbca.core.ejb.ca.publisher.PublisherQueueData pqd = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(entityManager, pk);
    		entityManager.remove(pqd);
		} catch (Exception e) {
			log.info(e);
		}
		log.trace("<removeQueueData()");
    }

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a specific publisherId.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getPendingEntriesForPublisher(int publisherId) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
    	}
    	Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherQueueData.STATUS_PENDING, 0);
    	if (datas.size() == 0) {
			log.debug("No publisher queue entries found for publisher "+publisherId);
    	}
    	Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
    	Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter = datas.iterator();
    	while (iter.hasNext()) {
    		org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
    		ret.add(pqd);
    	}			
		log.trace("<getPendingEntriesForPublisher()");
    	return ret;
    }

    /**
     * Gets the number of pending entries for a publisher.
     * @param publisherId The publisher to count the number of pending entries for.
     * @return The number of pending entries.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int getPendingEntriesCountForPublisher(int publisherId) {
    	return Long.valueOf(PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager, publisherId)).intValue();
    }
    
    /**
     * Gets an array with the number of new pending entries for a publisher in each intervals specified by 
     * <i>lowerBounds</i> and <i>upperBounds</i>. 
     * 
     * The interval is defined as from lowerBounds[i] to upperBounds[i] and the unit is seconds from now. 
     * A negative value results in no boundary.
     * 
     * @param publisherId The publisher to count the number of pending entries for.
     * @return Array with the number of pending entries corresponding to each element in <i>interval</i>.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesCountForPublisherInIntervals(publisherId: " + publisherId + ", lower:" + Arrays.toString(lowerBounds) + ", upper:" + Arrays.toString(upperBounds) +  ")");
    	}
    	if(lowerBounds.length != upperBounds.length) {
    		throw new IllegalArgumentException("lowerBounds and upperBounds must have equal length");
    	}
    	List<BigInteger> entryCountList = PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager, publisherId, lowerBounds, upperBounds);
    	int[] result = new int[lowerBounds.length];
		for(int i = 0; i < lowerBounds.length && i < result.length; i++) {
			result[i] = entryCountList.get(i).intValue();
		}
    	log.trace("<getPendingEntriesCountForPublisherInIntervals()");
    	return result;
    }
    
    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a specific publisherId.
	 *
	 * @param orderBy order by clause for the SQL to the database, for example "order by timeCreated desc".
	 * 
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getPendingEntriesForPublisherWithLimit(int publisherId, int limit, int timeout, String orderBy) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisherWithLimit(publisherId: " + publisherId + ")");
    	}
    	Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();	
        //TODO: This code has been modified from JDBC to JPA fetching, which might negatively affect performance. Investigate. 
        List<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> publisherQueueDataList = org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherQueueData.STATUS_PENDING, limit);
        for (org.ejbca.core.ejb.ca.publisher.PublisherQueueData publisherQueueData : publisherQueueDataList) {
            PublisherQueueData pqd = new PublisherQueueData(publisherQueueData.getPk(), new Date(publisherQueueData.getTimeCreated()), new Date(
                    publisherQueueData.getLastUpdate()), PublisherQueueData.STATUS_PENDING, publisherQueueData.getTryCounter(), 
                    publisherQueueData.getPublishType(), publisherQueueData.getFingerprint(), publisherId, publisherQueueData.getPublisherQueueVolatileData());
            ret.add(pqd);
            if (log.isDebugEnabled()) {
                log.debug("Return pending record with pk " + publisherQueueData.getPk() + ", and timeCreated "
                        + new Date(publisherQueueData.getTimeCreated()));
            }
        }
    	log.trace("<getPendingEntriesForPublisherWithLimit()");
    	return ret;
    }

    /**
     * Finds all entries for a specific fingerprint.
	 *
	 * @return Collection of PublisherQueueData, never null
	 * 
     * @ejb.interface-method view-type="both"
     */
    public Collection getEntriesByFingerprint(String fingerprint) {
    	if (log.isTraceEnabled()) {
            log.trace(">getEntriesByFingerprint(fingerprint: " + fingerprint + ")");
    	}
    	Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
    	Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findDataByFingerprint(entityManager, fingerprint);
    	if (datas.size() == 0) {
			log.debug("No publisher queue entries found for fingerprint "+fingerprint);
		} else {
	    	Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter = datas.iterator();
	    	while (iter.hasNext()) {
	    		org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
	    		PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()), d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(), d.getPublisherQueueVolatileData());
	    		ret.add(pqd);
	    	}			
		}
		log.trace("<getEntriesByFingerprint()");
    	return ret;
    }

    /** Updates a record with new status
     * 
     * @param pk primary key of data entry
     * @param status status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to not update status
     * @param tryCounter an updated try counter, or -1 to not update counter
     * 
     * @ejb.interface-method view-type="both"
     */
    public void updateData(String pk, int status, int tryCounter) {
    	if (log.isTraceEnabled()) {
            log.trace(">updateData(pk: " + pk + ", status: "+status+")");
    	}
    	org.ejbca.core.ejb.ca.publisher.PublisherQueueData data = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(entityManager, pk);
    	if (data != null) {
    		if (status > 0) {
        		data.setPublishStatus(status);    			
    		}
    		data.setLastUpdate(new Date().getTime());
    		if (tryCounter > -1) {
    			data.setTryCounter(tryCounter);
    		}
		} else {
			log.debug("Trying to set status on nonexisting data, pk: "+pk);
		}
		log.trace("<updateData()");
    }
    
	/**
	 * Intended for use from PublishQueueProcessWorker.
	 * 
	 * Publishing algorithm that is a plain fifo queue, but limited to selecting entries to republish at 100 records at a time. It will select from the database for this particular publisher id, and process 
	 * the record that is returned one by one. The records are ordered by date, descending so the oldest record is returned first. 
	 * Publishing is tried every time for every record returned, with no limit.
     * Repeat this process as long as we actually manage to publish something this is because when publishing starts to work we want to publish everything in one go, if possible.
     * However we don't want to publish more than 20000 certificates each time, because we want to commit to the database some time as well.
     * Now, the OCSP publisher uses a non-transactional data source so it commits every time so...
	 * 
	 * @param publisherId
	 * @throws PublisherException 
	 */
	public void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(Admin admin, int publisherId, BasePublisher publisher) {
		int successcount = 0;
		// Repeat this process as long as we actually manage to publish something
		// this is because when publishing starts to work we want to publish everything in one go, if possible.
		// However we don't want to publish more than 5000 certificates each time, because we want to commit to the database some time as well.
		int totalcount = 0;
		
		do {
			Collection<PublisherQueueData> c = getPendingEntriesForPublisherWithLimit(publisherId, 100, 60, "order by timeCreated");
			successcount = doPublish(admin, publisherId, publisher, c);
			totalcount += successcount;
		} while ( (successcount > 0) && (totalcount < 20000) );
	}

    /**
     * @param publisherId
     * @param c
     * @return how many publishes that succeeded
     * @throws PublisherException
     */
    private int doPublish(Admin admin, int publisherId, BasePublisher publisher, Collection<PublisherQueueData> c) {
        if (log.isDebugEnabled()) {
            log.debug("Found " + c.size() + " certificates to republish for publisher " + publisherId);
        }
        int successcount = 0;
        int failcount = 0;

        for (PublisherQueueData pqd : c) {

            String fingerprint = pqd.getFingerprint();
            int publishType = pqd.getPublishType();
            if (log.isDebugEnabled()) {
                log.debug("Publishing from queue to publisher: " + publisherId + ", fingerprint: " + fingerprint + ", pk: " + pqd.getPk()
                        + ", type: " + publishType);
            }
            PublisherQueueVolatileData voldata = pqd.getVolatileData();
            String username = null;
            String password = null;
            ExtendedInformation ei = null;
            String userDataDN = null;
            if (voldata != null) {
                username = voldata.getUsername();
                password = voldata.getPassword();
                ei = voldata.getExtendedInformation();
                userDataDN = voldata.getUserDN();
            }
            boolean published = false;

            
            try {
                if (publishType == PublisherQueueData.PUBLISH_TYPE_CERT) {
                    if (log.isDebugEnabled()) {
                        log.debug("Publishing Certificate");
                    }
                    if (publisher != null) {
                        // Read the actual certificate and try to publish it
                        // again
                        // TODO: we might need change fetch-type for all but the
                        // actual cert or a native query w SqlResultSetMapping..
                   
                        CertificateData cd = CertificateData.findByFingerprint(entityManager, fingerprint);

                        if (cd == null) {
                            throw new FinderException();
                        }
              
                        published = publisher.storeCertificate(admin, cd.getCertificate(), username, password, userDataDN, cd.getCaFingerprint(), cd
                                .getStatus(), cd.getType(), cd.getRevocationDate(), cd.getRevocationReason(), cd.getTag(), cd
                                .getCertificateProfileId(), cd.getUpdateTime(), ei);

                    } else {
                        String msg = intres.getLocalizedMessage("publisher.nopublisher", publisherId);
                        log.info(msg);
                    }
                } else if (publishType == PublisherQueueData.PUBLISH_TYPE_CRL) {

                    if (log.isDebugEnabled()) {
                        log.debug("Publishing CRL");
                    }
                    CRLData crlData = CRLData.findByFingerprint(entityManager, fingerprint);

                    if (crlData == null) {
                        throw new FinderException();
                    }
                    published = publisher.storeCRL(admin, crlData.getCRLBytes(), crlData.getCaFingerprint(), userDataDN);
                } else {
                    String msg = intres.getLocalizedMessage("publisher.unknowntype", publishType);
                    log.error(msg);
                }
            } catch (FinderException e) {

                String msg = intres.getLocalizedMessage("publisher.errornocert", fingerprint);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), username, null,
                        LogConstants.EVENT_INFO_STORECERTIFICATE, msg, e);
            } catch (PublisherException e) {
                // Publisher session have already logged this error nicely to
                // getLogSession().log
                log.debug(e.getMessage());
                // We failed to publish, update failcount so we can break early
                // if nothing succeeds but everything fails.
                failcount++;
            }
            if (published) {

                if (publisher.getKeepPublishedInQueue()) {
                    // Update with information that publishing was successful
                    updateData(pqd.getPk(), PublisherQueueData.STATUS_SUCCESS, pqd.getTryCounter());
                } else {
                    // We are done with this one.. nuke it!
                    removeQueueData(pqd.getPk());
                }

                successcount++; // jipeee update success counter
            } else {
                // Update with new tryCounter, but same status as before
                int tryCount = pqd.getTryCounter() + 1;
                updateData(pqd.getPk(), pqd.getPublishStatus(), tryCount);
            }
            // If we don't manage to publish anything, but fails on all the
            // first ten ones we expect that this publisher is dead for now. We
            // don't have to try with every record.
            if ((successcount == 0) && (failcount > 10)) {
                if (log.isDebugEnabled()) {
                    log.debug("Breaking out of publisher loop because everything seems to fail (at least the first 10 entries)");
                }
                break;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Returning from publisher with " + successcount + " entries published successfully.");
        }
        return successcount;
    }
}
