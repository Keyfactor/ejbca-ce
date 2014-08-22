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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Manages publisher queues which contains data to be republished, either because publishing failed or because publishing is done asynchronously.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublisherQueueSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherQueueSessionBean implements PublisherQueueSessionLocal  {

	private static final Logger log = Logger.getLogger(PublisherQueueSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;

    /** not injected but created in ejbCreate, since it is ourself */
    private PublisherQueueSessionLocal publisherQueueSession;

    @PostConstruct
    public void ejbCreate() {
    	publisherQueueSession = sessionContext.getBusinessObject(PublisherQueueSessionLocal.class);
    }

    @Override
    public void addQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileInformation queueData, int publishStatus) throws CreateException {
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

    @Override
    public void removeQueueData(String pk) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeQueueData(pk: " + pk + ")");
    	}
    	try {
    		org.ejbca.core.ejb.ca.publisher.PublisherQueueData pqd = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(entityManager, pk);
    		if (pqd == null) {
    			if (log.isDebugEnabled()) {
    				log.debug("Trying to remove queue data that does not exist: "+pk);
    			}
    		} else {
        		entityManager.remove(pqd);    			
    		}
		} catch (Exception e) {
			log.info(e);
		}
		log.trace("<removeQueueData()");
    }

    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
    	}
    	Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherConst.STATUS_PENDING, 0);
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

    @Override
    public int getPendingEntriesCountForPublisher(int publisherId) {
    	return (int)org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager, publisherId);
    }
    
    @Override
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesCountForPublisherInIntervals(publisherId: " + publisherId + ", lower:" + Arrays.toString(lowerBounds) + ", upper:" + Arrays.toString(upperBounds) +  ")");
    	}
    	if(lowerBounds.length != upperBounds.length) {
    		throw new IllegalArgumentException("lowerBounds and upperBounds must have equal length");
    	}
    	List<Integer> entryCountList = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager, publisherId, lowerBounds, upperBounds);
    	int[] result = new int[lowerBounds.length];
		for(int i = 0; i < lowerBounds.length && i < result.length; i++) {
			result[i] = entryCountList.get(i).intValue();
		}
    	log.trace("<getPendingEntriesCountForPublisherInIntervals()");
    	return result;
    }
    
    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimit(int publisherId, int limit, int timeout, String orderBy) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisherWithLimit(publisherId: " + publisherId + ")");
    	}
    	Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();	
        //TODO: This code has been modified from JDBC to JPA fetching, which might negatively affect performance. Investigate. 
        List<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> publisherQueueDataList = org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherConst.STATUS_PENDING, limit);
        for (org.ejbca.core.ejb.ca.publisher.PublisherQueueData publisherQueueData : publisherQueueDataList) {
            PublisherQueueData pqd = new PublisherQueueData(publisherQueueData.getPk(), new Date(publisherQueueData.getTimeCreated()), new Date(
                    publisherQueueData.getLastUpdate()), PublisherConst.STATUS_PENDING, publisherQueueData.getTryCounter(), 
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

    @Override
    public Collection<PublisherQueueData> getEntriesByFingerprint(String fingerprint) {
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

    @Override
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
    
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(AuthenticationToken admin, int publisherId, BasePublisher publisher) {
        int successcount = 0;
        // Repeat this process as long as we actually manage to publish something
        // this is because when publishing starts to work we want to publish everything in one go, if possible.
        // However we don't want to publish more than 20000 certificates each time, because we want to commit to the database some time as well.
        int totalcount = 0;
        do {
            successcount = publisherQueueSession.doChunk(admin, publisherId, publisher);
            totalcount += successcount;
        } while ( (successcount > 0) && (totalcount < 20000) );
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public int doChunk(AuthenticationToken admin, int publisherId, BasePublisher publisher) {
        final Collection<PublisherQueueData> c = getPendingEntriesForPublisherWithLimit(publisherId, 100, 60, "order by timeCreated");
        return doPublish(admin, publisherId, publisher, c);
    }

    /** @return how many publishes that succeeded */
    private int doPublish(AuthenticationToken admin, int publisherId, BasePublisher publisher, Collection<PublisherQueueData> c) {
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
            PublisherQueueVolatileInformation voldata = pqd.getVolatileData();
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
                if (publishType == PublisherConst.PUBLISH_TYPE_CERT) {
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
                        final Certificate cert = cd.getCertificate(this.entityManager);
                       
                        try {
                        	published = publisherQueueSession.storeCertificateNonTransactional(publisher, admin, cert, username, password, userDataDN,
                        			cd.getCaFingerprint(), cd.getStatus(), cd.getType(), cd.getRevocationDate(), cd.getRevocationReason(), cd.getTag(), cd
                        			.getCertificateProfileId(), cd.getUpdateTime(), ei);
                        } catch (EJBException e) {
                        	final Throwable t = e.getCause();
                        	if (t instanceof PublisherException) {
                        		throw (PublisherException)t;
                        	} else {
                        		throw e;
                        	}
                        }
                    } else {
                        String msg = intres.getLocalizedMessage("publisher.nopublisher", publisherId);
                        log.info(msg);
                    }
                } else if (publishType == PublisherConst.PUBLISH_TYPE_CRL) {
                    if (log.isDebugEnabled()) {
                        log.debug("Publishing CRL");
                    }
            
                    CRLData crlData = CRLData.findByFingerprint(entityManager, fingerprint);

                    if (crlData == null) {
                        throw new FinderException();
                    }
                    try {
                        published = publisherQueueSession.storeCRLNonTransactional(publisher, admin, crlData.getCRLBytes(), crlData.getCaFingerprint(), crlData.getCrlNumber(), userDataDN);
                    } catch (EJBException e) {
                        final Throwable t = e.getCause();
                        if (t instanceof PublisherException) {
                            throw (PublisherException) t;
                        } else {
                            throw e;
                        }
                    }
                } else {
                    String msg = intres.getLocalizedMessage("publisher.unknowntype", publishType);
                    log.error(msg);
                }
            } catch (FinderException e) {
                final String msg = intres.getLocalizedMessage("publisher.errornocert", fingerprint) + e.getMessage();
                log.info(msg);
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
                    updateData(pqd.getPk(), PublisherConst.STATUS_SUCCESS, pqd.getTryCounter());
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

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean storeCertificateNonTransactional(BasePublisher publisher, AuthenticationToken admin, Certificate cert, String username, String password, String userDN,
    		String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
    		long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
    	return publisher.storeCertificate(admin, cert, username, password, userDN, cafp, status, type, revocationDate, revocationReason,
                tag, certificateProfileId, lastUpdate, extendedinformation);
    }

    /** Publishers do not run a part of regular transactions and expect to run in auto-commit mode. */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean storeCRLNonTransactional(BasePublisher publisher, AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
    	return publisher.storeCRL(admin, incrl, cafp, number, userDN);
    }
}
