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

package org.ejbca.core.ejb.ca.publisher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.annotation.Resource;
import jakarta.ejb.CreateException;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBException;
import jakarta.ejb.FinderException;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.ExternalScriptsConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ocsp.OcspDataSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;

/**
 * Manages publisher queues which contains data to be republished, either because publishing failed or because publishing is done asynchronously.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherQueueSessionBean implements PublisherQueueSessionLocal {

    private static final Logger log = Logger.getLogger(PublisherQueueSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final ReentrantLock executorServiceLock = new ReentrantLock(false);
    private static final AtomicInteger beanInstanceCount = new AtomicInteger(0);
    private static volatile ExecutorService executorService = null;
    private static final String TIMEOUT_MESSAGE_INDICATOR = "timed out";
    
    private static final long MAX_JOBS_PER_QUEUE_WORKER = 200000L;

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;
    
    @EJB
    private NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession;
    
    @EJB
    private OcspDataSessionLocal ocspDataSession;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    
    /** not injected but created in ejbCreate, since it is ourself */
    private PublisherQueueSessionLocal publisherQueueSession;


    public PublisherQueueSessionBean() { }

    /** Constructor for unit tests */
    protected PublisherQueueSessionBean(final EntityManager entityManager, final NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession,
            final OcspDataSessionLocal ocspDataSession, final PublisherQueueSessionLocal publisherQueueSession) {
        this.entityManager = entityManager;
        this.noConflictCertificateStoreSession = noConflictCertificateStoreSession;
        this.ocspDataSession = ocspDataSession;
        this.publisherQueueSession = publisherQueueSession;
    }

    @PostConstruct
    public void postConstruct() {
        publisherQueueSession = sessionContext.getBusinessObject(PublisherQueueSessionLocal.class);
        // Keep track of number of instances of this bean, so we can free the executorService thread pool when the last is destroyed
        beanInstanceCount.incrementAndGet();
    }

    @PreDestroy
    public void preDestroy() {
        // Shut down the thread pool when the last instance of this SSB is destroyed
        if (beanInstanceCount.decrementAndGet() == 0) {
            executorServiceLock.lock();
            try {
                if (executorService != null) {
                    executorService.shutdown();
                    executorService = null;
                }
            } finally {
                executorServiceLock.unlock();
            }
        }
    }

    /** @return a reference to the "CachedThreadPool" executor service (creating one if needed). */
    private ExecutorService getExecutorService() {
        if (executorService == null) {
            executorServiceLock.lock();
            try {
                if (executorService == null) {
                    executorService = Executors.newCachedThreadPool();
                }
            } finally {
                executorServiceLock.unlock();
            }
        }
        return executorService;
    }

    @Override
    public void addQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileInformation queueData, int publishStatus, boolean safeDirectPublish)
            throws CreateException {
        if (log.isTraceEnabled()) {
            log.trace(">addQueueData(publisherId: " + publisherId + ")");
        }
        try {
            entityManager.persist(new org.ejbca.core.ejb.ca.publisher.PublisherQueueData(publisherId, publishType, fingerprint, queueData,
                    publishStatus, (safeDirectPublish && publishType == PublisherConst.PUBLISH_TYPE_CERT)));
        } catch (Exception e) {
            throw new CreateException(e.getMessage());
        }
        log.trace("<addQueueData()");
    }

    @Override
    public void removeQueueData(final String pk) {
        if (log.isTraceEnabled()) {
            log.trace(">removeQueueData(pk: " + pk + ")");
        }
        try {
            org.ejbca.core.ejb.ca.publisher.PublisherQueueData pqd = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(entityManager, pk);
            if (pqd == null) {
                log.warn("Trying to remove queue data that does not exist: " + pk);
            } else {
                entityManager.remove(pqd);
            }
        } catch (Exception e) {
            log.error("Failed to remove publisher queue data", e);
        }
        log.trace("<removeQueueData()");
    }

    @Override
    public void removeQueueDataByPublisherId(final int publisherId) {
        if (log.isTraceEnabled()) {
            log.trace(">removeQueueDataByPublisherId(publisherId: " + publisherId + ")");
        }
        final Query query = entityManager.createQuery("DELETE FROM PublisherQueueData pqd WHERE pqd.publisherId=:publisherId");
        query.setParameter("publisherId", publisherId);
        query.executeUpdate();
        log.trace("<removeQueueDataByPublisherId()");

    }

    @Override
    public PublishingResult publishQueueData(final AuthenticationToken admin, final String pk, final BasePublisher publisher) {
        if (log.isTraceEnabled()) {
            log.trace(">publishQueueData(pk: " + pk + ")");
        }
        PublishingResult result = null;
        final org.ejbca.core.ejb.ca.publisher.PublisherQueueData entity = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findByPk(
                entityManager, pk);
        if (entity == null) {
            log.warn("Trying to publish queue data that does not exist: " + pk);
        } else {
            PublisherQueueData pqd = new PublisherQueueData(entity.getPk(), new Date(entity.getTimeCreated()),
                    new Date(entity.getLastUpdate()), entity.getPublishStatus(), entity.getTryCounter(),
                    entity.getPublishType(), entity.getFingerprint(), entity.getPublisherId(),
                    entity.getPublisherQueueVolatileData());
            result = doPublish(admin, publisher, pqd);
        }
        log.trace("<publishQueueData()");
        return result;
    }

    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId) {
        if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisher(publisherId: " + publisherId + ")");
        }
        Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas = org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherConst.STATUS_PENDING, 0, 0);
        if (datas.isEmpty()) {
            log.debug("No publisher queue entries found for publisher " + publisherId);
        }
        Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
        Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter = datas.iterator();
        while (iter.hasNext()) {
            org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
            PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()),
                    d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(),
                    d.getPublisherQueueVolatileData());
            ret.add(pqd);
        }
        log.trace("<getPendingEntriesForPublisher()");
        return ret;
    }

    @Override
    public int getPendingEntriesCountForPublisher(int publisherId) {
        return (int) org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager, publisherId);
    }

    @Override
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds) {
        if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesCountForPublisherInIntervals(publisherId: " + publisherId + ", lower:" + Arrays.toString(lowerBounds)
                    + ", upper:" + Arrays.toString(upperBounds) + ")");
        }
        if (lowerBounds.length != upperBounds.length) {
            throw new IllegalArgumentException("lowerBounds and upperBounds must have equal length");
        }
        List<Integer> entryCountList = org.ejbca.core.ejb.ca.publisher.PublisherQueueData.findCountOfPendingEntriesForPublisher(entityManager,
                publisherId, lowerBounds, upperBounds);
        int[] result = new int[lowerBounds.length];
        for (int i = 0; i < lowerBounds.length && i < result.length; i++) {
            result[i] = entryCountList.get(i).intValue();
        }
        log.trace("<getPendingEntriesCountForPublisherInIntervals()");
        return result;
    }

    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimit(int publisherId, int limit) {
        return getPendingEntriesForPublisherWithLimitAndOffset(publisherId, limit, 0);
    }

    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimitAndOffset(final int publisherId, int limit, int offset) {
        if (log.isTraceEnabled()) {
            log.trace(">getPendingEntriesForPublisherWithLimit(publisherId: " + publisherId + ")");
        }
        Collection<PublisherQueueData> ret = new ArrayList<PublisherQueueData>();
        //TODO: This code has been modified from JDBC to JPA fetching, which might negatively affect performance. Investigate. 
        List<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> publisherQueueDataList = org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByPublisherIdAndStatus(entityManager, publisherId, PublisherConst.STATUS_PENDING, limit, offset);
        for (org.ejbca.core.ejb.ca.publisher.PublisherQueueData publisherQueueData : publisherQueueDataList) {
            PublisherQueueData pqd = new PublisherQueueData(publisherQueueData.getPk(), new Date(publisherQueueData.getTimeCreated()), new Date(
                    publisherQueueData.getLastUpdate()), PublisherConst.STATUS_PENDING, publisherQueueData.getTryCounter(),
                    publisherQueueData.getPublishType(), publisherQueueData.getFingerprint(), publisherId,
                    publisherQueueData.getPublisherQueueVolatileData());
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
        Collection<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> datas = org.ejbca.core.ejb.ca.publisher.PublisherQueueData
                .findDataByFingerprint(entityManager, fingerprint);
        if (datas.isEmpty()) {
            log.debug("No publisher queue entries found for fingerprint " + fingerprint);
        } else {
            Iterator<org.ejbca.core.ejb.ca.publisher.PublisherQueueData> iter = datas.iterator();
            while (iter.hasNext()) {
                org.ejbca.core.ejb.ca.publisher.PublisherQueueData d = iter.next();
                PublisherQueueData pqd = new PublisherQueueData(d.getPk(), new Date(d.getTimeCreated()), new Date(d.getLastUpdate()),
                        d.getPublishStatus(), d.getTryCounter(), d.getPublishType(), d.getFingerprint(), d.getPublisherId(),
                        d.getPublisherQueueVolatileData());
                ret.add(pqd);
            }
        }
        log.trace("<getEntriesByFingerprint()");
        return ret;
    }

    @Override
    public void updateData(String pk, int status, int tryCounter) {
        if (log.isTraceEnabled()) {
            log.trace(">updateData(pk: " + pk + ", status: " + status + ")");
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
            log.debug("Trying to set status on nonexisting data, pk: " + pk);
        }
        log.trace("<updateData()");
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public PublishingResult plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(final AuthenticationToken admin, final BasePublisher publisher,
            final long maxNumberOfJobs) {   
        if (maxNumberOfJobs > MAX_JOBS_PER_QUEUE_WORKER || maxNumberOfJobs <= 0) {
            log.warn("Number of maxmimum jobs for the queue worker must be between 1 and " + MAX_JOBS_PER_QUEUE_WORKER + ". Using the default of "
                    + PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS + " instead.");
        }
        final PublishingResult result = new PublishingResult();
        PublishingResult intermediateResult;
        // Repeat this process as long as we actually manage to publish something
        // this is because when publishing starts to work we want to publish everything in one go, if possible.
        // However, we don't want to publish more than 20000 certificates each time, because we want to commit to the database some time as well.
        int totalCount = 0;
        do {
            intermediateResult = publisherQueueSession.doChunk(admin, publisher);
            result.append(intermediateResult);
            totalCount += intermediateResult.getSuccesses();
        } while ((intermediateResult.getSuccesses() > 0) && (totalCount < maxNumberOfJobs));
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public PublishingResult doChunk(AuthenticationToken admin, BasePublisher publisher) {
        final Collection<PublisherQueueData> publisherQueueDatas = getPendingEntriesForPublisherWithLimit(publisher.getPublisherId(), 100);
        return doPublish(admin, publisher, publisherQueueDatas);
    }

    @Override
    public PublishingResult doPublish(AuthenticationToken admin, BasePublisher publisher, PublisherQueueData publisherQueueData) {
        return doPublish(admin, publisher, Collections.singletonList(publisherQueueData));
    }
    
    /** 
     * @param admin the administrator that must be authorized for publishing
     * @param publisher the publisher to publish to
     * @param publisherQueueData the data to publish
     *  
     * @return how many publishing operations that succeeded and failed 
     */
    private PublishingResult doPublish(AuthenticationToken admin, BasePublisher publisher, Collection<PublisherQueueData> publisherQueueData) {
        final int publisherId;
        if (publisher != null) {
            publisherId = publisher.getPublisherId();
        } else {
            publisherId = -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("Found " + publisherQueueData.size() + " certificates to republish for publisher " + publisherId);
        }
        final PublishingResult result = new PublishingResult();
        for (PublisherQueueData pqd : publisherQueueData) {
            String fingerprint = pqd.getFingerprint();
            int publishType = pqd.getPublishType();
            if (log.isDebugEnabled()) {
                log.debug("Publishing from queue to publisher: " + publisherId + ", fingerprint: " + fingerprint + ", pk: " + pqd.getPk()
                        + ", type: " + publishType);
            }
            PublisherQueueVolatileInformation voldata = pqd.getVolatileData();
            String password = null;
            ExtendedInformation ei = null;
            String userDataDN = null;
            if (voldata != null) {
                password = voldata.getPassword();
                ei = voldata.getExtendedInformation();
                userDataDN = voldata.getUserDN();
            }
            boolean published = false;
            boolean connectionTimedOut = false;

            try {
                if (publishType == PublisherConst.PUBLISH_TYPE_CERT) {
                    if (log.isDebugEnabled()) {
                        log.debug("Publishing Certificate");
                    }
                    if (publisher != null) {
                        // Read the actual certificate and try to publish it again
                        // TODO: we might need change fetch-type for all but the actual cert or a native query w SqlResultSetMapping..
                        final CertificateDataWrapper certificateDataWrapper = noConflictCertificateStoreSession.getCertificateData(fingerprint);
                        if (certificateDataWrapper==null) {
                            throw new FinderException();
                        }
                        try {
                            published = publisherQueueSession.publishCertificateNonTransactional(publisher, admin, certificateDataWrapper, password, userDataDN, ei);
                        } catch (EJBException e) {
                            final Throwable t = e.getCause();
                            if (t instanceof PublisherException) {
                                throw (PublisherException) t;
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

                    CRLData crlData = crlStoreSession.findByFingerprint(fingerprint);

                    if (crlData == null) {
                        throw new FinderException();
                    }
                    try {
                        published = publisherQueueSession.publishCRLNonTransactional(publisher, admin, crlData.getCRLBytes(),
                                crlData.getCaFingerprint(), crlData.getCrlNumber(), userDataDN);
                    } catch (EJBException e) {
                        final Throwable t = e.getCause();
                        if (t instanceof PublisherException) {
                            throw (PublisherException) t;
                        } else {
                            throw e;
                        }
                    }
                    
                } else if (publishType == PublisherConst.PUBLISH_TYPE_OCSP_RESPONSE) {
                    if (log.isDebugEnabled()) {
                        log.debug("Publishing OCSP Response");
                    }
                    
                    OcspResponseData ocspResponseData = ocspDataSession.findOcspDataById(fingerprint);
                               
                    if (ocspResponseData == null) {
                        throw new FinderException();
                    }
                    
                    published = publisherQueueSession.publishOcspResponsesNonTransactional((CustomPublisherContainer) publisher, admin, ocspResponseData);
                    
                } else {
                    String msg = intres.getLocalizedMessage("publisher.unknowntype", publishType);
                    log.error(msg);
                }
            } catch (FinderException e) {
                final String msg = intres.getLocalizedMessage("publisher.errornocert", fingerprint) + e.getMessage();
                log.info(msg);
                result.addFailure(fingerprint);
            } catch (PublisherException e) {
                // Publisher session have already logged this error nicely to
                // getLogSession().log
                log.debug(e.getMessage());
                // We failed to publish, update failcount, so we can break early if nothing succeeds but everything fails.
                result.addFailure(fingerprint, e.getMessage());
                // We will want to break out early on timeout exceptions, to avoid delaying
                // Publish Queue Process Service from moving on to the next publisher.
                if (e.getMessage() != null && e.getMessage().contains(TIMEOUT_MESSAGE_INDICATOR)){
                    connectionTimedOut = true;
                }
            }
            if (published) {
                if (publisher.getKeepPublishedInQueue()) {
                    // Update with information that publishing was successful
                    updateData(pqd.getPk(), PublisherConst.STATUS_SUCCESS, pqd.getTryCounter());
                } else {
                    // We are done with this one.. nuke it!
                    removeQueueData(pqd.getPk());
                }
                result.addSuccess(fingerprint); // jipeee update success counter
            } else {
                // Update with new tryCounter, but same status as before
                int tryCount = pqd.getTryCounter() + 1;
                updateData(pqd.getPk(), pqd.getPublishStatus(), tryCount);
                result.addFailure(fingerprint);
            }
            // Break out of the loop immediately if a connection timed out.
            // Publisher is not available for now, so we don't want to get stuck here for up to 99 timeouts.
            if (connectionTimedOut){
                if (log.isDebugEnabled()) {
                    log.debug("Connection timed out. Breaking out of publisher loop.");
                }
                break;
            }
            // If we don't manage to publish anything, but fails on all the
            // first ten ones we expect that this publisher is dead for now. We
            // don't have to try with every record.
            if (result.shouldBreakPublishingOperation()) {
                if (log.isDebugEnabled()) {
                    log.debug("Breaking out of publisher loop because everything seems to fail (at least the first 10 entries)");
                }
                break;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Returning from publisher with " + result.getSuccesses() + " entries published successfully.");
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean publishCertificateNonTransactional(BasePublisher publisher, AuthenticationToken admin, CertificateDataWrapper certWrapper,
            String password, String userDN, ExtendedInformation extendedinformation) throws PublisherException {
        if (publisher.isCallingExternalScript()) {
            final ExternalScriptsConfiguration externalScriptsConfiguration = (ExternalScriptsConfiguration) globalConfigurationSession.
                    getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (externalScriptsConfiguration.getEnableExternalScripts()) {
                // if the publisher claims to call external scripts, and we have not enabled calling external scripts, the publisher default, 
                // typically ExternalScriptsAllowlist.forbidAll() will be used.
                // If we have enabled external scripts, the below will allow all (ExternalScriptsAllowlist.permitAll) if allow list is not set, 
                // and only the commands on the allow list if an allows list is enabled and configured.
                final ExternalScriptsAllowlist allowlist = ExternalScriptsAllowlist.fromText(
                        externalScriptsConfiguration.getExternalScriptsWhitelist(),
                        externalScriptsConfiguration.getIsExternalScriptsWhitelistEnabled());                
                publisher.setExternalScriptsAllowlist(allowlist);
            }
        }
        if (publisher.isFullEntityPublishingSupported()) {
            return publisher.storeCertificate(admin, certWrapper.getCertificateDataOrCopy(), certWrapper.getBase64CertData(), password, userDN, extendedinformation);
        } else {
            final BaseCertificateData certificateData = certWrapper.getBaseCertificateData();
            final String cAFingerprint = certificateData.getCaFingerprint();
            final int status = certificateData.getStatus();
            final int type = certificateData.getType();
            final long revocationDate = certificateData.getRevocationDate();
            final int revocationReason = certificateData.getRevocationReason();
            final String username = certificateData.getUsername();
            final String tag  = certificateData.getTag();
            final Integer certificateProfileId = certificateData.getCertificateProfileId();
            final Long updateTime = certificateData.getUpdateTime();
            // ECA-9491 Tmp. until refactored.
            if (extendedinformation != null) {
                extendedinformation.setAccountBindingId(certificateData.getAccountBindingId());
            }
            return publisher.storeCertificate(admin, certWrapper.getCertificate(), username, password, userDN, cAFingerprint, status, type, revocationDate,
                    revocationReason, tag, certificateProfileId, updateTime, extendedinformation);
        }
    }

    /** Publishers do not run a part of regular transactions and expect to run in auto-commit mode. */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean publishCRLNonTransactional(BasePublisher publisher, AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN)
            throws PublisherException {
        if (publisher.isCallingExternalScript()) {
            final ExternalScriptsConfiguration externalScriptsConfiguration = (ExternalScriptsConfiguration) globalConfigurationSession.
                    getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (externalScriptsConfiguration.getEnableExternalScripts()) {
                final ExternalScriptsAllowlist allowlist = ExternalScriptsAllowlist.fromText(
                        externalScriptsConfiguration.getExternalScriptsWhitelist(),
                        externalScriptsConfiguration.getIsExternalScriptsWhitelistEnabled());                
                publisher.setExternalScriptsAllowlist(allowlist);
            }
        }
        return publisher.storeCRL(admin, incrl, cafp, number, userDN);
    }
    
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean publishOcspResponsesNonTransactional(CustomPublisherContainer publisher, AuthenticationToken admin, OcspResponseData ocspResponseData)
            throws PublisherException {
        if (publisher.isCallingExternalScript()) {
            final ExternalScriptsConfiguration externalScriptsConfiguration = (ExternalScriptsConfiguration) globalConfigurationSession.
                    getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (externalScriptsConfiguration.getEnableExternalScripts()) {
                final ExternalScriptsAllowlist allowlist = ExternalScriptsAllowlist.fromText(
                        externalScriptsConfiguration.getExternalScriptsWhitelist(),
                        externalScriptsConfiguration.getIsExternalScriptsWhitelistEnabled());                
                publisher.setExternalScriptsAllowlist(allowlist);
            }
        }
        return publisher.storeOcspResponseData(ocspResponseData);
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public List<Object> publishCertificateNonTransactionalInternal(final List<BasePublisher> publishers, final AuthenticationToken admin,
            final CertificateDataWrapper certWrapper, final String password, final String userDN, final ExtendedInformation extendedinformation) {
        final List<Object> publisherResults = new ArrayList<Object>();
        final boolean parallel = EjbcaConfiguration.isPublishParallelEnabled();
        // Are we doing parallel publishing (only meaningful if there is more than one publisher configured)?
        if (parallel && publishers.size() > 1) {
            final List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>();
            BasePublisher publisherFirst = null;
            for (final BasePublisher publisher : publishers) {
                if (publisherFirst == null) {
                    // We will execute the first of the publishers in the main thread...
                    publisherFirst = publisher;
                } else {
                    // ...and the rest of the publishers will be executed in new threads
                    final Future<Boolean> future = getExecutorService().submit(new Callable<Boolean>() {
                        @Override
                        public Boolean call() throws Exception {
                            if (!publishCertificateNonTransactional(publisher, admin, certWrapper, password, userDN, extendedinformation)) {
                                throw new PublisherException("Return code from publisher is false.");
                            }
                            return Boolean.TRUE;
                        }
                    });
                    futures.add(future);
                }
            }
            // Wait at most 300 seconds in total for all the publishers to complete.
            final long deadline = System.currentTimeMillis() + 300000L;
            // Execute the first publishing in the calling thread
            Object publisherResultFirst;
            try {
                if (!publishCertificateNonTransactional(publisherFirst, admin, certWrapper, password, userDN, extendedinformation)) {
                    throw new PublisherException("Return code from publisher is false.");
                }
                publisherResultFirst = Boolean.TRUE;
            } catch (Exception e) {
                publisherResultFirst = getAsPublisherException(e);
            }
            publisherResults.add(publisherResultFirst);
            // Wait for all the background threads to finish and get the result from each invocation
            for (final Future<Boolean> future : futures) {
                Object publisherResult;
                try {
                    final long maxTimeToWait = Math.max(1000L, deadline - System.currentTimeMillis());
                    publisherResult = Boolean.valueOf(future.get(maxTimeToWait, TimeUnit.MILLISECONDS));
                } catch (Exception e) {
                    publisherResult = getAsPublisherException(e);
                }
                publisherResults.add(publisherResult);
            }
        } else {
            // Perform publishing sequentially (old fall back behavior)
            for (final BasePublisher publisher : publishers) {
                try {
                    if (!publishCertificateNonTransactional(publisher, admin, certWrapper, password, userDN, extendedinformation)) {
                        throw new PublisherException("Return code from publisher is false.");
                    }
                    publisherResults.add(Boolean.TRUE);
                } catch (Exception e) {
                    publisherResults.add(getAsPublisherException(e));
                }
            }
        }
        return publisherResults;
    }

    private PublisherException getAsPublisherException(final Exception e) {
        if (log.isDebugEnabled()) {
            log.debug("Publisher threw exception", e);
        }
        if (e instanceof PublisherException) {
            return (PublisherException) e;
        }
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
            if (t instanceof PublisherException) {
                return (PublisherException) t;
            }
        }
        return new PublisherException(e.getMessage());
    }

}
