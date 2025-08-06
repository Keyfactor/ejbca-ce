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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Asynchronous;
import jakarta.ejb.CreateException;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBException;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.repository.Cache;
import org.cesecore.repository.CachedDatabase;
import org.cesecore.repository.Database;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.exception.RecordIndexAlreadyExistsException;
import org.cesecore.repository.exception.RecordIndexDoesNotExistException;
import org.cesecore.repository.util.XmlUtil;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.LogRedactionUtils;
import org.cesecore.util.ProfileID;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.FatalPublisherConnectionException;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import org.ejbca.dto.PublisherData;
import org.ejbca.dto.PublisherDataBean;
import org.ejbca.dto.PublisherDataBuilder;
import org.ejbca.dto.PublisherDataConverter;

/**
 * Handles management of Publishers.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherSessionBean implements PublisherSessionLocal, PublisherSessionRemote {

    private static final Logger log = Logger.getLogger(PublisherSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String PROPERTYKEY_STORECRL = "storeCRL";

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;

    private static final Lock INIT_LOCK = new ReentrantLock();
    private static CachedDatabase<PublisherData, Integer, PublisherDataBean> repository;
    private static ConcurrentMap<Integer, BasePublisher> basePublisherMap;

    @PostConstruct
    public void postConstruct() {
        if (repository == null) {
            try {
                INIT_LOCK.lock();
                if (repository == null) {
                    Database<PublisherData, Integer, PublisherDataBean> database = new Database<>(
                            entityManager,
                            PublisherDataBean.class,
                            new PublisherDataConverter(),
                            "name");
                    final var cache = new Cache<PublisherData, Integer>(EjbcaConfiguration.getCachePublisherTime());
                    repository = new CachedDatabase<>(database, cache);
                    basePublisherMap = new ConcurrentHashMap<>();
                }
            } finally {
                INIT_LOCK.unlock();
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushPublisherCache() {
        repository.clearCache();
        if (log.isDebugEnabled()) {
            log.debug("Flushed Publisher cache.");
        }
    }

    @Asynchronous
    @Override
    public void publishQueuedEntry(AuthenticationToken admin, int publisherId, PublisherQueueData entity) {
        final BasePublisher publisher = getPublisher(publisherId);
        final PublishingResult publisherResult = publisherQueueSession.doPublish(admin, publisher, entity);
        final boolean success = publisherResult.getSuccesses() > 0;
        if (success) {
            final int eepId = certificateStoreSession.getCertificateData(entity.getFingerprint()).getCertificateData().getEndEntityProfileId();
            final String userDn = LogRedactionUtils.getSubjectDnLogSafe(entity.getVolatileData().getUserDN(), eepId);

            final String msg = intres.getLocalizedMessage("publisher.store", userDn, publisher.getName(), success);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);

            auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CERTIFICATE, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER,
                    EjbcaServiceTypes.EJBCA, admin.toString(), null, entity.getFingerprint(), entity.getVolatileData().getUsername(), details);
        } else {
            final String msg = intres.getLocalizedMessage("publisher.errorstore", publisher.getName(), entity.getFingerprint());
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            if (publisherResult.getMessage(entity.getFingerprint()) != null) {
                details.put("error", publisherResult.getMessage(entity.getFingerprint()));
            }
            auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CERTIFICATE, EventStatus.FAILURE, EjbcaModuleTypes.PUBLISHER,
                    EjbcaServiceTypes.EJBCA, admin.toString(), null, entity.getFingerprint(), entity.getVolatileData().getUsername(), details);
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public boolean storeCertificateNewTransaction(AuthenticationToken admin, Collection<Integer> publisherids, CertificateDataWrapper certWrapper,
            String password, String userDN, ExtendedInformation extendedinformation) throws AuthorizationDeniedException {
        return storeCertificate(admin, publisherids, certWrapper, password, userDN, extendedinformation);
    }
    
    @Override
    public boolean storeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, CertificateDataWrapper certWrapper,
            String password, String userDN, ExtendedInformation extendedinformation) throws AuthorizationDeniedException {
        
        final BaseCertificateData certificateData = certWrapper.getBaseCertificateData();
        final int caid = certificateData.getIssuerDN().hashCode();
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
        if (publisherids == null) {
            return true;
        }
        final int status = certificateData.getStatus();
        final long revocationDate = certificateData.getRevocationDate();
        final String username = certificateData.getUsername();
        boolean returnval = true;
        final List<BasePublisher> publishersToTryDirect = new ArrayList<>();
        final List<BasePublisher> publishersToQueuePending = new ArrayList<>();
        final List<BasePublisher> publishersToQueueSuccess = new ArrayList<>();
        for (final Integer id : publisherids) {
            BasePublisher publisher = getPublisher(repository.findById(id));
            if (publisher != null) {
                // If the publisher will not publish the certificate, break out directly and do not call the publisher or queue the certificate
                if (publisher.willPublishCertificate(status, revocationDate)) {
                    if (publisher.getOnlyUseQueue() || publisher.getSafeDirectPublishing()) {
                        if (publisher.getUseQueueForCertificates()) {
                            publishersToQueuePending.add(publisher);
                            // Publishing to the queue directly is not considered a successful write to the publisher (since we don't know that it will be)
                            returnval = false;
                        } else {
                            // NOOP: This publisher is configured to only write to the queue, but not for certificates
                        }
                    } else {
                        publishersToTryDirect.add(publisher);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Not storing or queuing certificate for Publisher with id " + id + " because publisher will not publish it.");
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                log.info(msg);
                returnval = false;
            }
        }
        final String fingerprint = certificateData.getFingerprint();
        final List<Object> publisherResults = publisherQueueSession.publishCertificateNonTransactionalInternal(publishersToTryDirect, admin,
                certWrapper, password, userDN, extendedinformation);
        final String certSerno = certificateData.getSerialNumberHex();
        for (int i = 0; i < publishersToTryDirect.size(); i++) {
            final Object publisherResult = publisherResults.get(i);
            final BasePublisher publ = publishersToTryDirect.get(i);
            final Integer id = publ.getPublisherId();
            final String name = getPublisherName(id);
            if (!(publisherResult instanceof PublisherException)) {
                // If it wasn't an exception, it's a Boolean, but check it anyhow to avoid any chance of exception
                Boolean result = false;
                if (publisherResult instanceof Boolean) {
                    result = (Boolean)publisherResult;
                } else {
                    log.error("Return type from storeCertificateNonTransactionalInternal was not a Boolean but a " + result.getClass().getName() + ", this is an API error.");
                }

                final String msg = intres.getLocalizedMessage("publisher.store", certificateData.getLogSafeSubjectDn(), name, result);
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CERTIFICATE, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER,
                        EjbcaServiceTypes.EJBCA, admin.toString(), null, certSerno, username, details);
                if (publ.getKeepPublishedInQueue() && publ.getUseQueueForCertificates()) {
                    publishersToQueueSuccess.add(publ);
                }
            } else {
                final String msg = intres.getLocalizedMessage("publisher.errorstore", name, fingerprint);
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);

                details.put("error", LogRedactionUtils.getRedactedMessage(((PublisherException) publisherResult).getMessage()));
                auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CERTIFICATE, EventStatus.FAILURE, EjbcaModuleTypes.PUBLISHER,
                        EjbcaServiceTypes.EJBCA, admin.toString(), null, certSerno, username, details);
                if (publ.getUseQueueForCertificates()) {
                    publishersToQueuePending.add(publ);
                }
                returnval = false;
            }
        }
        addQueueData(publishersToQueueSuccess, username, password, extendedinformation, userDN, fingerprint, status, PublisherConst.STATUS_SUCCESS);
        addQueueData(publishersToQueuePending, username, password, extendedinformation, userDN, fingerprint, status, PublisherConst.STATUS_PENDING);
        return returnval;
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, String fingerprint,
            String password, String userDN, ExtendedInformation extendedinformation) throws AuthorizationDeniedException {
        final CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(fingerprint);
        return storeCertificate(admin, publisherids, certificateDataWrapper, password, userDN, extendedinformation);
    }

    private void addQueueData(final List<BasePublisher> publishersToQueue, final String username, final String password,
            final ExtendedInformation extendedInformation, final String userDN, final String fingerprint, final int status, final int publisherStatus) {
        for (final BasePublisher publ : publishersToQueue) {
            final int id = publ.getPublisherId();
            final String name = getPublisherName(id);
            if (log.isDebugEnabled()) {
                log.debug("KeepPublishedInQueue: " + publ.getKeepPublishedInQueue());
                log.debug("UseQueueForCertificates: " + publ.getUseQueueForCertificates());
            }
            // Write to the publisher queue either for audit reasons or to be able try again
            PublisherQueueVolatileInformation pqvd = new PublisherQueueVolatileInformation();
            pqvd.setUsername(username);
            pqvd.setPassword(password);
            pqvd.setExtendedInformation(extendedInformation);
            pqvd.setUserDN(userDN);
            try {
                publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_CERT, fingerprint, pqvd, publisherStatus, publ.getSafeDirectPublishing());
                final String msg = intres.getLocalizedMessage("publisher.storequeue", name, fingerprint, status);
                log.info(msg);
            } catch (CreateException e) {
                final String msg = intres.getLocalizedMessage("publisher.errorstorequeue", name, fingerprint, status);
                log.info(msg, e);
            }
        }
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, Collection<Integer> publisherids, byte[] incrl, String cafp, int number, String issuerDn)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL");
        }
        int caid = DnComponents.stringToBCDNString(issuerDn).hashCode();
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }

        boolean returnval = true;
        for (Integer id : publisherids) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            final BasePublisher publ = getPublisher(id);
            if (publ != null) {
                final String name = getPublisherName(id);
                // If it should be published directly
                if (!publ.getOnlyUseQueue()) {
                    boolean publishCrl = true;
                    if (isStoreCrlPropertyUsed(publ)) {
                        final List<CustomPublisherProperty> properties = ((CustomPublisherContainer) publ).getCustomUiPropertyList(admin);
                        publishCrl = properties.stream()
                            .filter(property -> property.getName().equals(PROPERTYKEY_STORECRL))
                            .map(property -> Boolean.valueOf(property.getValue()))
                            .findFirst()
                            .orElse(false);
                    }

                    if (publishCrl) {
                        try {
                            try {
                                if (publisherQueueSession.publishCRLNonTransactional(publ, admin, incrl, cafp, number, issuerDn)) {
                                    publishStatus = PublisherConst.STATUS_SUCCESS;
                                }
                            } catch (EJBException e) {
                                final Throwable t = e.getCause();
                                if (t instanceof PublisherException) {
                                    throw (PublisherException) t;
                                } else {
                                    throw e;
                                }
                            }
                            final String msg;
                            final Map<String, Object> details = new LinkedHashMap<>();
                            EventStatus status;
                            if (publishStatus == PublisherConst.STATUS_SUCCESS) {
                                msg = intres.getLocalizedMessage("publisher.store", "CRL", name, publishStatus);
                                status = EventStatus.SUCCESS;
                            } else {
                                msg = intres.getLocalizedMessage("publisher.store.fail", "CRL", name, publishStatus);
                                status = EventStatus.FAILURE;
                            }
                            details.put("msg", msg);
                            auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CRL, status, EjbcaModuleTypes.PUBLISHER,
                                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
                        } catch (PublisherException pe) {
                            final String msg = intres.getLocalizedMessage("publisher.errorstore", name, "CRL");
                            final Map<String, Object> details = new LinkedHashMap<>();
                            details.put("msg", msg);

                            details.put("error", LogRedactionUtils.getRedactedMessage(pe.getMessage()));
                            auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CRL, EventStatus.FAILURE, EjbcaModuleTypes.PUBLISHER,
                                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("No CRL published. The VA publisher is not configured to do it.");
                        }
                        publishStatus = PublisherConst.STATUS_SUCCESS;
                    }
                }
                if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                    returnval = false;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Publisher status: " + publishStatus);
                    log.debug("KeepPublishedInQueue: " + publ.getKeepPublishedInQueue());
                    log.debug("UseQueueForCRLs: " + publ.getUseQueueForCRLs());
                }
                if ((publishStatus != PublisherConst.STATUS_SUCCESS || publ.getKeepPublishedInQueue()) && publ.getUseQueueForCRLs()) {
                    // Write to the publisher queue either for audit reasons or
                    // to be able try again
                    final PublisherQueueVolatileInformation pqvd = new PublisherQueueVolatileInformation();
                    pqvd.setUserDN(issuerDn);
                    String fp = CertTools.getFingerprintAsString(incrl);
                    try {
                        // publishStatus can only be either STATUS_PENDING or STATUS_SUCCESS, for CRLs we want to store with the actual status, that may be
                        // STATUS_SUCCESS if it was published directly above (status is success, but useQueueForCRLS and keepPublishedInQueue is active)
                        publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_CRL, fp, pqvd, publishStatus, false);
                        String msg = intres.getLocalizedMessage("publisher.storequeue", name, fp, "CRL");
                        log.info(msg);
                    } catch (CreateException e) {
                        String msg = intres.getLocalizedMessage("publisher.errorstorequeue", name, fp, "CRL");
                        log.info(msg, e);
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                log.info(msg);
                returnval = false;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCRL");
        }
        return returnval;
    }

    @Override
    public boolean storeOcspResponses(AuthenticationToken admin, Collection<Integer> publisherids, OcspResponseData ocspResponseData)
            throws AuthorizationDeniedException {

        final int caid = ocspResponseData.getCaId();
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }

        if (CollectionUtils.isEmpty(publisherids)) {
            return true; //Nothing to publish just return success
        }

        for (final int id : publisherids) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            BasePublisher publ = getPublisher(id);
            if (publ != null) {
                if (isOcspResponsePublisher(publ)) {
                    final String name = getPublisherName(id);
                    // If it should be published directly
                    if (!publ.getOnlyUseQueue()) {
                        try {

                            if (publisherQueueSession.publishOcspResponsesNonTransactional((CustomPublisherContainer) publ, admin, ocspResponseData)) {
                                publishStatus = PublisherConst.STATUS_SUCCESS;
                                logSuccessPublish(admin, name, publishStatus);
                            }
                        } catch (PublisherException e) {
                            logFailPublish(admin, name, e);
                        } catch (AuditRecordStorageException e) {
                            log.error("Error when loging audit data ", e);
                        }
                    }

                    if ((publishStatus != PublisherConst.STATUS_SUCCESS || publ.getKeepPublishedInQueue()) && publ.getUseQueueForOcspResponses()) {
                        addOcspResponseQueueData(id, name, publishStatus, ocspResponseData.getId());
                        if (log.isTraceEnabled()) {
                            log.trace("<storeOCSPResponse");
                        }
                        continue;
                    }

                    if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                        return false;
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                log.info(msg);
                return false;
            }
        }
        return true;
    }
    
    private void addOcspResponseQueueData(int id, String name, int publishStatus, String responseId) {
        // Write to the publisher queue either for audit reasons or
        // to be able try again
        final PublisherQueueVolatileInformation pqvd = new PublisherQueueVolatileInformation();
        try {
            // publishStatus can only be either STATUS_PENDING or STATUS_SUCCESS, for OCSP response we want to store with the actual status, that may be
            // STATUS_SUCCESS if it was published directly above (status is success, but useQueueForOcspResponse and keepPublishedInQueue is active)
            publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_OCSP_RESPONSE, responseId, pqvd, publishStatus, false);
            String msg = intres.getLocalizedMessage("publisher.storequeue", name, responseId, "OCSP Response");
            log.info(msg);
        } catch (CreateException e) {
            String msg = intres.getLocalizedMessage("publisher.errorstorequeue", name, responseId, "OCSP Response");
            log.info(msg, e);
        }
    }
    
    
    private void logSuccessPublish(AuthenticationToken admin, String name, int publishStatus) {
        final String msg = intres.getLocalizedMessage("publisher.store", "OCSP Response", name, publishStatus);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_OCSP_RESPONSE, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER,
                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);        
    }

    private void logFailPublish(AuthenticationToken admin, String name, Exception e) {
        final String msg = intres.getLocalizedMessage("publisher.errorstore", name, "OCSP Response");
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        details.put("error", e.getMessage());
        auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_OCSP_RESPONSE, EventStatus.FAILURE, EjbcaModuleTypes.PUBLISHER,
                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);

    }
    
    
    private boolean isOcspResponsePublisher(final BasePublisher publisher) {
        return (publisher instanceof CustomPublisherContainer) && 
        StringUtils.contains(((CustomPublisherContainer) publisher).getClassPath(), "PeerPublisher") ||
        StringUtils.contains(((CustomPublisherContainer) publisher).getClassPath(), "EnterpriseValidationAuthorityPublisher");
    }


    private boolean isStoreCrlPropertyUsed(final BasePublisher publisher) {
        return (publisher instanceof CustomPublisherContainer) && (
        StringUtils.contains(((CustomPublisherContainer) publisher).getClassPath(), "PeerPublisher") ||
        StringUtils.contains(((CustomPublisherContainer) publisher).getClassPath(), "ValidationAuthorityPublisher"));
    }
    
    
    @Override
    public boolean republishCrl(final AuthenticationToken admin, final Collection<Integer> publisherids, final String caFingerprint, final String issuerDn, final IntRange crlPartitionIndeces) throws AuthorizationDeniedException {
        boolean result = true;
        if(crlPartitionIndeces != null) {
            for (int crlPartitionIndex = crlPartitionIndeces.getMinimumInteger(); crlPartitionIndex <= crlPartitionIndeces.getMaximumInteger(); crlPartitionIndex++) {
                result &= republishCrlPartition(admin, publisherids, caFingerprint, issuerDn, crlPartitionIndex);
            }
            result &=  republishCrlPartition(admin, publisherids, caFingerprint, issuerDn, CertificateConstants.NO_CRL_PARTITION);
        } else {
            result = republishCrlPartition(admin, publisherids, caFingerprint, issuerDn, CertificateConstants.NO_CRL_PARTITION);
        }
        return result;
    }

    private boolean republishCrlPartition(final AuthenticationToken admin, final Collection<Integer> publisherids, final String caFingerprint, final String issuerDn, final int crlPartitionIndex) throws AuthorizationDeniedException {
        final byte[] crlbytes = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRL(issuerDn, crlPartitionIndex, false);
        boolean result = false;
        // Get the CRLnumber
        X509CRL crl;
        try {
            crl = CertTools.getCRLfromByteArray(crlbytes);
        } catch (CRLException e) {
            throw new IllegalStateException("Couldn't deserialize CRL", e);
        }
        int crlNumber = CrlExtensions.getCrlNumber(crl).intValue();
        if (crlbytes != null && crlbytes.length > 0 && crlNumber > 0) {
            log.info("Publishing CRL to CA publishers.");
            result = storeCRL(admin, publisherids, crlbytes, caFingerprint, crlNumber, issuerDn);
            log.info("CRL with number " + crlNumber + " published.");
        } else {
            log.info("CRL not published, no CRL exists for CA.");
        }
        return result;
    }

    @Override
    public void testConnection(int publisherId) throws PublisherConnectionException { // NOPMD: this is not a JUnit test
        if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + publisherId + ")");
        }
        final var dto = repository.findById(publisherId);
        if (dto == null) {
            String msg = intres.getLocalizedMessage("publisher.nopublisher", publisherId);
            log.info(msg);
        }
        else {
            try {
                getPublisher(dto).testConnection();
                String msg = intres.getLocalizedMessage("publisher.testedpublisher", dto.name());
                log.info(msg);
            } catch (PublisherConnectionException | FatalPublisherConnectionException e) {
                String msg = intres.getLocalizedMessage("publisher.errortestpublisher", dto.name());
                log.info(msg);
                throw new PublisherConnectionException(e.getMessage(), e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<testConnection(id: " + publisherId + ")");
        }
    }

    @Override
    public int addPublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws PublisherExistsException,
            AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ")");
        }
        int id = findFreePublisherId();
        addPublisher(admin, id, name, publisher);
        if (log.isTraceEnabled()) {
            log.trace("<addPublisher()");
        }
        return id;
    }

    @Override
    public void addPublisher(AuthenticationToken admin, int id, String name, BasePublisher publisher) throws PublisherExistsException,
            AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ", id: " + id + ")");
        }
        addPublisherInternal(admin, id, name, publisher);
        final String msg = intres.getLocalizedMessage("publisher.addedpublisher", name);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.PUBLISHER_CREATION, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                admin.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addPublisher()");
        }
    }

    @Override
    public void addPublisherFromData(AuthenticationToken admin, int id, String name, Map<?, ?> data) throws PublisherExistsException,
            AuthorizationDeniedException {
        final BasePublisher publisher = PublisherDataUtil.constructPublisher((Integer) (data.get(BasePublisher.TYPE)));
        if (publisher != null) {
            publisher.setPublisherId(id);
            publisher.setName(name);
            publisher.loadData(data);
            addPublisher(admin, id, name, publisher);
        }
    }

    private void putBasePublisher(PublisherData dto, BasePublisher publisher) {
        publisher.setPublisherId(dto.id());
        publisher.setName(dto.name());
        basePublisherMap.put(dto.id(), publisher);
    }

    private void addPublisherInternal(final AuthenticationToken admin, final int id, final String name, final BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException {
        authorizedToEditPublishers(admin);
        var dto = new PublisherDataBuilder()
                .setId(id)
                .setName(name)
                .setUpdateCounter(0)
                .build();
        dto = PublisherDataUtil.setPublisher(dto, publisher);
        try {
            repository.add(dto);
            putBasePublisher(dto, publisher);
        }
        catch (RecordIdAlreadyExistsException e) {
            throw new PublisherExistsException(intres.getLocalizedMessage("publisher.erroraddpublisher", id));
        }
        catch (RecordIndexAlreadyExistsException e) {
            throw new PublisherExistsException(intres.getLocalizedMessage("publisher.erroraddpublisher", name));
        }
    }

    List<PublisherData> setPublisherInDatabase(final int publisherId, final String name, final BasePublisher publisher) {
        final String publisherData = PublisherDataUtil.toString(publisher);
        final String selectSql = "SELECT bean FROM PublisherDataBean bean WHERE bean.id=:id";
        return repository.execute((em)-> {
            List<PublisherDataBean> originalBeans = em.createQuery(selectSql, PublisherDataBean.class)
                    .setParameter("id", publisherId)
                    .getResultList();
            if (originalBeans.isEmpty()) {
                return List.of();
            }
            final var bean = originalBeans.get(0);
            final PublisherData originalDto = PublisherDataConverter.INSTANCE.toDto(bean);
            bean.setName(name);
            bean.setData(publisherData);
            bean.setUpdateCounter(bean.getUpdateCounter() + 1);
            em.merge(bean);
            final PublisherData updatedDto = PublisherDataConverter.INSTANCE.toDto(bean);
            publisher.setName(name);
            return List.of(originalDto, updatedDto);
        });
    }

    @Override
    public void changePublisher(final AuthenticationToken admin, final String name, final BasePublisher publisher) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">changePublisher(name: " + name + ")");
        }

        final int publisherId = getPublisherId(name);
        changePublisher(admin, publisherId, name, publisher);

        if (log.isTraceEnabled()) {
            log.trace("<changePublisher()");
        }
    }

    @Override
    public void changePublisher(final AuthenticationToken admin, final int id, final String name, final BasePublisher publisher) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">changePublisher(id: " + id + ")");
        }
        authorizedToEditPublishers(admin);
        final List<PublisherData> publisherDataList = setPublisherInDatabase(id, name, publisher);
        if (publisherDataList.isEmpty()) {
            String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);
            log.info(msg);
        }
        else {
            final var originalDto = publisherDataList.get(0);
            final var updatedDto = publisherDataList.get(1);
            putBasePublisher(updatedDto, publisher);
            final var diff = XmlUtil.getDiff(
                    originalDto.data(),
                    updatedDto.data());
            final String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            for (Map.Entry<String, Object> entry : diff.entrySet()) {
                // Strip passwords from log
                final String key = entry.getKey().toString();
                String value = key.contains(LdapPublisher.LOGINPASSWORD) ?
                        "hidden" :
                        entry.getValue().toString();
                details.put(key, value);
            }
            auditSession.log(EjbcaEventTypes.PUBLISHER_CHANGE, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);

        }
        if (log.isTraceEnabled()) {
            log.trace("<changePublisher()");
        }
    }

    private PublisherDataBean getPublisherDataBeanByName(final EntityManager em, final String sql, final String name) {
        final var beans = em.createQuery(sql, PublisherDataBean.class)
                .setParameter("name", name)
                .getResultList();
        return beans.isEmpty() ?
                null :
                beans.get(0);
    }

    private void cloneDbBean(final String oldName, final String newName) {
        final var sql = "SELECT bean FROM PublisherDataBean bean WHERE bean.name=:name";
        repository.execute((em) -> {
            final int newId = findFreePublisherId();
            final PublisherDataBean originalBean = getPublisherDataBeanByName(em, sql, oldName);
            if (originalBean == null) {
                throw new RecordIndexDoesNotExistException("No publisher with name " + oldName + " found.");
            }
            final PublisherDataBean newBean = getPublisherDataBeanByName(em, sql, newName);
            if (newBean != null) {
                throw new RecordIndexAlreadyExistsException("There is already a publisher with the name " + newName + ".");
            }
            em.detach(originalBean);
            originalBean.setId(newId);
            originalBean.setName(newName);
            em.persist(originalBean);
            log.info("Cloning publisher: oldName=" + oldName + ", newId=" + newId + ", newName=" + newName);
            return null;
        });
    }

    @Override
    public void clonePublisher(final AuthenticationToken admin, final String oldName, final String newName) throws PublisherDoesntExistsException,
            AuthorizationDeniedException, PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">clonePublisher(name: " + oldName + ")");
        }
        authorizedToEditPublishers(admin);
        try {
            cloneDbBean(oldName, newName);
        }
        catch (RecordIndexDoesNotExistException e) {
            throw new PublisherDoesntExistsException(e.getMessage());
        }
        catch (RecordIndexAlreadyExistsException e) {
            throw new PublisherExistsException(e.getMessage());
        }
        finally {
            if (log.isTraceEnabled()) {
                log.trace("<clonePublisher()");
            }
        }
    }

    private Integer removeByName(final String name) {
        return repository.execute((em) -> {
            String sql = "DELETE FROM PublisherDataBean WHERE name=:name";
            return em.createQuery(sql)
                    .setParameter("name", name)
                    .executeUpdate();
        });
    }

    @Override
    public void removePublisherInternal(AuthenticationToken admin, String name) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">removePublisherInternal(name: " + name + ")");
        }
        authorizedToEditPublishers(admin);
        try {
            final var count = removeByName(name);
            if (count == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to remove a publisher that does not exist: " + name);
                }
            } else {
                final String msg = intres.getLocalizedMessage("publisher.removedpublisher", name);
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.PUBLISHER_REMOVAL, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorremovepublisher", name);
            log.info(msg, e);
        }
        log.trace("<removePublisherInternal()");
    }

    @Override
    public void removePublisher(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException, ReferencesToItemExistException {
        if (log.isTraceEnabled()) {
            log.trace(">removePublisher(name: " + name + ")");
        }
        checkPublisherInUse(name);
        removePublisherInternal(admin, name);
        log.trace("<removePublisher()");
    }

    /**
     * Checks if the given publisher is in use, and throws AuthorizationDeniedException with an informative error message if so. 
     * @param name Name of publisher
     * @throws ReferencesToItemExistException If in use by CAs, profiles or Multi Group Publishers.
     */
    private void checkPublisherInUse(final String name) throws ReferencesToItemExistException {
        final List<String> inUseBy = new ArrayList<>();
        Integer publisherId = getPublisherId(name);
        if (publisherId == null) {
            return;
        }
        if (caAdminSession.exitsPublisherInCAs(publisherId)) {
            inUseBy.add("one or more CAs");
        }
        if (certificateProfileSession.existsPublisherIdInCertificateProfiles(publisherId)) {
            inUseBy.add("one or more Certificate Profiles");
        }
        for (final Entry<Integer, BasePublisher> entry : getAllPublishersInternal().entrySet()) {
            final BasePublisher publisher = entry.getValue();
            if (publisher instanceof MultiGroupPublisher) {
                final List<TreeSet<Integer>> publisherGroups = ((MultiGroupPublisher) publisher).getPublisherGroups();
                for (final TreeSet<Integer> group : publisherGroups) {
                    if (group.contains(publisherId)) {
                        inUseBy.add("publisher '" + publisher.getName() + "'");
                        break;
                    }
                }
            }
        }

        if (!inUseBy.isEmpty()) {
            final String message = "Publisher " + name + " can't be deleted because it's in use by: " +
                    StringUtils.join(inUseBy, ", ");
            log.info(message);
            throw new ReferencesToItemExistException(message);
        }
    }

    private void verifyPublisherNameExists(EntityManager entityManager, final String name) throws RecordIndexDoesNotExistException {
        String selectSql = "SELECT bean FROM PublisherDataBean bean WHERE name=:name";
        List<PublisherDataBean> list = entityManager.createQuery(selectSql, PublisherDataBean.class)
                .setParameter("name", name)
                .getResultList();
        if (list.isEmpty()) {
            throw new RecordIndexDoesNotExistException("There is no publisher with the name " + name + ".");
        }
    }

    private void verifyPublisherNameDoesNotExist(EntityManager entityManager, final String name) throws RecordIndexAlreadyExistsException {
        String selectSql = "SELECT bean FROM PublisherDataBean bean WHERE name=:name";
        List<PublisherDataBean> list = entityManager.createQuery(selectSql, PublisherDataBean.class)
                .setParameter("name", name)
                .getResultList();
        if (!list.isEmpty()) {
            throw new RecordIndexAlreadyExistsException("There is already a publisher with the name " + name + ".");
        }
    }

    private void doRenamePublisher(final AuthenticationToken admin, final String oldName, final String newName) {
        final String selectSql = "SELECT bean FROM PublisherDataBean bean WHERE bean.name=:oldName";
        repository.execute((em) -> {
            verifyPublisherNameExists(em, oldName);
            verifyPublisherNameDoesNotExist(em, newName);
            final var bean = em.createQuery(selectSql, PublisherDataBean.class)
                    .setParameter("oldName", oldName)
                    .getSingleResult();
            bean.setName(newName);
            em.merge(bean);
            return null;
        });
        String msg = intres.getLocalizedMessage("publisher.renamedpublisher", oldName, newName);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.PUBLISHER_RENAME, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                admin.toString(), null, null, null, details);
    }

    @Override
    public void renamePublisher(final AuthenticationToken admin, final String oldName, final String newName) throws PublisherExistsException,
            AuthorizationDeniedException, PublisherDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renamePublisher(from " + oldName + " to " + newName + ")");
        }
        authorizedToEditPublishers(admin);
        try {
            doRenamePublisher(admin, oldName, newName);
        }
        catch (RecordIndexDoesNotExistException e) {
            String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldName, newName);
            log.info(msg);
            throw new PublisherDoesntExistsException(e.getMessage());
        }
        catch (RecordIndexAlreadyExistsException e) {
            String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldName, newName);
            log.info(msg);
            throw new PublisherExistsException(e.getMessage());
        }
        finally {
            if (log.isTraceEnabled()) {
                log.trace("<renamePublisher()");
            }
        }
    }
    
    @Override
    public Map<Integer, BasePublisher> getAllPublishersInternal() {
        final Map<Integer, BasePublisher> map = new HashMap<>();
        for (final var dto : findAll()) {
            final BasePublisher publisher = getPublisher(dto);
            map.put(dto.id(), publisher);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<PublisherData> findAll() {
        return repository.findAll();
    }

    @Override
    public Map<Integer, BasePublisher> getPublishersForPeer(final int peerId) {
        return findAll().stream()
                        .map(this::getPublisher)
                        .filter(CustomPublisherContainer.class::isInstance)
                        .map(CustomPublisherContainer.class::cast)
                        .filter(p -> p.getPeerId().equals(String.valueOf(peerId)))
                        .collect(Collectors.toMap(BasePublisher::getPublisherId, Function.identity()));
    }

    @Override
    public Map<Integer, BasePublisher> getAllPublishers() {
        final var dtoList = findAll();
        final Map<Integer, BasePublisher> map = new HashMap<>();
        for (final var dto : dtoList) {
            map.put(dto.id(), getPublisher(dto));
        }
        return map;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getPublisherIdToNameMap() {
        return findAll().stream()
                .collect(Collectors.toMap(
                        PublisherData::id,
                        PublisherData::name));
    }

    @Override
    public Map<String, Integer> getPublisherNameToIdMap() {
        return findAll().stream()
                .collect(Collectors.toMap(
                        PublisherData::name,
                        PublisherData::id));
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(String name) {
        final var dto = repository.findByIndex(name);
        return getPublisher(dto);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(int id) {
        return getPublisher(repository.findById(id));
    }

    @Override
    public PublisherData getPublisherData(final int id) {
        return repository.findById(id);
    }

    @Override
    public PublisherData getPublisherData(final String name) {
        return repository.findByIndex(name);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherUpdateCount(int id) {
        final var dto = repository.findById(id);
        return dto == null ?
                0 :
                dto.updateCounter();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherId(String name) {
        final var dto = repository.findByIndex(name);
        return dto == null ?
                0 :
                dto.id();
   }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getPublisherName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherName(id: " + id + ")");
        }
        final var dto = repository.findById(id);
        final var name = dto == null ?
                null :
                dto.name();
        if (log.isTraceEnabled()) {
            log.trace("<getPublisherName(): " + name);
        }
        return name;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<?, ?> getPublisherDataAsMap(int id) throws PublisherDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherDataAsMap(id: " + id + ")");
        }
        final var dto = repository.findById(id);
        if (dto == null) {
            if (log.isTraceEnabled()) {
                log.trace("<getPublisherDataAsMap(id: " + id + ")");
            }
            throw new PublisherDoesntExistsException("Publisher with id " + id + " doesn't exist");
        }
        else {
            final var basePublisher = getPublisher(dto);
            if (log.isTraceEnabled()) {
                log.trace("<getPublisherDataAsMap(id: " + id + ")");
            }
            return basePublisher.getRawData();
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String testAllConnections() {
        if (log.isTraceEnabled()) {
            log.trace(">testAllConnections");
        }
        StringBuilder stringBuilder = new StringBuilder(); 
        for (final var dto : findAll()) {
            String name = dto.name();
            try {
                getPublisher(dto).testConnection();
            } catch (PublisherConnectionException | FatalPublisherConnectionException pe) {
                String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
                log.info(msg);
                stringBuilder.append(msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<testAllConnections");
        }
        return stringBuilder.toString();
    }

    private int findFreePublisherId() {
        final ProfileID.DB db = (id) -> repository.findById(id) == null;
        return ProfileID.getNotUsedID(db);
    }

    private HashMap<?, ?> parseDataMapFromPublisher(final PublisherData dto) {
        final var xml = new PublisherDataConverter().toBean(dto).getData();
        try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))) {
            return (HashMap<?, ?>) decoder.readObject();
        } catch (IOException e) {
            final String msg = "Failed to parse PublisherData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + dto.data());
            }
            throw new IllegalStateException(msg, e);
        }
    }

    private BasePublisher getPublisher(final PublisherData dto) {
        if (dto == null) {
            return null;
        }
        return basePublisherMap.computeIfAbsent(dto.id(), k -> PublisherDataUtil.getPublisher(dto));
    }

    private void authorizedToEditPublishers(AuthenticationToken admin) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit publishers
        if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_EDITPUBLISHER)) {
            final String msg = intres.getLocalizedMessage("store.editpublishernotauthorized", admin.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    @Override
    public BasePublisher createPublisherObjectFromTypeId(final int typeId) {
        switch (typeId) {
        case PublisherConst.TYPE_ADPUBLISHER:
            return new ActiveDirectoryPublisher();
        case PublisherConst.TYPE_LDAPPUBLISHER:
            return new LdapPublisher();
        case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
            return new CustomPublisherContainer();
        case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
            return new LdapSearchPublisher();
        case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
            return new MultiGroupPublisher();
        default:
            throw new IllegalArgumentException("Invalid Publisher Type ID");
        }
    }

}
