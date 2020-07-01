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
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.commons.collections.CollectionUtils;
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
import org.cesecore.jndi.JndiConstants;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ProfileID;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.FatalPublisherConnectionException;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.LegacyValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Handles management of Publishers.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublisherSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherSessionBean implements PublisherSessionLocal, PublisherSessionRemote {

    private static final Logger log = Logger.getLogger(PublisherSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

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

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushPublisherCache() {
        PublisherCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed Publisher cache.");
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
        final int revocationReason = certificateData.getRevocationReason();
        final String username = certificateData.getUsername();
        boolean returnval = true;
        final List<BasePublisher> publishersToTryDirect = new ArrayList<>();
        final List<BasePublisher> publishersToQueuePending = new ArrayList<>();
        final List<BasePublisher> publishersToQueueSuccess = new ArrayList<>();
        for (final Integer id : publisherids) {
            BasePublisher publ = getPublisherInternal(id, null, true);
            if (publ != null) {
                // If the publisher will not publish the certificate, break out directly and do not call the publisher or queue the certificate
                if (publ.willPublishCertificate(status, revocationReason)) {
                    if (publ.getOnlyUseQueue()) {
                        if (publ.getUseQueueForCertificates()) {
                            publishersToQueuePending.add(publ);
                            // Publishing to the queue directly is not considered a successful write to the publisher (since we don't know that it will be)
                            returnval = false;
                        } else {
                            // NOOP: This publisher is configured to only write to the queue, but not for certificates
                        }
                    } else {
                        publishersToTryDirect.add(publ);
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
            final int id = publ.getPublisherId();
            final String name = getPublisherName(id);
            if (!(publisherResult instanceof PublisherException)) {
                // If it wasn't an exception, it's a Boolean, but check it anyhow to avoid any chance of exception
                Boolean result = false;
                if (publisherResult instanceof Boolean) {
                    result = (Boolean)publisherResult;
                } else {
                    log.error("Return type from storeCertificateNonTransactionalInternal was not a Boolean but a " + result.getClass().getName() + ", this is an API error.");
                }
                final String msg = intres.getLocalizedMessage("publisher.store", certificateData.getSubjectDnNeverNull(), name, result);
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
                details.put("error", ((PublisherException) publisherResult).getMessage());
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
                publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_CERT, fingerprint, pqvd, publisherStatus);
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
        int caid = CertTools.stringToBCDNString(issuerDn).hashCode();
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }

        boolean returnval = true;
        for (Integer id : publisherids) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            final BasePublisher publ = getPublisherInternal(id, null, true);
            if (publ != null) {
                final String name = getPublisherName(id);
                // If it should be published directly
                if (!publ.getOnlyUseQueue()) {
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
                        final String msg = intres.getLocalizedMessage("publisher.store", "CRL", name, publishStatus);
                        final Map<String, Object> details = new LinkedHashMap<>();
                        details.put("msg", msg);
                        auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CRL, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER,
                                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
                    } catch (PublisherException pe) {
                        final String msg = intres.getLocalizedMessage("publisher.errorstore", name, "CRL");
                        final Map<String, Object> details = new LinkedHashMap<>();
                        details.put("msg", msg);
                        details.put("error", pe.getMessage());
                        auditSession.log(EjbcaEventTypes.PUBLISHER_STORE_CRL, EventStatus.FAILURE, EjbcaModuleTypes.PUBLISHER,
                                EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
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
                        publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_CRL, fp, pqvd, publishStatus);
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
            BasePublisher publ = getPublisherInternal(id, null, true);
            if (publ != null) {
                final String name = getPublisherName(id);
                // If it should be published directly
                if (!publ.getOnlyUseQueue()) {
                    try {
                        
                        if (isOcspResponsePublisher(publ) && publisherQueueSession
                                .publishOcspResponsesNonTransactional((CustomPublisherContainer) publ, admin, ocspResponseData)) {
                            
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
                    return false;
                }
                
                if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                    return false;
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
            publisherQueueSession.addQueueData(id, PublisherConst.PUBLISH_TYPE_OCSP_RESPONSE, responseId, pqvd, publishStatus);
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
        final byte[] crlbytes = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRL(issuerDn,
                crlPartitionIndex, false);
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
    public void testConnection(int publisherid) throws PublisherConnectionException { // NOPMD: this is not a JUnit test
        if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + publisherid + ")");
        }
        PublisherData pdl = PublisherData.findById(entityManager, publisherid);
        if (pdl != null) {
            String name = pdl.getName();
            try {
                getPublisher(pdl).testConnection();
                String msg = intres.getLocalizedMessage("publisher.testedpublisher", name);
                log.info(msg);
            } catch (PublisherConnectionException | FatalPublisherConnectionException pe) {
                String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
                log.info(msg);
                throw new PublisherConnectionException(pe.getMessage(), pe);
            }
        } else {
            String msg = intres.getLocalizedMessage("publisher.nopublisher", publisherid);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<testConnection(id: " + publisherid + ")");
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
        final BasePublisher publisher = constructPublisher((Integer) (data.get(BasePublisher.TYPE)));
        if (publisher != null) {
            publisher.setPublisherId(id);
            publisher.setName(name);
            publisher.loadData(data);
            addPublisher(admin, id, name, publisher);
        }
    }

    private void addPublisherInternal(AuthenticationToken admin, int id, String name, BasePublisher publisher) throws AuthorizationDeniedException,
            PublisherExistsException {
        authorizedToEditPublishers(admin);
        if (PublisherData.findByName(entityManager, name) == null) {
            if (PublisherData.findById(entityManager, id) == null) {
                entityManager.persist(new PublisherData(id, name, publisher));
            } else {
                final String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", id);
                log.info(msg);
                throw new PublisherExistsException();
            }
        } else {
            final String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);
            log.info(msg);
            throw new PublisherExistsException();
        }
    }

    @Override
    public void changePublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">changePublisher(name: " + name + ")");
        }
        authorizedToEditPublishers(admin);

        PublisherData htp = PublisherData.findByName(entityManager, name);
        if (htp != null) {
            final Map<Object, Object> diff = getPublisher(htp).diff(publisher);
            htp.setPublisher(publisher);
            // Since loading a Publisher is quite complex, we simple purge the cache here
            PublisherCache.INSTANCE.removeEntry(htp.getId());
            final String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                // Strip passwords from log
                final String key = entry.getKey().toString();
                String value = entry.getValue().toString();
                if (key.contains(LdapPublisher.LOGINPASSWORD)) {
                    value = "hidden";
                }
                details.put(key, value);
            }
            auditSession.log(EjbcaEventTypes.PUBLISHER_CHANGE, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changePublisher()");
        }
    }

    @Override
    public void clonePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherDoesntExistsException,
            AuthorizationDeniedException, PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">clonePublisher(name: " + oldname + ")");
        }
        BasePublisher publisherdata = null;
        PublisherData htp = PublisherData.findByName(entityManager, oldname);
        if (htp == null) {
            throw new PublisherDoesntExistsException("Could not find publisher " + oldname);
        }
        try {
            publisherdata = (BasePublisher) getPublisher(htp).clone();
            addPublisherInternal(admin, findFreePublisherId(), newname, publisherdata);
            final String msg = intres.getLocalizedMessage("publisher.clonedpublisher", newname, oldname);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.PUBLISHER_CREATION, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } catch (PublisherExistsException f) {
            final String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);
            log.info(msg);
            throw f;
        } catch (CloneNotSupportedException e) {
            // Severe error, should never happen
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<clonePublisher()");
        }
    }

    @Override
    public void removePublisherInternal(AuthenticationToken admin, String name) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">removePublisherInternal(name: " + name + ")");
        }
        authorizedToEditPublishers(admin);
        try {
            PublisherData htp = PublisherData.findByName(entityManager, name);
            if (htp == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to remove a publisher that does not exist: " + name);
                }
            } else {
                entityManager.remove(htp);
                // Purge the cache here
                PublisherCache.INSTANCE.removeEntry(htp.getId());
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
        int publisherId = getPublisherId(name);
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

    @Override
    public void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException,
            AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">renamePublisher(from " + oldname + " to " + newname + ")");
        }
        authorizedToEditPublishers(admin);
        boolean success = false;
        if (PublisherData.findByName(entityManager, newname) == null) {
            PublisherData htp = PublisherData.findByName(entityManager, oldname);
            if (htp != null) {
                htp.setName(newname);
                success = true;
                // Since loading a Publisher is quite complex, we simple purge the cache here
                PublisherCache.INSTANCE.removeEntry(htp.getId());
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("publisher.renamedpublisher", oldname, newname);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.PUBLISHER_RENAME, EventStatus.SUCCESS, EjbcaModuleTypes.PUBLISHER, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldname, newname);
            log.info(msg);
            throw new PublisherExistsException();
        }
        if (log.isTraceEnabled()) {
            log.trace("<renamePublisher()");
        }
    }
    
    @Override
    public Map<Integer, BasePublisher> getAllPublishersInternal() {
        final Map<Integer, BasePublisher> returnval = new HashMap<>();
        for (PublisherData publisherData : findAll()) {
            final BasePublisher publisher = getPublisher(publisherData);
            returnval.put(publisherData.getId(), publisher);
        }
        return returnval;
    }
    
    @Override
    public List<PublisherData> findAll() {
        final TypedQuery<PublisherData> query = entityManager.createQuery("SELECT a FROM PublisherData a", PublisherData.class);
        return query.getResultList();
    }

    @Override
    public Map<Integer, BasePublisher> getPublishersForPeer(int peerId) {
        return findAll().stream()
                        .map(publisherData -> getPublisher(publisherData))
                        .filter(CustomPublisherContainer.class::isInstance)
                        .map(CustomPublisherContainer.class::cast)
                        .filter(p -> p.getPeerId().equals(String.valueOf(peerId)))
                        .collect(Collectors.toMap(BasePublisher::getPublisherId, Function.identity()));

    }

    @Override
    public Map<Integer, BasePublisher> getAllPublishers() {
        final Map<Integer, BasePublisher> returnval = new HashMap<>();
        final boolean enabled = ((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        BasePublisher publisher = null;
        for (PublisherData publisherData : findAll()) {
            publisher = getPublisher(publisherData);
            if (publisher != null && enabled || !GeneralPurposeCustomPublisher.class.getName().equals(publisher.getRawData().get(CustomPublisherContainer.CLASSPATH))) {
                returnval.put(publisherData.getId(), publisher);
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer, String> getPublisherIdToNameMap() {
        final HashMap<Integer, String> returnval = new HashMap<>();
        final boolean enabled = ((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        BasePublisher publisher = null;
        for (PublisherData publisherData : findAll()) {
            publisher = getPublisher(publisherData);
            if (enabled || !GeneralPurposeCustomPublisher.class.getName().equals(publisher.getRawData().get(CustomPublisherContainer.CLASSPATH))) {
                returnval.put(publisherData.getId(), publisherData.getName());
            }
        }
        return returnval;
    }

    @Override
    public HashMap<String, Integer> getPublisherNameToIdMap() {
        final HashMap<String, Integer> returnval = new HashMap<>();
        final boolean enabled = ((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableExternalScripts();
        BasePublisher publisher;
        for (PublisherData publisherData : findAll()) {
            publisher = getPublisher(publisherData);
            if (enabled || !GeneralPurposeCustomPublisher.class.getName().equals(publisher.getRawData().get(CustomPublisherContainer.CLASSPATH))) {
                returnval.put(publisherData.getName(), publisherData.getId());
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(String name) {
        return getPublisherInternal(-1, name, true);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public BasePublisher getPublisher(int id) {
        return getPublisherInternal(id, null, true);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherUpdateCount(int publisherid) {
        int returnval = 0;
        PublisherData pd = PublisherData.findById(entityManager, publisherid);
        if (pd != null) {
            returnval = pd.getUpdateCounter();
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getPublisherId(String name) {
        // Get publisher to ensure it is in the cache, or read
        final BasePublisher pub = getPublisherInternal(-1, name, true);
        final int ret = (pub != null) ? pub.getPublisherId() : 0;
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getPublisherName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherName(id: " + id + ")");
        }
        // Get publisher to ensure it is in the cache, or read
        final BasePublisher pub = getPublisherInternal(id, null, true);
        final String ret = (pub != null) ? pub.getName() : null;
        if (log.isTraceEnabled()) {
            log.trace("<getPublisherName(): " + ret);
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<?, ?> getPublisherData(int id) throws PublisherDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherData(id: " + id + ")");
        }

        final BasePublisher pub = getPublisherInternal(id, null, true);
        if (pub == null) {
            throw new PublisherDoesntExistsException("Publisher with id " + id + " doesn't exist");
        }
        return (Map<?, ?>) pub.saveData();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String testAllConnections() {
        if (log.isTraceEnabled()) {
            log.trace(">testAllConnections");
        }
        StringBuilder stringBuilder = new StringBuilder(); 
        for(PublisherData pdl : findAll()) {
            String name = pdl.getName();
            try {
                getPublisher(pdl).testConnection();
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
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return PublisherData.findById(PublisherSessionBean.this.entityManager, i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /**
     * Internal method for getting Publisher, to avoid code duplication. Tries to find the Publisher even if the id is wrong due to CA certificate DN not being
     * the same as CA DN. Uses PublisherCache directly if configured to do so.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param id
     *            numerical id of Publisher that we search for, or -1 if a name is to be used instead
     * @param name
     *            human readable name of Publisher, used instead of id if id == -1, can be null if id != -1
     * @param fromCache if we should use the cache or return a new, decoupled, instance from the database, to be used when you need
     *             a completely distinct object, for edit, and not a shared cached instance.
     * @return BasePublisher value object or null if it does not exist
     */
    private BasePublisher getPublisherInternal(int id, final String name, boolean fromCache) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherInternal: " + id + ", " + name);
        }
        Integer idValue = id;
        if (id == -1) {
            idValue = PublisherCache.INSTANCE.getNameToIdMap().get(name);
        }
        BasePublisher returnval = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && idValue != null && !PublisherCache.INSTANCE.shouldCheckForUpdates(idValue)) {
            // Get from cache (or null)
            returnval = PublisherCache.INSTANCE.getEntry(idValue);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (returnval == null) {
            if (log.isDebugEnabled()) {
                log.debug("Publisher with ID " + idValue + " and/or name '" + name + "' will be checked for updates.");
            }
            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            PublisherData pd = null;
            if (name != null) {
                pd = PublisherData.findByName(entityManager, name);
            } else if (idValue != null) {
                pd = PublisherData.findById(entityManager, idValue);
            }
            if (pd != null) {
                returnval = getPublisher(pd);
                final int digest = pd.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                PublisherCache.INSTANCE.updateWith(pd.getId(), digest, pd.getName(), returnval);
            } else {
                // Ensure that it is removed from cache if it exists
                if (idValue != null) {
                    PublisherCache.INSTANCE.removeEntry(idValue);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getPublisherInternal: " + id + ", " + name + ": " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }
    
    private HashMap<?, ?> parseDataMapFromPublisher(final PublisherData publisherData) {
        final String data = publisherData.getData();
        try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)))) {
            return (HashMap<?, ?>) decoder.readObject();
        } catch (IOException e) {
            final String msg = "Failed to parse PublisherData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + data);
            }
            throw new IllegalStateException(msg, e);
        }
    }

    /** @return the publisher data and updates it if necessary. */
    private BasePublisher getPublisher(final PublisherData pData) {
        BasePublisher publisher = pData.getCachedPublisher();
        if (publisher == null) {
            HashMap<?, ?> h = parseDataMapFromPublisher(pData);
            // Handle Base64 encoded string values
            HashMap<?, ?> data = new Base64GetHashMap(h);

            publisher = constructPublisher((Integer) (data.get(BasePublisher.TYPE)));
            if (publisher != null) {
                publisher.setPublisherId(pData.getId());
                publisher.setName(pData.getName());
                publisher.loadData(data);
            }
        }
        return publisher;
    }

    @SuppressWarnings("deprecation")
    private BasePublisher constructPublisher(final int publisherType) {
        switch (publisherType) {
        case PublisherConst.TYPE_LDAPPUBLISHER:
            return new LdapPublisher();
        case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
            return new LdapSearchPublisher();
        case PublisherConst.TYPE_ADPUBLISHER:
            return new ActiveDirectoryPublisher();
        case PublisherConst.TYPE_VAPUBLISHER:
            //Attempt to create the legacy publisher if available, if not return null. 
            try {
                return (BasePublisher) Class.forName(LegacyValidationAuthorityPublisher.OLD_VA_PUBLISHER_QUALIFIED_NAME).newInstance();
            } catch (InstantiationException e) {
                return null;
            } catch (IllegalAccessException e) {
                return null;
            } catch (ClassNotFoundException e) {
                return null;
            }
        case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
            return new MultiGroupPublisher();
        case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
            return new CustomPublisherContainer();
        default:
            throw new IllegalStateException("Invalid or unimplemented publisher type " + publisherType);
        }
    }

    private void authorizedToEditPublishers(AuthenticationToken admin) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit publishers
        if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_EDITPUBLISHER)) {
            final String msg = intres.getLocalizedMessage("store.editpublishernotauthorized", admin.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public int adhocUpgradeTo6_3_1_1() {
        int numberOfUpgradedPublishers = 0;
        for (PublisherData publisherData : findAll()) {
            // Extract the data payload instead of the BasePublisher since the original BasePublisher implementation might no longer
            // be on the classpath
            HashMap<?, ?> h = parseDataMapFromPublisher(publisherData);
            // Handle Base64 encoded string values
            @SuppressWarnings("unchecked")
            HashMap<Object, Object> data = new Base64GetHashMap(h);
            if (PublisherConst.TYPE_VAPUBLISHER == (Integer) data.get(BasePublisher.TYPE)) {
                numberOfUpgradedPublishers++;
                publisherData.setPublisher(new LegacyValidationAuthorityPublisher(data));
                //Purge the entry from the cache
                PublisherCache.INSTANCE.removeEntry(publisherData.getId());
            }           
        }
        return numberOfUpgradedPublishers;
    }

    @SuppressWarnings("deprecation")
    @Override
    public boolean isOldVaPublisherPresent() {
        for (PublisherData publisherData : findAll()) {
            // Extract the data payload instead of the BasePublisher since the original BasePublisher implementation might no longer
            // be on the classpath
            HashMap<?, ?> h = parseDataMapFromPublisher(publisherData);
            // Handle Base64 encoded string values
            @SuppressWarnings("unchecked")
            HashMap<Object, Object> data = new Base64GetHashMap(h);
            if (PublisherConst.TYPE_VAPUBLISHER == (Integer) data.get(BasePublisher.TYPE)) {
                return true;
            }           
        }
        return false;
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
