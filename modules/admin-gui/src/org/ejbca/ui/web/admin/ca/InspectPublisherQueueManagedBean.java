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

package org.ejbca.ui.web.admin.ca;

import static java.util.stream.Collectors.toSet;

import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ejb.EJB;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublishingResult;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.services.ServiceDataSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Backing bean for the "Inspect Publisher Queue" page.
 */
@Named("inspectPublisherQueue")
@ViewScoped
public class InspectPublisherQueueManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(InspectPublisherQueueManagedBean.class);
    private static final long serialVersionUID = 1L;
    private static final int MAX_RESULTS = 20;
    private static final int DESCRIPTION_MAX_LENGTH = 80;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private CertificateDataSessionLocal certificateSession;
    @EJB
    private CrlStoreSessionLocal crlSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private ServiceSessionLocal serviceSession;
    @EJB
    private ServiceDataSessionLocal serviceDataSession;

    @EJB
    private PublisherSessionLocal publisherSession;

    private int pageNumber;
    private String publisherId;
    private boolean isLastPage;

    public List<PublisherQueueItem> getItems() {
        return items;
    }

    private List<PublisherQueueItem> items = new ArrayList<>();
    private int successfullyPublishedItems;

    public InspectPublisherQueueManagedBean() {
        super(AccessRulesConstants.REGULAR_VIEWPUBLISHER);
    }

    /**
     * A publisher queue item, displayed as a row in the GUI.
     */
    public final class PublisherQueueItem {
        private final PublisherQueueData publisherQueueData;

        private boolean selected;

        public PublisherQueueItem(PublisherQueueData data) {
            this.publisherQueueData = data;
        }

        public String getDescription() {
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CERT) {
                final CertificateInfo certificateInfo = certificateSession.getCertificateInfo(publisherQueueData.getFingerprint());
                if (isAuthorizedToViewCertificate(certificateInfo)) {
                    return StringUtils.abbreviate(getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_CERTIFICATE_DESCRIPTION", false,
                            certificateInfo.getSubjectDN()), DESCRIPTION_MAX_LENGTH);
                } else if (certificateInfo == null) {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NONEXISTENT_ENTRY");
                } else {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NOT_AUTHORIZED");
                }
            } else if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final CRLInfo crlInfo = crlSession.getCRLInfo(getFingerprint());
                if (isAuthorizedToViewCrl(crlInfo)) {
                    return StringUtils.abbreviate(getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_CRL_DESCRIPTION", false,
                            crlInfo.getLastCRLNumber(), crlInfo.getSubjectDN()), DESCRIPTION_MAX_LENGTH);
                } else if (crlInfo == null) {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NONEXISTENT_ENTRY");
                } else {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NOT_AUTHORIZED");
                }
            }
            return publisherQueueData.getFingerprint() + " (" + publisherQueueData.getPublishType() + ")";
        }

        public String getFingerprint() {
            return publisherQueueData.getFingerprint();
        }

        public String getPrimaryKey() {
            return publisherQueueData.getPk();
        }

        public String getLink() {
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CERT) {
                final CertificateInfo certificateInfo = certificateSession.getCertificateInfo(getFingerprint());
                if (isAuthorizedToViewCertificate(certificateInfo)) {
                    return getEjbcaWebBean().getBaseUrl() + "ra/viewcert.xhtml?fp=" + publisherQueueData.getFingerprint();
                }
            } else if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final CRLInfo crlInfo = crlSession.getCRLInfo(getFingerprint());
                if (isAuthorizedToViewCrl(crlInfo)) {
                    return String.format("%spublicweb/webdist/certdist?cmd=crl&issuer=%s&crlnumber=%d", getEjbcaWebBean().getBaseUrl(),
                            StringEscapeUtils.escapeHtml(crlInfo.getSubjectDN()), crlInfo.getLastCRLNumber());
                }
            }
            return "#";
        }

        public String getStatus() {
            if (isStatusNotOk()) {
                return "Failed";
            } else if (isStatusPending()) {
                return "Pending...";
            } else if (isStatusOk()) {
                return "OK";
            } else {
                return "Unknown status " + publisherQueueData.getPublishStatus();
            }
        }

        public boolean isStatusOk() {
            return publisherQueueData.getPublishStatus() == PublisherConst.STATUS_SUCCESS;
        }

        public boolean isStatusPending() {
            return publisherQueueData.getPublishStatus() == PublisherConst.STATUS_PENDING;
        }

        public boolean isStatusNotOk() {
            return publisherQueueData.getPublishStatus() == PublisherConst.STATUS_FAILED;
        }

        public String getTimeCreated() {
            return new SimpleDateFormat("dd MMMM yyyy HH:mm:ss").format(publisherQueueData.getTimeCreated());
        }

        public String getTimeLastUpdated() {
            if (new Date(0L).equals(publisherQueueData.getLastUpdate())) {
                return "Never";
            } else {
                return new SimpleDateFormat("dd MMMM yyyy HH:mm:ss").format(publisherQueueData.getLastUpdate());
            }
        }

        public boolean isCanView() {
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CERT) {
                final CertificateInfo certificateInfo = certificateSession.getCertificateInfo(publisherQueueData.getFingerprint());
                return isAuthorizedToViewCertificate(certificateInfo);
            }
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final CRLInfo crlInfo = crlSession.getCRLInfo(getFingerprint());
                return isAuthorizedToViewCrl(crlInfo);
            }
            return true;
        }

        public boolean isSelected() {
            return selected;
        }

        public void setSelected(boolean selected) {
            this.selected = selected;
        }
    }

    private boolean isAuthorizedToViewCertificate(final CertificateInfo certificateInfo) {
        if (certificateInfo == null) {
            return false;
        }
        if (!caSession.authorizedToCANoLogging(getAdmin(), DnComponents.stringToBCDNString(certificateInfo.getIssuerDN()).hashCode())) {
            return false;
        }
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(),
                AccessRulesConstants.VIEW_END_ENTITY);
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        if (authorizedEepIds.contains(EndEntityConstants.EMPTY_END_ENTITY_PROFILE)) {
            authorizedEepIds.add(EndEntityConstants.NO_END_ENTITY_PROFILE);
        }
        if (!accessAnyEepAvailable && !authorizedEepIds.contains(Integer.valueOf(certificateInfo.getEndEntityProfileIdOrZero()))) {
            return false;
        }
        return true;
    }

    private boolean isAuthorizedToViewCrl(final CRLInfo crlInfo) {
        if (crlInfo == null) {
            return false;
        }
        return caSession.authorizedToCANoLogging(getAdmin(), DnComponents.stringToBCDNString(crlInfo.getSubjectDN()).hashCode());
    }

    /**
     * Get a message describing why the publisher queue process service cannot run.
     *
     * @return an error message or null if the service can run.
     */
    public String getReasonWhyPublisherQueueProcessQueueCannotRun() {
        if (!getStreamOfPublishers().findFirst().isPresent()) {
            return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NO_SERVICE");
        }
        if (!getStreamOfPublishers().filter(x -> x.getValue().isActive()).findFirst().isPresent()) {
            return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_SERVICE_DISABLED");
        }
        return null;
    }

    public String getPublisherId() {
        return this.publisherId;
    }

    public void setPublisherId(final String publisherId) {
        this.publisherId = publisherId;
    }

    public String nextPage() {
        pageNumber++;
        return "";
    }

    public String previousPage() {
        pageNumber--;
        return "";
    }

    public boolean isFirstPage() {
        return pageNumber == 0;
    }

    public boolean isLastPage() {
        return this.isLastPage;
    }

    public String republishAll() {
        final Integer publisherId = getPublisherIdInteger();
        if (publisherId == null) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return "";
        }
        log.info("Attempting to republish items in the queue with publisher ID " + publisherId + ".");
        final Optional<Integer> idOfPublisherQueueProcessService = getStreamOfPublishers().filter(
                entry -> entry.getValue().isActive()).map(entry -> entry.getKey()).findFirst();
        if (!idOfPublisherQueueProcessService.isPresent()) {
            log.error(getReasonWhyPublisherQueueProcessQueueCannotRun());
            return "";
        }
        log.info("Scheduling timer for PublishQueueProcessWorker with ID " + idOfPublisherQueueProcessService.get()
                + ".");
        serviceSession.runService(idOfPublisherQueueProcessService.get());
        addInfoMessage("INSPECT_PUBLISHER_QUEUE_STARTED_SERVICE",
                serviceSession.getServiceName(idOfPublisherQueueProcessService.get()));
        return "";
    }

    public String republishSelected() {
        final Integer publisherId = getPublisherIdInteger();
        if (publisherId == null) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return "";
        }
        final List<PublisherQueueItem> selectedItems = items.stream().filter(PublisherQueueItem::isSelected).collect(Collectors.toList());
        if (selectedItems.size() > MAX_RESULTS) {
            addNonTranslatedErrorMessage("Too many items selected.");
            return "";
        }
        log.info("Attempting to republish items with fingerprints " + selectedItems.stream()
                .map(PublisherQueueItem::getFingerprint).collect(Collectors.joining(", "))
                + " in the queue with publisher ID " + publisherId + ".");
        final AuthenticationToken admin = getAdmin();
        final BasePublisher publisher = publisherSession.getAllPublishers().get(publisherId);
        successfullyPublishedItems = 0;
        selectedItems.forEach(item -> republishItem(admin, publisher, item));
        if (successfullyPublishedItems != 0) {
            addInfoMessage("INSPECT_PUBLISHER_QUEUE_REPUBLISHED_ITEMS", successfullyPublishedItems);
        }
        return "";
    }

    private void addRepublishErrorMessage(final PublisherQueueItem item, final String message, final Throwable e) {
        final String logMessage = "Re-publishing of item with fingerprint " + item.getFingerprint() + " (" + item.getDescription() + ") failed";
        if (e == null) {
            log.error(logMessage);
        } else {
            log.error(logMessage + ": " + e.getMessage(), e);
        }
        addErrorMessage("INSPECT_PUBLISHER_QUEUE_REPUBLISH_ERROR", item.getFingerprint(), item.getDescription(),
                message);
    }

    private void republishItem(final AuthenticationToken admin, final BasePublisher publisher, final PublisherQueueItem item) {
        try {
            final PublishingResult result = publisherQueueSession.publishQueueData(admin, item.getPrimaryKey(), publisher);
            if (result == null) {
                addRepublishErrorMessage(item, "Queued item could not be found in database", null);
            } else if (result.getSuccesses() == 0) {
                addRepublishErrorMessage(item, result.getMessage(item.getFingerprint()), null);
            } else {
                successfullyPublishedItems++;
            }
        } catch (RuntimeException e) {
            addRepublishErrorMessage(item, ExceptionUtils.getRootCause(e).getMessage(), e);
        }
    }

    public String flushAll() {
        final Integer publisherId = getPublisherIdInteger();
        if (publisherId == null) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return "";
        }
        log.info("Attempting to flush items in the queue with publisher ID " + publisherId + ".");
        publisherQueueSession.removeQueueDataByPublisherId(publisherId);
        return "";
    }

    public String flushSelected() {
        final Integer publisherId = getPublisherIdInteger();
        if (publisherId == null) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return "";
        }
        final List<PublisherQueueItem> selectedItems = items.stream().filter(PublisherQueueItem::isSelected).collect(Collectors.toList());
        if (selectedItems.size() > MAX_RESULTS) {
            addNonTranslatedErrorMessage("Too many items selected.");
            return "";
        }
        log.info("Attempting to flush items with fingerprints " + selectedItems.stream()
                .map(PublisherQueueItem::getFingerprint).collect(Collectors.joining(", "))
                + " in the queue with publisher ID " + publisherId + ".");
        selectedItems.forEach(item -> publisherQueueSession.removeQueueData(item.getPrimaryKey()));
        return "";
    }

    private Stream<AbstractMap.SimpleEntry<Integer, ServiceConfiguration>> getStreamOfPublishers() {
        return serviceSession
            .getServiceIdToNameMap()
            .entrySet()
            .stream()
            .map(idToName -> new AbstractMap.SimpleEntry<>(idToName.getKey(), serviceSession.getService(idToName.getValue())))
            .filter(entry -> entry.getValue().getWorkerClassPath().endsWith("PublishQueueProcessWorker"))
            .filter(entry -> getSelectedPublisherIdsFor(entry.getValue()).contains(getPublisherId()));
    }

    private Set<String> getSelectedPublisherIdsFor(final ServiceConfiguration serviceConfiguration) {
        final String selectedPublishersString = (String) serviceConfiguration.getWorkerProperties().get(PublishQueueProcessWorker.PROP_PUBLISHER_IDS);
        return Arrays.stream(selectedPublishersString.split(";")).collect(toSet());
    }

	public List<PublisherQueueItem> getItemsForCurrentPage() {
        final Integer publisherId = getPublisherIdInteger();
        if (publisherId == null) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return new ArrayList<>();
        }
        List<PublisherQueueItem> retValues = publisherQueueSession.getPendingEntriesForPublisherWithLimitAndOffset(
                        publisherId, MAX_RESULTS + 1, MAX_RESULTS * pageNumber).stream().map(PublisherQueueItem::new)
                .collect(Collectors.toList());
        if (retValues.size() != MAX_RESULTS + 1) {
            isLastPage = true;
        } else {
            isLastPage = false;
            retValues.remove(retValues.size() - 1);
        }
        items = retValues;
        return retValues;
	}

    private Integer getPublisherIdInteger() {
        try {
            return Integer.parseInt(getPublisherId());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
