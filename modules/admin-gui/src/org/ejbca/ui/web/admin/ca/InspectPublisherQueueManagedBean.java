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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the "Inspect Publisher Queue" page. 
 *
 * @version $Id$
 */
@ManagedBean(name = "inspectPublisherQueue")
@ViewScoped
public class InspectPublisherQueueManagedBean extends BaseManagedBean {
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

    private int pageNumber;
    private String publisherId;
    private boolean isLastPage;

    public InspectPublisherQueueManagedBean() {
        super(AccessRulesConstants.REGULAR_VIEWPUBLISHER);
    }
    
    /**
     * A publisher queue item, displayed as a row in the GUI.
     */
    public final class PublisherQueueItem {
        private final PublisherQueueData publisherQueueData;

        public PublisherQueueItem(PublisherQueueData data) {
            this.publisherQueueData = data;
        }

        public String getDescription() {
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CERT) {
                final CertificateInfo certificateInfo = certificateSession.getCertificateInfo(publisherQueueData.getFingerprint());
                if (isAuthorizedToViewCertificate(certificateInfo)) {
                    return StringUtils.abbreviate(getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_CERTIFICATE_DESCRIPTION", /* unescape */ false,
                            certificateInfo.getSubjectDN()), DESCRIPTION_MAX_LENGTH);
                } else {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NOT_AUTHORIZED");
                }
            } else if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final CRLInfo crlInfo = crlSession.getCRLInfo(getFingerprint());
                if (isAuthorizedToViewCrl(crlInfo)) {
                    return StringUtils.abbreviate(getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_CRL_DESCRIPTION", /* unescape */ false,
                            crlInfo.getLastCRLNumber(), crlInfo.getSubjectDN()), DESCRIPTION_MAX_LENGTH);
                } else {
                    return getEjbcaWebBean().getText("INSPECT_PUBLISHER_QUEUE_NOT_AUTHORIZED");
                }
            }
            return publisherQueueData.getFingerprint() + " (" + publisherQueueData.getPublishType() + ")";
        }

        public String getFingerprint() {
            return publisherQueueData.getFingerprint();
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
                    return String.format("%spublicweb/webdist/certdist?cmd=crl&issuer=%s&crlnumber=%d", getEjbcaWebBean().getBaseUrlPublic(),
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
            return new SimpleDateFormat("dd MMMM yyyy hh:mm:ss").format(publisherQueueData.getTimeCreated());
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
    }

    private boolean isAuthorizedToViewCertificate(final CertificateInfo certificateInfo) {
        if (!caSession.authorizedToCANoLogging(getAdmin(), CertTools.stringToBCDNString(certificateInfo.getIssuerDN()).hashCode())) {
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
        return caSession.authorizedToCANoLogging(getAdmin(), CertTools.stringToBCDNString(crlInfo.getSubjectDN()).hashCode());
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

    public List<PublisherQueueItem> getItems() {
        try {
            final int publisherId = Integer.parseInt(getPublisherId());
            final List<PublisherQueueItem> items = publisherQueueSession
                    .getPendingEntriesForPublisherWithLimitAndOffset(publisherId, MAX_RESULTS + 1, MAX_RESULTS * pageNumber)
                    .stream()
                    .map(data -> new PublisherQueueItem(data))
                    .collect(Collectors.toList());
            if (items.size() != MAX_RESULTS + 1) {
                isLastPage = true;
                return items;
            } else {
                isLastPage = false;
                items.remove(items.size() - 1);
                return items;
            }
        } catch (NumberFormatException e) {
            addNonTranslatedErrorMessage("The publisher ID must be an integer.");
            return new ArrayList<>();
        }
    }
}
