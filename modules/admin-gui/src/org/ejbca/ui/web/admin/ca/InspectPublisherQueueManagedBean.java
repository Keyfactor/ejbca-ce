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
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the "Inspect Publisher Queue" page. 
 *
 * @version $Id $
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

    private int pageNumber;
    private String publisherId;
    private boolean isLastPage;

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
                final CertificateInfo certificate = certificateSession.getCertificateInfo(publisherQueueData.getFingerprint());
                return StringUtils.abbreviate("Certificate: '" + certificate.getSubjectDN() + "'", DESCRIPTION_MAX_LENGTH);
            } else if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final int crlNumber = crlSession.getCRLInfo(publisherQueueData.getFingerprint()).getLastCRLNumber();
                final String crlIssuer = crlSession.getCRLInfo(publisherQueueData.getFingerprint()).getSubjectDN();
                return StringUtils.abbreviate(String.format("CRL: #%d. Issued by '%s'", crlNumber, crlIssuer), DESCRIPTION_MAX_LENGTH);
            } else {
                return publisherQueueData.getFingerprint() + " (" + publisherQueueData.getPublishType() + ")";
            }
        }

        public String getFingerprint() {
            return publisherQueueData.getFingerprint();
        }

        public String getLink() {
            if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CERT) {
                return getEjbcaWebBean().getBaseUrl() + "ra/viewcert.xhtml?fp=" + publisherQueueData.getFingerprint();
            } else if (publisherQueueData.getPublishType() == PublisherConst.PUBLISH_TYPE_CRL) {
                final CRLInfo crlInfo = crlSession.getCRLInfo(getFingerprint());
                return String.format("%spublicweb/webdist/certdist?cmd=crl&issuer=%s&crlnumber=%d", getEjbcaWebBean().getBaseUrlPublic(),
                        StringEscapeUtils.escapeHtml(crlInfo.getSubjectDN()), crlInfo.getLastCRLNumber());
            } else {
                return "#";
            }
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
                return new SimpleDateFormat("dd MMMM yyyy hh:mm:ss").format(publisherQueueData.getLastUpdate());
            }
        }
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
