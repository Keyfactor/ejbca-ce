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
package org.ejbca.ui.web.admin;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.primefaces.model.FilterMeta;
import org.primefaces.model.LazyDataModel;
import org.primefaces.model.SortMeta;

/**
 *  JSF Managed Bean or the index page in the Admin GUI.
 *
 */
@Named
@ViewScoped
public class AdminIndexMBean extends CheckAdmin implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AdminIndexMBean.class);

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;

    private LazyDataModel<CaCrlStatusInfo> caCrlStatusModel;

    @PostConstruct
    public void init() {
        caCrlStatusModel = new CaCrlStatusLazyDataModel();
    }

    public LazyDataModel<CaCrlStatusInfo> getCaCrlStatusModel() {
        return caCrlStatusModel;
    }

    /** Backing object for main page list of CA and CRL statuses. */
    public static class CaCrlStatusInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String caName;
        private final boolean caService;
        private final boolean crlStatus;
        public CaCrlStatusInfo(final String caName, final boolean caService, final boolean crlStatus) {
            this.caName = caName;
            this.caService = caService;
            this.crlStatus = crlStatus;
        }
        public String getCaName() { return caName; }
        public boolean isCaService() { return caService; }
        public boolean isCrlStatus() { return crlStatus; }
    }

    private static class CaCrlStatusInfoComparator implements Comparator<CaCrlStatusInfo>, Serializable {
        private static final long serialVersionUID = 1L;
        @Override
        public int compare(CaCrlStatusInfo o1, CaCrlStatusInfo o2) {
            return o1.getCaName().compareToIgnoreCase(o2.getCaName());
        }
    }

    public class CaCrlStatusLazyDataModel extends LazyDataModel<CaCrlStatusInfo> {
        private static final long serialVersionUID = 1L;
        private List<CaCrlStatusInfo> caCrlStatusInfo;

        @Override
        public int count(Map<String, FilterMeta> filterBy) {
            try {
                return getAuthorizedInternalCaCrlStatusInfos().size();
            } catch (Exception e) {
                log.error("Failed to count CA CRL status infos", e);
                return 0;
            }
        }

        @Override
        public List<CaCrlStatusInfo> load(int first, int pageSize, Map<String, SortMeta> sortBy, Map<String, FilterMeta> filterBy) {
            try {
                caCrlStatusInfo = getAuthorizedInternalCaCrlStatusInfos();
                int to = first + pageSize;
                if (to > caCrlStatusInfo.size()) {
                    to = caCrlStatusInfo.size();
                }
                return caCrlStatusInfo.subList(first, to);
            } catch (Exception e) {
                log.error("Failed to load CA CRL status infos lazily", e);
                return Collections.emptyList();
            }
        }

        @Override
        public String getRowKey(CaCrlStatusInfo object) {
            return object.getCaName();
        }

        @Override
        public CaCrlStatusInfo getRowData(String rowKey) {
            if (caCrlStatusInfo == null) {
                try {
                    caCrlStatusInfo = getAuthorizedInternalCaCrlStatusInfos();
                } catch (Exception e) {
                    log.error("Failed to load caCrlStatusInfo in getRowData", e);
                    return null;
                }
            }
            for (CaCrlStatusInfo info : caCrlStatusInfo) {
                if (info.getCaName().equals(rowKey)) {
                    return info;
                }
            }
            return null;
        }
    }
    
    public AdminIndexMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR);
    }

    public List<CaCrlStatusInfo> getAuthorizedInternalCaCrlStatusInfos() throws Exception {
        final List<CaCrlStatusInfo> ret = new ArrayList<>();
        final Collection<Integer> caIds = caSession.getAuthorizedCaIds(getAdmin());
        for (final Integer caId : caIds) {
            final CAInfo cainfo = caSession.getCAInfoInternal(caId);
            if (cainfo == null || cainfo.getStatus() == CAConstants.CA_EXTERNAL || cainfo.getCAType() == CAInfo.CATYPE_PROXY) {
                continue;
            }
            final String caName = cainfo.getName();
            boolean caTokenStatus = false;
            final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
            try {
                caTokenStatus = cryptoTokenManagementSession.isCryptoTokenStatusActive(cryptoTokenId);
            } catch (Exception e) {
                final String msg = getAdmin().toString() + " failed to load CryptoToken status for " + cryptoTokenId;
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                } else {
                    log.info(msg);
                }
            }
            final boolean caService = (cainfo.getStatus() == CAConstants.CA_ACTIVE) && caTokenStatus;
            boolean crlStatus = true;
            final Date now = new Date();
            // TODO GUI support for Partitioned CRLs (ECA-7961)
            
            final Date crlNextUpdate = crlStoreSession.getCrlExpireDate(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
            
            
            if (crlNextUpdate != null && now.after(crlNextUpdate)) {
                crlStatus = false;
            }
            
            final Date deltaCrlNextUpdate = crlStoreSession.getCrlExpireDate(cainfo.getLatestSubjectDN(), CertificateConstants.NO_CRL_PARTITION, true);
            
            if (deltaCrlNextUpdate != null && now.after(deltaCrlNextUpdate)) {
                crlStatus = false;
            }
            ret.add(new CaCrlStatusInfo(caName, caService, crlStatus));
        }
        
        ret.sort(new CaCrlStatusInfoComparator());
        return ret;
    }

    /**
     * Used in the publisherqueuestatuses.xhtml page to get the publisher queue length by its name
     * @param publishername
     * @return publisher queue length
     */
    public int getPublisherQueueLength(String publishername) {
        return getPublisherQueueLength(publisherSession.getPublisherId(publishername));
    }
    
    private int getPublisherQueueLength(int publisherId) {
        return publisherQueueSession.getPendingEntriesCountForPublisher(publisherId);
    }

    public String getPublisherQueueInspectionLink(final String publisherName) {
        return String.format("ca/inspectpublisherqueue.xhtml?faces-redirect=true&publisherId=%s", publisherSession.getPublisher(publisherName).getPublisherId());
    }
    
    public boolean isAuthorizedToViewPublishers() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_VIEWPUBLISHER);
    }
}