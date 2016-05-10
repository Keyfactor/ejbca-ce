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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.TimeZone;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRequestsSearchRequest;
import org.ejbca.core.model.era.RaRequestsSearchResponse;

/**
 * Backing bean for Manage Requests page. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaManageRequestsBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaSearchCertsBean.class);

    public class ApprovalRequestGUIInfo {
        private final RaApprovalRequestInfo request;
        private final String requestDate;
        private final String caName;
        private final String type;
        private final String displayName;
        private final String detail;
        private final String status;
        
        public ApprovalRequestGUIInfo(final RaApprovalRequestInfo request, final IdNameHashMap<CAInfo> caIdInfos) {
            this.request = request;
            requestDate = ValidityDate.formatAsISO8601ServerTZ(request.getRequestDate().getTime(), TimeZone.getDefault());
            caName = caIdInfos.get(request.getCAId()).getName();
            
            switch (request.getType()) {
            case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_add_end_entity"); break;
            case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE: type = raLocaleBean.getMessage("manage_requests_type_revoke_certificate"); break;
            case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_revoke_end_entity"); break;
            default:
                log.info("Invalid/unsupported type of approval request: " + request.getType());
                type = "???";
            }
            
            /*username = request.getUsername();
            subjectDN = request.getSubjectDN();*/
            /*String cn = CertTools.getPartFromDN(subjectDN, "CN");
            if (cn == null) {
                cn = subjectDN;
            }*/
            displayName = "TODO"; // TODO could show CN or fall back to Subject DN for End Entity approval requests
            detail = "TODO"; // TODO could show full DN for End Entity approval requests
            
            switch (request.getStatus()) {
            case ApprovalDataVO.STATUS_APPROVED: status = raLocaleBean.getMessage("manage_requests_status_approved"); break;
            case ApprovalDataVO.STATUS_EXECUTED: status = raLocaleBean.getMessage("manage_requests_status_executed"); break;
            case ApprovalDataVO.STATUS_EXECUTIONDENIED: status = raLocaleBean.getMessage("manage_requests_status_execution_denied"); break;
            case ApprovalDataVO.STATUS_EXECUTIONFAILED: status = raLocaleBean.getMessage("manage_requests_status_execution_failed"); break;
            case ApprovalDataVO.STATUS_EXPIRED: status = raLocaleBean.getMessage("manage_requests_status_expired"); break;
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED: status = raLocaleBean.getMessage("manage_requests_status_expired_and_notified"); break;
            case ApprovalDataVO.STATUS_REJECTED: status = raLocaleBean.getMessage("manage_requests_status_rejected"); break;
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL: status = raLocaleBean.getMessage("manage_requests_status_waiting_for_approval"); break;
            default:
                log.info("Invalid status of approval request: " + request.getStatus());
                status = "???";
            }
        }
        
        public String getRequestDate() { return requestDate; }
        public String getCa() { return caName; }
        public String getType() { return type; }
        public String getDisplayName() { return displayName; }
        public String getDetail() { return detail; }
        public String getStatus() { return status; }
    }
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private RaRequestsSearchResponse lastExecutedResponse = null;
    
    private List<ApprovalRequestGUIInfo> resultsFiltered = new ArrayList<>();
    
    private enum ViewTab { NEEDS_APPROVAL, PENDING_APPROVAL, PROCESSED, CUSTOM_SEARCH };
    private ViewTab viewTab; // TODO show the NEEDS_APPROVAL tab automatically?
    
    private enum SortBy { REQUEST_DATE, CA, TYPE, DISPLAY_NAME, STATUS };
    private SortBy sortBy = SortBy.REQUEST_DATE;
    private boolean sortAscending = true;

    /** Returns the currently viewed tab, and initializes and shows the "Needs Approval" tab if no tab has been clicked */ 
    private ViewTab getViewedTab() {
        if (viewTab == null) {
            viewTab = ViewTab.NEEDS_APPROVAL;
            searchAndFilter();
        }
        return viewTab;
    }
    
    public void viewNeedsApproval() {
        viewTab = ViewTab.NEEDS_APPROVAL;
        searchAndFilter();
    }
    
    public boolean isViewingNeedsApproval() {
        return getViewedTab() == ViewTab.NEEDS_APPROVAL;
    }
    
    public void viewPendingApproval() {
        viewTab = ViewTab.PENDING_APPROVAL;
        searchAndFilter();
    }
    
    public boolean isViewingPendingApproval() {
        return getViewedTab() == ViewTab.PENDING_APPROVAL;
    }
    
    public void viewProcessed() {
        viewTab = ViewTab.PROCESSED;
        searchAndFilter();
    }

    public boolean isViewingProcessed() {
        return getViewedTab() == ViewTab.PROCESSED;
    }
    
    public void viewCustom() {
        viewTab = ViewTab.CUSTOM_SEARCH;
        searchAndFilter();
    }
    
    public boolean isViewingCustom() {
        return getViewedTab() == ViewTab.CUSTOM_SEARCH;
    }
    
    
    private void searchAndFilter() {
        final RaRequestsSearchRequest searchRequest = new RaRequestsSearchRequest();
        switch (viewTab) {
        case CUSTOM_SEARCH:
            // TODO
            searchRequest.setSearchingWaitingForMe(true);
            searchRequest.setSearchingPending(true);
            searchRequest.setSearchingHistorical(true);
            break;
        case NEEDS_APPROVAL:
            searchRequest.setSearchingWaitingForMe(true);
            break;
        case PENDING_APPROVAL:
            searchRequest.setSearchingPending(true);
            break;
        case PROCESSED:
            searchRequest.setSearchingHistorical(true);
            break;
        }
        lastExecutedResponse = raMasterApiProxyBean.searchForApprovalRequests(raAuthenticationBean.getAuthenticationToken(), searchRequest);
        final List<RaApprovalRequestInfo> reqInfos = lastExecutedResponse.getApprovalRequests();
        final List<ApprovalRequestGUIInfo> guiInfos = new ArrayList<>();
        final IdNameHashMap<CAInfo> caIdInfos = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        for (final RaApprovalRequestInfo reqInfo : reqInfos) {
            guiInfos.add(new ApprovalRequestGUIInfo(reqInfo, caIdInfos));
        }
        resultsFiltered = guiInfos;
        sort();
    }
    
    public List<ApprovalRequestGUIInfo> getFilteredResults() {
        getViewedTab(); // make sure we have all data
        return resultsFiltered;
    }
    
    public boolean isMoreResultsAvailable() {
        getViewedTab(); // make sure we have all data
        return lastExecutedResponse != null && lastExecutedResponse.isMightHaveMoreResults();
    }
    
    // Sorting
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<ApprovalRequestGUIInfo>() {
            @Override
            public int compare(ApprovalRequestGUIInfo o1, ApprovalRequestGUIInfo o2) {
                switch (sortBy) {
                case CA: return o1.caName.compareTo(o2.caName);
                case TYPE: return o1.type.compareTo(o2.type);
                case DISPLAY_NAME: return o1.displayName.compareTo(o2.detail);
                case STATUS: return o1.status.compareTo(o2.status);
                case REQUEST_DATE:
                default:
                    return o1.request.getRequestDate().compareTo(o2.request.getRequestDate()) * (sortAscending ? 1 : -1);
                }
            }
        });
    }
    
    public String getSortedByRequestDate() { return getSortedBy(SortBy.REQUEST_DATE); }
    public void sortByRequestDate() { sortBy(SortBy.REQUEST_DATE, false); }
    public String getSortedByCA() { return getSortedBy(SortBy.CA); }
    public void sortByCA() { sortBy(SortBy.CA, true); }
    public String getSortedByType() { return getSortedBy(SortBy.TYPE); }
    public void sortByType() { sortBy(SortBy.TYPE, true); }
    public String getSortedByDisplayName() { return getSortedBy(SortBy.DISPLAY_NAME); }
    public void sortByDisplayName() { sortBy(SortBy.DISPLAY_NAME, true); }
    public String getSortedByStatus() { return getSortedBy(SortBy.STATUS); }
    public void sortByStatus() { sortBy(SortBy.STATUS, true); }
	
    private String getSortedBy(final SortBy sortBy) {
        if (this.sortBy.equals(sortBy)) {
            return sortAscending ? "\u25bc" : "\u25b2";
        }
        return "";
    }
    
    /** Set current sort column. Flip the order if the column was already selected. */
    private void sortBy(final SortBy sortBy, final boolean defaultAscending) {
        if (this.sortBy.equals(sortBy)) {
            sortAscending = !sortAscending;
        } else {
            sortAscending = defaultAscending;
        }
        this.sortBy = sortBy;
        sort();
    }
    
    
}
