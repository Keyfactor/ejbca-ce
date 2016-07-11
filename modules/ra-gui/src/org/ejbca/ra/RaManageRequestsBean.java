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

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRequestsSearchRequest;
import org.ejbca.core.model.era.RaRequestsSearchResponse;

/**
 * Backing bean for Manage Requests page (for a list of requests)
 * 
 * @see RaManageRequestBean
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaManageRequestsBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaManageRequestsBean.class);

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
    private ViewTab viewTab;
    
    private enum SortBy { REQUEST_DATE, CA, TYPE, DISPLAY_NAME, REQUESTER_NAME, STATUS };
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
            // TODO implement custom search (needed for ECA-5124)
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
        for (final RaApprovalRequestInfo reqInfo : reqInfos) {
            guiInfos.add(new ApprovalRequestGUIInfo(reqInfo, raLocaleBean));
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
                int sortDir = (sortAscending ? 1 : -1);
                switch (sortBy) {
                // TODO locale-aware sorting
                case CA: return o1.getCa().compareTo(o2.getCa()) * sortDir;
                case TYPE: return o1.getType().compareTo(o2.getType()) * sortDir;
                case DISPLAY_NAME: return o1.getDisplayName().compareTo(o2.getDisplayName()) * sortDir;
                case REQUESTER_NAME: return o1.getRequesterName().compareTo(o2.getRequesterName()) * sortDir;
                case STATUS: return o1.getStatus().compareTo(o2.getStatus()) * sortDir;
                case REQUEST_DATE:
                default:
                    // We compare the date objects (o1.request.getRequestDate()) and not the strings (o1.getRequestDate())
                    return o1.request.getRequestDate().compareTo(o2.request.getRequestDate()) * sortDir;
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
    public String getSortedByRequesterName() { return getSortedBy(SortBy.REQUESTER_NAME); }
    public void sortByRequesterName() { sortBy(SortBy.REQUESTER_NAME, true); }
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
