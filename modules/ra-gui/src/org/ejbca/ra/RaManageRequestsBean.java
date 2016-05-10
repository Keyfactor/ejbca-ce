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
 * Backing bean for Manage Requests page. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaManageRequestsBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaSearchCertsBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private RaRequestsSearchResponse lastExecutedResponse = null;
    
    private List<RaApprovalRequestInfo> resultsFiltered = new ArrayList<>();
    
    private enum ViewTab { NEEDS_APPROVAL, PENDING_APPROVAL, PROCESSED, CUSTOM_SEARCH };
    private ViewTab viewTab = ViewTab.NEEDS_APPROVAL;
    
    private enum SortBy { REQUEST_DATE };
    private SortBy sortBy = SortBy.REQUEST_DATE;
    private boolean sortAscending = true;

    public void viewNeedsApproval() {
        viewTab = ViewTab.NEEDS_APPROVAL;
        searchAndFilter();
    }
    
    public void viewPendingApproval() {
        viewTab = ViewTab.PENDING_APPROVAL;
        searchAndFilter();
    }
    
    public void viewProcessed() {
        viewTab = ViewTab.PROCESSED;
        searchAndFilter();
    }
    
    public void viewAll() {
        viewTab = ViewTab.CUSTOM_SEARCH;
        searchAndFilter();
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
        resultsFiltered = lastExecutedResponse.getApprovalRequests();
        sort();
    }
    
    public List<RaApprovalRequestInfo> getFilteredResults() {
        return resultsFiltered;
    }
    
    public boolean isMoreResultsAvailable() {
        return lastExecutedResponse != null && lastExecutedResponse.isMightHaveMoreResults();
    }
    
    // Sorting
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<RaApprovalRequestInfo>() {
            @Override
            public int compare(RaApprovalRequestInfo o1, RaApprovalRequestInfo o2) {
                switch (sortBy) {
                case REQUEST_DATE:
                default:
                    return o1.getRequestDate().compareTo(o2.getRequestDate()) * (sortAscending ? 1 : -1);
                }
            }
        });
    }
    
    public String getSortedByRequestDate() { return getSortedBy(SortBy.REQUEST_DATE); }
    public void sortByRequestDate() { sortBy(SortBy.REQUEST_DATE, false); }
	
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
