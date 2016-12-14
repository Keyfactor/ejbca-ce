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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
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

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }
    
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
    private boolean customSearchingWaiting;
    private boolean customSearchingPending;
    private boolean customSearchingProcessed;
    private boolean customSearchingExpired;
    private String customSearchStartDate;
    private String customSearchEndDate;
    private String customSearchExpiresDays;
    
    private enum SortBy { ID, REQUEST_DATE, CA, TYPE, DISPLAY_NAME, REQUESTER_NAME, STATUS };
    private SortBy sortBy = SortBy.REQUEST_DATE;
    private boolean sortAscending;
    
    /** Returns the currently viewed tab, and initializes and shows the "Needs Approval" tab if no tab has been clicked */ 
    private ViewTab getViewedTab() {
        if (viewTab == null) {
            final String tabHttpParam = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("tab");
            if (tabHttpParam != null) {
                switch (tabHttpParam) {
                case "needsApproval": viewTab = ViewTab.NEEDS_APPROVAL; break;
                case "pending": viewTab = ViewTab.PENDING_APPROVAL; break;
                case "processed": viewTab = ViewTab.PROCESSED; break;
                case "custom": viewTab = ViewTab.CUSTOM_SEARCH; break;
                default:
                    throw new IllegalStateException("Internal Error: Invalid tab parameter value");
                }
            } else {
                viewTab = ViewTab.NEEDS_APPROVAL;
            }
            sortAscending = getDefaultRequestDateSortOrder(); // based on the selected tab
            searchAndFilter();
        }
        return viewTab;
    }
    
    private boolean getDefaultRequestDateSortOrder() {
        switch (getViewedTab()) {
        case NEEDS_APPROVAL:
        case PENDING_APPROVAL:
            return true; // ascending (oldest first)
        case PROCESSED:
        case CUSTOM_SEARCH:
            return false; // descending (most recent first)
        default:
            throw new IllegalStateException("Internal error: Invalid tab");
        }
    }
    
    public String getCurrentTabName() {
        switch (getViewedTab()) {
        case NEEDS_APPROVAL: return "needsApproval";
        case PENDING_APPROVAL: return "pending";
        case PROCESSED: return "processed";
        case CUSTOM_SEARCH: return "custom";
        default:
            throw new IllegalStateException("Internal error: Invalid tab");
        }
    }
    
    public boolean isViewingNeedsApproval() {
        return getViewedTab() == ViewTab.NEEDS_APPROVAL;
    }
    
    public boolean isViewingPendingApproval() {
        return getViewedTab() == ViewTab.PENDING_APPROVAL;
    }

    public boolean isViewingProcessed() {
        return getViewedTab() == ViewTab.PROCESSED;
    }
    
    public boolean isViewingCustom() {
        return getViewedTab() == ViewTab.CUSTOM_SEARCH;
    }
    
    
    public void searchAndFilter() {
        final RaRequestsSearchRequest searchRequest = new RaRequestsSearchRequest();
        switch (viewTab) {
        case CUSTOM_SEARCH:
            try {
                // TODO timezone?
                if (!StringUtils.isBlank(customSearchStartDate)) {
                    searchRequest.setStartDate(new SimpleDateFormat("yyyy-MM-dd").parse(customSearchStartDate.trim()));
                }
                if (!StringUtils.isBlank(customSearchEndDate)) {
                    final Calendar cal = Calendar.getInstance();
                    cal.setTime(new SimpleDateFormat("yyyy-MM-dd").parse(customSearchEndDate.trim()));
                    cal.add(Calendar.DAY_OF_MONTH, 1);
                    searchRequest.setEndDate(cal.getTime());
                }
                if (!StringUtils.isBlank(customSearchExpiresDays)) {
                    final Calendar cal = Calendar.getInstance();
                    cal.setTime(new Date());
                    cal.add(Calendar.DAY_OF_MONTH, Integer.parseInt(customSearchExpiresDays.trim()));
                    searchRequest.setExpiresBefore(cal.getTime());
                    if (!customSearchingWaiting && !customSearchingPending) {
                        // This combination makes no sense, so show unfinished requests also
                        customSearchingWaiting = true;
                        customSearchingPending = true;
                        // TODO should search for all admins in this case, when that is implemented
                    }
                }
                searchRequest.setSearchingWaitingForMe(customSearchingWaiting);
                searchRequest.setSearchingPending(customSearchingPending);
                searchRequest.setSearchingHistorical(customSearchingProcessed);
                searchRequest.setSearchingExpired(customSearchingExpired);
            } catch (ParseException e) {
                // Text field is validated by f:validateRegex, so shouldn't happen
                throw new IllegalStateException("Invalid date value", e);
            }
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
            guiInfos.add(new ApprovalRequestGUIInfo(reqInfo, raLocaleBean, raAccessBean));
        }
        resultsFiltered = guiInfos;
        sort();
    }
    
    public boolean isCustomSearchingWaiting() { return customSearchingWaiting; }
    public void setCustomSearchingWaiting(final boolean customSearchingWaiting) { this.customSearchingWaiting = customSearchingWaiting; }
    public boolean isCustomSearchingPending() { return customSearchingPending; }
    public void setCustomSearchingPending(final boolean customSearchingPending) { this.customSearchingPending = customSearchingPending; }
    public boolean isCustomSearchingProcessed() { return customSearchingProcessed; }
    public void setCustomSearchingProcessed(final boolean customSearchingProcessed) { this.customSearchingProcessed = customSearchingProcessed; }
    public boolean isCustomSearchingExpired() { return customSearchingExpired; }
    public void setCustomSearchingExpired(final boolean customSearchingExpired) { this.customSearchingExpired = customSearchingExpired; }
    public String getCustomSearchStartDate() { return customSearchStartDate; }
    public void setCustomSearchStartDate(final String startDate) { this.customSearchStartDate = StringUtils.trim(startDate); }
    public String getCustomSearchEndDate() { return customSearchEndDate; }
    public void setCustomSearchEndDate(final String endDate) { this.customSearchEndDate = StringUtils.trim(endDate); }
    public String getCustomSearchExpiresDays() { return customSearchExpiresDays; }
    public void setCustomSearchExpiresDays(final String customSearchExpiresDays) { this.customSearchExpiresDays = StringUtils.trim(customSearchExpiresDays); }
    
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
                int sortDir = (isSortAscending() ? 1 : -1);
                switch (sortBy) {
                // TODO locale-aware sorting
                case ID: return o1.getId().compareTo(o2.getId()) * sortDir;
                case CA: return o1.getCa().compareTo(o2.getCa()) * sortDir;
                case TYPE: return o1.getType().compareTo(o2.getType()) * sortDir;
                case DISPLAY_NAME: return o1.getDisplayName().compareTo(o2.getDisplayName()) * sortDir;
                case REQUESTER_NAME: return o1.getRequesterName().compareTo(o2.getRequesterName()) * sortDir;
                case STATUS: return o1.getStatus().compareTo(o2.getStatus()) * sortDir;
                case REQUEST_DATE:
                default:
                    // We compare the date objects (o1.request.getRequestDate()) and not the strings (o1.getRequestDate())
                    return o1.request.getApprovalData().getRequestDate().compareTo(o2.request.getApprovalData().getRequestDate()) * sortDir;
                }
            }
        });
    }
    
    public String getSortedByRequestDate() { return getSortedBy(SortBy.REQUEST_DATE); }
    public void sortByRequestDate() { sortBy(SortBy.REQUEST_DATE, getDefaultRequestDateSortOrder()); }
    public String getSortedByID() { return getSortedBy(SortBy.ID); }
    public void sortByID() { sortBy(SortBy.ID, false); }
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
            return isSortAscending() ? "\u25bc" : "\u25b2";
        }
        return "";
    }
    
    /** Set current sort column. Flip the order if the column was already selected. */
    private void sortBy(final SortBy sortBy, final boolean defaultAscending) {
        if (this.sortBy.equals(sortBy)) {
            sortAscending = !isSortAscending();
        } else {
            sortAscending = defaultAscending;
        }
        this.sortBy = sortBy;
        sort();
    }
    
    private boolean isSortAscending() {
        if (viewTab == null) {
            // Initialize defaults based on the current tab
            sortAscending = getDefaultRequestDateSortOrder();
        }
        return sortAscending;
    }
    
}
