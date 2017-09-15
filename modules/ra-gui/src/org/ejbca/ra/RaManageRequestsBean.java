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
import java.util.Locale;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

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

    private enum ViewTab { TO_APPROVE, PENDING, PROCESSED, CUSTOM_SEARCH };
    private ViewTab viewTab = ViewTab.TO_APPROVE;
    private boolean customSearchingWaiting = true;
    private boolean customSearchingProcessed = true;
    private boolean customSearchingExpired = true;
    private String customSearchStartDate;
    private String customSearchEndDate;
    private String customSearchExpiresDays;

    private enum SortBy { ID, REQUEST_DATE, CA, TYPE, DISPLAY_NAME, REQUESTER_NAME, STATUS };
    private SortBy sortBy = SortBy.REQUEST_DATE;
    private boolean sortAscending = true;

    public String getTab() {
        return viewTab != null ? viewTab.name().toLowerCase(Locale.ROOT) : null;
    }

    public void setTab(final String value) {
        try {
            viewTab = !StringUtils.isBlank(value) ? ViewTab.valueOf(value.toUpperCase(Locale.ROOT)) : ViewTab.TO_APPROVE;
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid value for the 'tab' parameter: '" + value + "'");
            }
            viewTab = ViewTab.TO_APPROVE;
        }
    }

    public boolean isViewingNeedsApproval() {
        return viewTab == ViewTab.TO_APPROVE;
    }

    public boolean isViewingPendingApproval() {
        return viewTab == ViewTab.PENDING;
    }

    public boolean isViewingProcessed() {
        return viewTab == ViewTab.PROCESSED;
    }

    public boolean isViewingCustom() {
        return viewTab == ViewTab.CUSTOM_SEARCH;
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
                    // Only requests in waiting state can expire
                    customSearchingWaiting = true;
                    customSearchingProcessed = false;
                    customSearchingExpired = false;
                }
                searchRequest.setSearchingWaitingForMe(customSearchingWaiting);
                searchRequest.setSearchingPending(customSearchingWaiting); // those are also waiting
                searchRequest.setSearchingHistorical(customSearchingProcessed);
                searchRequest.setSearchingExpired(customSearchingExpired);
                searchRequest.setIncludeOtherAdmins(true);
            } catch (ParseException e) {
                // Text field is validated by f:validateRegex, so shouldn't happen
                throw new IllegalStateException("Invalid date value", e);
            }
            break;
        case TO_APPROVE:
            searchRequest.setSearchingWaitingForMe(true);
            break;
        case PENDING:
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
            final ApprovalRequestGUIInfo approvalRequestGuiInfo = new ApprovalRequestGUIInfo(reqInfo, raLocaleBean, raAccessBean);
            if (isCustomSearchingWaiting() && !approvalRequestGuiInfo.isCanApprove()) {
                continue;
            }
            guiInfos.add(approvalRequestGuiInfo);
        }
        resultsFiltered = guiInfos;
        sort();
    }

    public boolean isCustomSearchingWaiting() { return customSearchingWaiting; }
    public void setCustomSearchingWaiting(final boolean customSearchingWaiting) { this.customSearchingWaiting = customSearchingWaiting; }
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
        return resultsFiltered;
    }

    public boolean isMoreResultsAvailable() {
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
    public void sortByRequestDate() { sortBy(SortBy.REQUEST_DATE, viewTab == ViewTab.PROCESSED || viewTab == ViewTab.CUSTOM_SEARCH); }
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

    public String getSortColumn() {
        return sortBy.name();
    }

    public void setSortColumn(final String value) {
        try {
            sortBy = !StringUtils.isBlank(value) ? SortBy.valueOf(value.toUpperCase(Locale.ROOT)) : SortBy.REQUEST_DATE;
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid value for the 'sortColumn' parameter: '" + value + "'");
            }
            sortBy = SortBy.REQUEST_DATE;
        }
    }

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

    public boolean isSortAscending() {
        return sortAscending;
    }

    public void setSortAscending(final boolean value) {
        sortAscending = value;
    }

}
