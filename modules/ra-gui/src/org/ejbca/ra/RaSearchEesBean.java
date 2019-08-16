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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.component.html.HtmlOutputLabel;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaEndEntitySearchRequest;
import org.ejbca.core.model.era.RaEndEntitySearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaEndEntityDetails.Callbacks;

/**
 * Backing bean for Search Certificates page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaSearchEesBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaSearchEesBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private final List<RaEndEntityDetails> resultsFiltered = new ArrayList<>();
    private Map<Integer,String> eepIdToNameMap = null;
    private Map<Integer,String> cpIdToNameMap = null;
    private Map<Integer,String> caIdToNameMap = null;
    private List<SelectItem> availableEeps = new ArrayList<>();
    private List<SelectItem> availableCps = new ArrayList<>();
    private List<SelectItem> availableCas = new ArrayList<>();

    private RaEndEntitySearchRequest stagedRequest = new RaEndEntitySearchRequest();
    private RaEndEntitySearchRequest lastExecutedRequest = null;
    private RaEndEntitySearchResponse lastExecutedResponse = null;

    private String genericSearchString = "";

    private String modifiedAfter = "";
    private String modifiedBefore = "";

    private enum SortOrder { PROFILE, CA, SUBJECT, USERNAME, MODIFIED, STATUS };

    private SortOrder sortBy = SortOrder.USERNAME;
    private boolean sortAscending = true;

    private boolean moreOptions = false;

    private IdNameHashMap<EndEntityProfile> endEntityProfileMap = null;
    private RaEndEntityDetails currentEndEntityDetails = null;
    private List<RaCertificateDetails> currentIssuedCerts = null;

    private final Callbacks raEndEntityDetailsCallbacks = new RaEndEntityDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
            return raLocaleBean;
        }

        @Override
        public EndEntityProfile getEndEntityProfile(int eepId) {
            final KeyToValueHolder<EndEntityProfile> tuple = getEndEntityProfileMap().get(eepId);
            return tuple==null ? null : tuple.getValue();
        }
    };

    private IdNameHashMap<EndEntityProfile> getEndEntityProfileMap() {
        if (endEntityProfileMap==null) {
            // This can be quite a massive object, so only retrieve it when asked for
            endEntityProfileMap = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.VIEW_END_ENTITY);
        }
        return endEntityProfileMap;
    }

    /** Invoked action on search form post */
    public void searchAndFilterAction() {
        searchAndFilterCommon();
    }

    /** Invoked on criteria changes */
    public void searchAndFilterAjaxListener(final AjaxBehaviorEvent event) {
        searchAndFilterCommon();
    }

    /** Determine if we need to query back end or just filter and execute the required action. */
    private void searchAndFilterCommon() {
        final int compared = stagedRequest.compareTo(lastExecutedRequest);
        boolean search = compared > 0;
        if (compared != 0) {
            stagedRequest.setPageNumber(0);
        }
        if (compared<=0 && lastExecutedResponse!=null) {
            // More narrow search → filter and check if there are sufficient results left
            if (log.isDebugEnabled()) {
                log.debug("More narrow criteria → Filter");
            }
            filterTransformSort();
            // Check if there are sufficient results to fill screen and search for more
            if (resultsFiltered.size()<lastExecutedRequest.getMaxResults() && lastExecutedResponse.isMightHaveMoreResults()) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to load more results since filter left too few results → Query");
                }
                search = true;
            } else {
                search = false;
            }
        }
        if (search) {
            // Wider search → Query back-end
            if (log.isDebugEnabled()) {
                log.debug("Wider criteria → Query");
            }
            searchForEndEntities();
        }
    }

    private void searchForEndEntities() {
        lastExecutedResponse = raMasterApiProxyBean.searchForEndEntities(raAuthenticationBean.getAuthenticationToken(), stagedRequest);
        if (!lastExecutedResponse.isMightHaveMoreResults() || !lastExecutedResponse.getEndEntities().isEmpty()) {
            // Only update last executed request when there is no timeout
            lastExecutedRequest = stagedRequest;
            stagedRequest = new RaEndEntitySearchRequest(stagedRequest);
            filterTransformSort();
        }
    }

    /** Perform in memory filtering using the current search criteria of the last result set from the back end. */
    private void filterTransformSort() {
        resultsFiltered.clear();
        if (lastExecutedResponse != null) {
            if (eepIdToNameMap==null || cpIdToNameMap==null || caIdToNameMap==null) {
                getAvailableCas();
                getAvailableEeps();
                getAvailableCps();
            }
            for (final EndEntityInformation endEntityInformation : lastExecutedResponse.getEndEntities()) {
                // ...we don't filter if the requested maxResults is lower than the search request
                if (!genericSearchString.isEmpty() && (
                        !stagedRequest.matchUsername(endEntityInformation.getUsername()) &&
                        !stagedRequest.matchSubjectDn(endEntityInformation.getDN()) &&
                        !stagedRequest.matchSubjectAn(endEntityInformation.getSubjectAltName())
                        )) {
                    continue;
                }
                if (!stagedRequest.matchEep(endEntityInformation.getEndEntityProfileId())) { continue; }
                if (!stagedRequest.matchCp(endEntityInformation.getCertificateProfileId())) { continue; }
                if (!stagedRequest.matchCa(endEntityInformation.getCAId())) { continue; }
                if (!stagedRequest.matchModifiedInterval(endEntityInformation.getTimeModified().getTime())) { continue; }
                if (!stagedRequest.matchStatus(endEntityInformation.getStatus())) { continue; }
                resultsFiltered.add(new RaEndEntityDetails(endEntityInformation, raEndEntityDetailsCallbacks, cpIdToNameMap, eepIdToNameMap, caIdToNameMap));
            }
            if (log.isDebugEnabled()) {
                log.debug("Filtered " + lastExecutedResponse.getEndEntities().size() + " responses down to " + resultsFiltered.size() + " results.");
            }
            sort();
            chain();
        }
    }

    /** Sort the filtered result set based on the select column and sort order. */
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<RaEndEntityDetails>() {
            @Override
            public int compare(RaEndEntityDetails o1, RaEndEntityDetails o2) {
                switch (sortBy) {
                case PROFILE:
                    return o1.getEepName().concat(o1.getCpName()).compareToIgnoreCase(o2.getEepName().concat(o2.getCpName())) * (sortAscending ? 1 : -1);
                case CA:
                    return o1.getCaName().compareToIgnoreCase(o2.getCaName()) * (sortAscending ? 1 : -1);
                case SUBJECT:
                    return (o1.getSubjectDn()+o1.getSubjectAn()).compareToIgnoreCase(o2.getSubjectDn()+o2.getSubjectAn()) * (sortAscending ? 1 : -1);
                case MODIFIED:
                    return o1.getModified().compareTo(o2.getModified()) * (sortAscending ? 1 : -1);
                case STATUS:
                    return o1.getStatus().compareTo(o2.getStatus()) * (sortAscending ? 1 : -1);
                case USERNAME:
                default:
                    return o1.getUsername().compareToIgnoreCase(o2.getUsername()) * (sortAscending ? 1 : -1);
                }
            }
        });
    }

    /** @return true if there were no matching search results for the current criteria. */
    public boolean isResultsNone() {
        return getFilteredResults().isEmpty() && !isMoreResultsAvailable();
    }
    /** @return true if there might be more search results for the current criteria than shown here. */
    public boolean isResultsMoreAvailable() {
        return !getFilteredResults().isEmpty() && isMoreResultsAvailable();
    }
    /** @return true if there more search results for the given criteria, but there are no result which we assume is caused by a search or peer timeout. */
    public boolean isResultsTimeout() {
        return getFilteredResults().isEmpty() && isMoreResultsAvailable();
    }

    public String getSortedByProfile() { return getSortedBy(SortOrder.PROFILE); }
    public void sortByProfile() { sortBy(SortOrder.PROFILE, true); }
    public String getSortedByCa() { return getSortedBy(SortOrder.CA); }
    public void sortByCa() { sortBy(SortOrder.CA, true); }
    public String getSortedBySubject() { return getSortedBy(SortOrder.SUBJECT); }
    public void sortBySubject() { sortBy(SortOrder.SUBJECT, true); }
    public String getSortedByModified() { return getSortedBy(SortOrder.MODIFIED); }
    public void sortByModified() { sortBy(SortOrder.MODIFIED, false); }
    public String getSortedByStatus() { return getSortedBy(SortOrder.STATUS); }
    public void sortByStatus() { sortBy(SortOrder.STATUS, true); }
    public String getSortedByUsername() { return getSortedBy(SortOrder.USERNAME); }
    public void sortByUsername() { sortBy(SortOrder.USERNAME, true); }

    /** @return an up or down arrow character depending on sort order if the sort column matches */
    private String getSortedBy(final SortOrder sortOrder) {
        if (sortBy.equals(sortOrder)) {
            return sortAscending ? "\u25bc" : "\u25b2";
        }
        return "";
    }
    /** Set current sort column. Flip the order if the column was already selected. */
    private void sortBy(final SortOrder sortOrder, final boolean defaultAscending) {
        if (sortBy.equals(sortOrder)) {
            sortAscending = !sortAscending;
        } else {
            sortAscending = defaultAscending;
        }
        this.sortBy = sortOrder;
        sort();
    }

    /** @return true if there might be more results in the back end than retrieved based on the current criteria. */
    public boolean isMoreResultsAvailable() {
        return lastExecutedResponse!=null && lastExecutedResponse.isMightHaveMoreResults();
    }

    /** @return true of more search criteria than just the basics should be shown */
    public boolean isMoreOptions() { return moreOptions; };

    /** Invoked when more or less options action is invoked. */
    public void moreOptionsAction() {
        moreOptions = !moreOptions;
        // Reset any criteria in the advanced section
        stagedRequest.setMaxResults(RaEndEntitySearchRequest.DEFAULT_MAX_RESULTS);
        stagedRequest.resetModifiedAfter();
        stagedRequest.resetModifiedBefore();
        modifiedAfter = "";
        modifiedBefore = "";
        searchAndFilterCommon();
    }

    public List<RaEndEntityDetails> getFilteredResults() {
        return resultsFiltered;
    }

    public String getGenericSearchString() { return this.genericSearchString; }
    public void setGenericSearchString(final String genericSearchString) {
        this.genericSearchString = genericSearchString;
        stagedRequest.setSubjectDnSearchString(genericSearchString);
        stagedRequest.setSubjectAnSearchString(genericSearchString);
        stagedRequest.setUsernameSearchString(genericSearchString);
    }

    public int getCriteriaMaxResults() { return stagedRequest.getMaxResults(); }
    public void setCriteriaMaxResults(final int criteriaMaxResults) { stagedRequest.setMaxResults(criteriaMaxResults); }
    public List<SelectItem> getAvailableMaxResults() {
        List<SelectItem> ret = new ArrayList<>();
        for (final int value : new int[]{ RaEndEntitySearchRequest.DEFAULT_MAX_RESULTS, 50, 100, 200, 400}) {
            ret.add(new SelectItem(value, raLocaleBean.getMessage("search_ees_page_criteria_results_option", value)));
        }
        return ret;
    }

    public int getCriteriaEepId() {
        return stagedRequest.getEepIds().isEmpty() ? 0 : stagedRequest.getEepIds().get(0);
    }
    public void setCriteriaEepId(final int criteriaEepId) {
        if (criteriaEepId==0) {
            stagedRequest.setEepIds(new ArrayList<Integer>());
        } else {
            stagedRequest.setEepIds(new ArrayList<>(Arrays.asList(new Integer[]{ criteriaEepId })));
        }
    }
    public boolean isOnlyOneEepAvailable() { return getAvailableEeps().size()==1; }
    public List<SelectItem> getAvailableEeps() {
        if (availableEeps.isEmpty()) {
            eepIdToNameMap = raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
            availableEeps.add(new SelectItem(0, raLocaleBean.getMessage("search_ees_page_criteria_eep_optionany")));
            for (final Entry<Integer,String> entry : getAsSortedByValue(eepIdToNameMap.entrySet())) {
                availableEeps.add(new SelectItem(entry.getKey(), "- " + entry.getValue()));
            }
        }
        return availableEeps;
    }

    public int getCriteriaCpId() {
        return stagedRequest.getCpIds().isEmpty() ? 0 : stagedRequest.getCpIds().get(0);
    }
    public void setCriteriaCpId(final int criteriaCpId) {
        if (criteriaCpId==0) {
            stagedRequest.setCpIds(new ArrayList<Integer>());
        } else {
            stagedRequest.setCpIds(new ArrayList<>(Arrays.asList(new Integer[]{ criteriaCpId })));
        }
    }
    public boolean isOnlyOneCpAvailable() { return getAvailableCps().size()==1; }
    public List<SelectItem> getAvailableCps() {
        if (availableCps.isEmpty()) {
            cpIdToNameMap = raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
            availableCps.add(new SelectItem(0, raLocaleBean.getMessage("search_ees_page_criteria_cp_optionany")));
            for (final Entry<Integer,String> entry : getAsSortedByValue(cpIdToNameMap.entrySet())) {
                availableCps.add(new SelectItem(entry.getKey(), "- " + entry.getValue()));
            }
        }
        return availableCps;
    }

    public int getCriteriaCaId() {
        return stagedRequest.getCaIds().isEmpty() ? 0 : stagedRequest.getCaIds().get(0);
    }
    public void setCriteriaCaId(int criteriaCaId) {
        if (criteriaCaId==0) {
            stagedRequest.setCaIds(new ArrayList<Integer>());
        } else {
            stagedRequest.setCaIds(new ArrayList<>(Arrays.asList(new Integer[]{ criteriaCaId })));
        }
    }
    public boolean isOnlyOneCaAvailable() { return getAvailableCas().size()==1; }
    public List<SelectItem> getAvailableCas() {
        if (availableCas.isEmpty()) {
            final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(caInfos, new Comparator<CAInfo>() {
                @Override
                public int compare(final CAInfo caInfo1, final CAInfo caInfo2) {
                    return caInfo1.getName().compareToIgnoreCase(caInfo2.getName());
                }
            });
            caIdToNameMap = new HashMap<>();
            for (final CAInfo caInfo : caInfos) {
                caIdToNameMap.put(caInfo.getCAId(), caInfo.getName());
            }
            availableCas.add(new SelectItem(0, raLocaleBean.getMessage("search_ees_page_criteria_ca_optionany")));
            for (final CAInfo caInfo : caInfos) {
                availableCas.add(new SelectItem(caInfo.getCAId(), "- " + caInfo.getName()));
            }
        }
        return availableCas;
    }

    public String getModifiedAfter() {
        return getDateAsString(modifiedAfter, stagedRequest.getModifiedAfter(), 0L);
    }
    public void setModifiedAfter(final String modifiedAfter) {
        this.modifiedAfter = modifiedAfter;
        stagedRequest.setModifiedAfter(parseDateAndUseDefaultOnFail(modifiedAfter, 0L));
    }
    public String getModifiedBefore() {
        return getDateAsString(modifiedBefore, stagedRequest.getModifiedBefore(), Long.MAX_VALUE);
    }
    public void setModifiedBefore(final String modifiedBefore) {
        this.modifiedBefore = modifiedBefore;
        stagedRequest.setModifiedBefore(parseDateAndUseDefaultOnFail(modifiedBefore, Long.MAX_VALUE));
    }

    /** @return the current value if the staged request value if the default value */
    private String getDateAsString(final String stagedValue, final long value, final long defaultValue) {
        if (value==defaultValue) {
            return stagedValue;
        }
        return ValidityDate.formatAsISO8601ServerTZ(value, TimeZone.getDefault());
    }
    /** @return the staged request value if it is a parsable date and the default value otherwise */
    private long parseDateAndUseDefaultOnFail(final String input, final long defaultValue) {
        markCurrentComponentAsValid(true);
        if (!input.trim().isEmpty()) {
            try {
                return ValidityDate.parseAsIso8601(input).getTime();
            } catch (ParseException e) {
                markCurrentComponentAsValid(false);
                raLocaleBean.addMessageWarn("search_ees_page_warn_invaliddate");
            }
        }
        return defaultValue;
    }

    /** Set or remove the styleClass "invalidInput" on the label with a for-attribute matching the current input component. */
    private void markCurrentComponentAsValid(final boolean valid) {
        final String STYLE_CLASS_INVALID = "invalidInput";
        // UIComponent.getCurrentComponent only works when invoked via f:ajax
        final UIComponent uiComponent = UIComponent.getCurrentComponent(FacesContext.getCurrentInstance());
        final String id = uiComponent.getId();
        final List<UIComponent> siblings = uiComponent.getParent().getChildren();
        for (final UIComponent sibling : siblings) {
            if (sibling instanceof HtmlOutputLabel) {
                final HtmlOutputLabel htmlOutputLabel = (HtmlOutputLabel) sibling;
                if (htmlOutputLabel.getFor().equals(id)) {
                    String styleClass = htmlOutputLabel.getStyleClass();
                    if (valid) {
                        if (styleClass!=null && styleClass.contains(STYLE_CLASS_INVALID)) {
                            styleClass = styleClass.replace(STYLE_CLASS_INVALID, "").trim();
                        }
                    } else {
                        if (styleClass==null) {
                            styleClass = STYLE_CLASS_INVALID;
                        } else {
                            if (!styleClass.contains(STYLE_CLASS_INVALID)) {
                                styleClass = styleClass.concat(" " + STYLE_CLASS_INVALID);
                            }
                        }
                    }
                    htmlOutputLabel.setStyleClass(styleClass);
                }
            }
        }
    }

    public int getCriteriaStatus() {
        return stagedRequest.getStatuses().isEmpty() ? 0 : stagedRequest.getStatuses().get(0);
    }
    public void setCriteriaStatus(final int criteriaStatus) {
        if (criteriaStatus==0) {
            stagedRequest.setStatuses(new ArrayList<Integer>());
        } else {
            stagedRequest.setStatuses(new ArrayList<>(Arrays.asList(new Integer[]{ criteriaStatus })));
        }
    }
    public List<SelectItem> getAvailableStatuses() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(0, raLocaleBean.getMessage("search_ees_page_criteria_status_option_any")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_NEW, "- " + raLocaleBean.getMessage("search_ees_page_criteria_status_option_new")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_KEYRECOVERY, "- " + raLocaleBean.getMessage("search_ees_page_criteria_status_option_keyrecovery")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_GENERATED, "- " + raLocaleBean.getMessage("search_ees_page_criteria_status_option_generated")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_REVOKED, "- " + raLocaleBean.getMessage("search_ees_page_criteria_status_option_revoked")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_FAILED, "- " + raLocaleBean.getMessage("search_ees_page_criteria_status_option_failed")));
        // Don't expose HISTORICAL, INITIALIZED, INPROCESS
        return ret;
    }

    private <T> List<Entry<T, String>> getAsSortedByValue(final Set<Entry<T, String>> entrySet) {
        final List<Entry<T, String>> entrySetSorted = new ArrayList<>(entrySet);
        Collections.sort(entrySetSorted, new Comparator<Entry<T, String>>() {
            @Override
            public int compare(final Entry<T, String> o1, final Entry<T, String> o2) {
                return o1.getValue().compareToIgnoreCase(o2.getValue());
            }
        });
        return entrySetSorted;
    }

    /** Chain the results in the current order for end entity details navigation. */
    private void chain() {
        RaEndEntityDetails previous = null;
        for (final RaEndEntityDetails current: resultsFiltered) {
            current.setPrevious(previous);
            if (previous!=null) {
                previous.setNext(current);
            }
            previous = current;
        }
        if (!resultsFiltered.isEmpty()) {
            resultsFiltered.get(resultsFiltered.size()-1).setNext(null);
        }
    }

    public void openEndEntityDetails(final RaEndEntityDetails selected) {
        currentEndEntityDetails = selected;
        currentIssuedCerts = null;
    }
    public RaEndEntityDetails getCurrentEndEntityDetails() {
        return currentEndEntityDetails;
    }

    public void nextEndEntityDetails() {
        currentEndEntityDetails = currentEndEntityDetails.getNext();
        currentIssuedCerts = null;
    }
    public void previousEndEntityDetails() {
        currentEndEntityDetails = currentEndEntityDetails.getPrevious();
        currentIssuedCerts = null;
    }
    public void closeEndEntityDetails() {
        currentEndEntityDetails = null;
        currentIssuedCerts = null;
    }

    /**
     * Query for the next page of search results.
     */
    public void queryNextPage(final AjaxBehaviorEvent event) {
        stagedRequest.setPageNumber(stagedRequest.getPageNumber() + 1);
        searchForEndEntities();
    }

    /**
     * Query for the previous page of search results.
     */
    public void queryPreviousPage(final AjaxBehaviorEvent event) {
        stagedRequest.setPageNumber(stagedRequest.getPageNumber() - 1);
        searchForEndEntities();
    }

    public boolean isShowNextPageButton() {
        return lastExecutedResponse != null && lastExecutedResponse.isMightHaveMoreResults();
    }

    public boolean isShowPreviousPageButton() {
        return stagedRequest != null && stagedRequest.getPageNumber() > 0;
    }

    /**
     * Performs a search for certificates belonging to an End Entity and returns a list of RaCertificateDetail objects.
     *
     * @param raMasterApiProxyBean the RaMasterApiProxyBeanLocal to be used in the search
     * @param raAuthenticationBean the RaAuthenticationBean to be used in the search
     * @param raLocaleBean the RaLocaleBean to be used when creating the RaCertificateDetail objects
     * @param username the username of the End Entity to be used in the search
     * @return
     */
    public static List<RaCertificateDetails> searchCertificatesByUsernameSorted(final RaMasterApiProxyBeanLocal raMasterApiProxyBean,
            final RaAuthenticationBean raAuthenticationBean, final RaLocaleBean raLocaleBean, final String username) {
        // Perform a certificate search with the given beans and username
        RaCertificateSearchResponse response = raMasterApiProxyBean.searchForCertificatesByUsername(
                raAuthenticationBean.getAuthenticationToken(), username);
        RaCertificateDetails.Callbacks raCertificateDetailsCallbacks = new RaCertificateDetails.Callbacks() {
            @Override
            public RaLocaleBean getRaLocaleBean() {
                return raLocaleBean;
            }
            @Override
            public UIComponent getConfirmPasswordComponent() {
                return null;
            }
            @Override
            public boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason)
                    throws ApprovalException, WaitingForApprovalException {
                return false;
            }
            @Override
            public boolean recoverKey(RaCertificateDetails raCertificateDetails) throws ApprovalException, CADoesntExistsException,
                    AuthorizationDeniedException, WaitingForApprovalException,NoSuchEndEntityException, EndEntityProfileValidationException {
                return false;
            }
            @Override
            public boolean keyRecoveryPossible(RaCertificateDetails raCertificateDetails) {
                return false;
            }
        };
        List<RaCertificateDetails> certificates = new ArrayList<>();
        for (CertificateDataWrapper cdw : response.getCdws()) {
            certificates.add(new RaCertificateDetails(cdw, raCertificateDetailsCallbacks, null, null, null));
        }
        // Sort by date created, descending
        Collections.sort(certificates, new Comparator<RaCertificateDetails>() {
            @Override
            public int compare(RaCertificateDetails cert1, RaCertificateDetails cert2) {
                return cert1.getCreated().compareTo(cert2.getCreated()) * -1;
            }
        });
        return certificates;
    }

    /**
     * @return a list of the current End Entity's certificates
     */
    public List<RaCertificateDetails> getCurrentIssuedCerts() {
        if (currentIssuedCerts == null) {
            if (currentEndEntityDetails != null) {
                currentIssuedCerts = RaEndEntityTools.searchCertsByUsernameSorted(
                        raMasterApiProxyBean, raAuthenticationBean.getAuthenticationToken(),
                        currentEndEntityDetails.getUsername(), raLocaleBean);
            } else {
                currentIssuedCerts = new ArrayList<>();
            }
        }
        return currentIssuedCerts;
    }

    /**
     * @return the URL to editing the current End Entity
     */
    public String redirectToEdit() {
        String url = "endentity.xhtml?faces-redirect=true&edit=true&ee="
                + currentEndEntityDetails.getUsername();
        return url;
    }
    
    /**
     * @param chosen the RaEndEntityDetails to be edited
     * @return the URL to editing the chosen End Entity
     */
    public String redirectToEdit(final RaEndEntityDetails chosen) {
        String url = "endentity.xhtml?faces-redirect=true&edit=true&ee="
                + chosen.getUsername();
        return url;
    }

    /**
     * @return true if the API is compatible with End Entity editing 
     */
    public boolean isApiEditCompatible() {
        return raMasterApiProxyBean.getApiVersion() >= 2;
    }
}
