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
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaCertificateDetails.Callbacks;

/**
 * Backing bean for Search Certificates page. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaSearchCertsBean implements Serializable {

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

    private final List<RaCertificateDetails> resultsFiltered = new ArrayList<>();
    private Map<Integer,String> eepIdToNameMap = null;
    private Map<Integer,String> cpIdToNameMap = null;
    private Map<String,String> caSubjectToNameMap = new HashMap<>();
    private List<SelectItem> availableEeps = new ArrayList<>();
    private List<SelectItem> availableCps = new ArrayList<>();
    private List<SelectItem> availableCas = new ArrayList<>();

    private RaCertificateSearchRequest stagedRequest = new RaCertificateSearchRequest();
    private RaCertificateSearchRequest lastExecutedRequest = null;
    private RaCertificateSearchResponse lastExecutedResponse = null;

    private String genericSearchString = "";

    private String issuedAfter = "";
    private String issuedBefore = "";
    private String expiresAfter = "";
    private String expiresBefore = "";
    private String revokedAfter = "";
    private String revokedBefore = "";
    
    private UIComponent confirmPasswordComponent;

    private enum SortOrder { PROFILE, CA, SERIALNUMBER, SUBJECT, USERNAME, ISSUANCE, EXPIRATION, STATUS };
    
    private SortOrder sortBy = SortOrder.USERNAME;
    private boolean sortAscending = true;

    private boolean moreOptions = false;
    
    private RaCertificateDetails currentCertificateDetails = null;

    private final Callbacks raCertificateDetailsCallbacks = new RaCertificateDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
            return raLocaleBean;
        }
        @Override
        public UIComponent getConfirmPasswordComponent() {
            return confirmPasswordComponent;
        }
        @Override
        public boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason) throws ApprovalException, WaitingForApprovalException {
            final boolean ret = raMasterApiProxyBean.changeCertificateStatus(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint(),
                    newStatus, newRevocationReason);
            if (ret) {
                // Re-initialize object if status has changed
                final CertificateDataWrapper cdw = raMasterApiProxyBean.searchForCertificate(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint());
                raCertificateDetails.reInitialize(cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
            }
            return ret;
        }
        @Override
        public boolean recoverKey(RaCertificateDetails raCertificateDetails) throws ApprovalException, CADoesntExistsException, AuthorizationDeniedException, WaitingForApprovalException, 
                                    NoSuchEndEntityException, EndEntityProfileValidationException {
            final boolean ret = raMasterApiProxyBean.markForRecovery(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getUsername(), raCertificateDetails.getPassword(), 
                                                                        raCertificateDetails.getCertificate());
            return ret;
        }
        @Override
        public boolean keyRecoveryPossible(RaCertificateDetails raCertificateDetails) {
            final boolean ret = raMasterApiProxyBean.keyRecoveryPossible(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getCertificate(), raCertificateDetails.getUsername());
            return ret;
        }
    };
    
    /** Invoked when the page is loaded */
    public void initialize() {
        // Perform a search if parameters where passed in the query string
        if (genericSearchString != null) {
            searchAndFilterCommon();
        }
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
        boolean search = compared>0;
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
            lastExecutedResponse = raMasterApiProxyBean.searchForCertificates(raAuthenticationBean.getAuthenticationToken(), stagedRequest);
            if (!lastExecutedResponse.isMightHaveMoreResults() || !lastExecutedResponse.getCdws().isEmpty()) {
                // Only update last executed request when there is no timeout
                lastExecutedRequest = stagedRequest;
                stagedRequest = new RaCertificateSearchRequest(stagedRequest);
                filterTransformSort();
            }
        }
    }

    /** Perform in memory filtering using the current search criteria of the last result set from the back end. */
    private void filterTransformSort() {
        resultsFiltered.clear();
        if (eepIdToNameMap==null || cpIdToNameMap==null || caSubjectToNameMap==null) {
            // If the session has been discontinued we need to ensure that we repopulate the objects
            getAvailableEeps();
            getAvailableCps();
            getAvailableCas();
        }
        if (lastExecutedResponse != null) {
            for (final CertificateDataWrapper cdw : lastExecutedResponse.getCdws()) {
                // ...we don't filter if the requested maxResults is lower than the search request
                if (!genericSearchString.isEmpty() && (
                        !stagedRequest.matchSerialNumber(cdw.getCertificateData().getSerialNumber()) &&
                        !stagedRequest.matchUsername(cdw.getCertificateData().getUsername()) &&
                        !stagedRequest.matchSubjectDn(cdw.getCertificateData().getSubjectDnNeverNull()) &&
                        !stagedRequest.matchSubjectAn(cdw.getCertificateData().getSubjectAltNameNeverNull())
                        )) {
                    continue;
                }
                if (!stagedRequest.matchEep(cdw.getCertificateData().getEndEntityProfileIdOrZero())) { continue; }
                if (!stagedRequest.matchCp(cdw.getCertificateData().getCertificateProfileId())) { continue; }
                if (!stagedRequest.matchCa(cdw.getCertificateData().getIssuerDN().hashCode())) { continue; }
                if (!stagedRequest.matchIssuedInterval(cdw.getCertificateData().getNotBefore())) { continue; }
                if (!stagedRequest.matchExpiresInterval(cdw.getCertificateData().getExpireDate())) { continue; }
                if (!stagedRequest.matchRevokedInterval(cdw.getCertificateData().getRevocationDate())) { continue; }
                if (!stagedRequest.matchStatusAndReason(cdw.getCertificateData().getStatus(), cdw.getCertificateData().getRevocationReason())) { continue; }
                resultsFiltered.add(new RaCertificateDetails(cdw, raCertificateDetailsCallbacks, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap));
            }
            if (log.isDebugEnabled()) {
                log.debug("Filtered " + lastExecutedResponse.getCdws().size() + " responses down to " + resultsFiltered.size() + " results.");
            }
            sort();
            chain();
        }
    }

    /** Sort the filtered result set based on the select column and sort order. */
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<RaCertificateDetails>() {
            @Override
            public int compare(RaCertificateDetails o1, RaCertificateDetails o2) {
                switch (sortBy) {
                case PROFILE:
                    return o1.getEepName().concat(o1.getCpName()).compareTo(o2.getEepName().concat(o2.getCpName())) * (sortAscending ? 1 : -1);
                case CA:
                    return o1.getCaName().compareTo(o2.getCaName()) * (sortAscending ? 1 : -1);
                case SERIALNUMBER:
                    return o1.getSerialnumber().compareTo(o2.getSerialnumber()) * (sortAscending ? 1 : -1);
                case SUBJECT:
                    return (o1.getSubjectDn()+o1.getSubjectAn()).compareTo(o2.getSubjectDn()+o2.getSubjectAn()) * (sortAscending ? 1 : -1);
                case ISSUANCE:
                    return o1.getCreated().compareTo(o2.getCreated()) * (sortAscending ? 1 : -1);
                case EXPIRATION:
                    return o1.getExpires().compareTo(o2.getExpires()) * (sortAscending ? 1 : -1);
                case STATUS:
                    return o1.getStatus().compareTo(o2.getStatus()) * (sortAscending ? 1 : -1);
                case USERNAME:
                default:
                    return o1.getUsername().compareTo(o2.getUsername()) * (sortAscending ? 1 : -1);
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
    public String getSortedBySerialNumber() { return getSortedBy(SortOrder.SERIALNUMBER); }
    public void sortBySerialNumber() { sortBy(SortOrder.SERIALNUMBER, true); }
    public String getSortedBySubject() { return getSortedBy(SortOrder.SUBJECT); }
    public void sortBySubject() { sortBy(SortOrder.SUBJECT, true); }
    public String getSortedByIssuance() { return getSortedBy(SortOrder.ISSUANCE); }
    public void sortByIssuance() { sortBy(SortOrder.ISSUANCE, false); }
    public String getSortedByExpiration() { return getSortedBy(SortOrder.EXPIRATION); }
    public void sortByExpiration() { sortBy(SortOrder.EXPIRATION, false); }
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
        stagedRequest.resetMaxResults();
        stagedRequest.resetIssuedAfter();
        stagedRequest.resetIssuedBefore();
        stagedRequest.resetExpiresAfter();
        stagedRequest.resetExpiresBefore();
        stagedRequest.resetRevokedAfter();
        stagedRequest.resetRevokedBefore();
        issuedAfter = "";
        issuedBefore = "";
        expiresAfter = "";
        expiresBefore = "";
        revokedAfter = "";
        revokedBefore = "";
        searchAndFilterCommon();
    }

    public List<RaCertificateDetails> getFilteredResults() {
        return resultsFiltered;
    }

    public String getGenericSearchString() { return this.genericSearchString; }
    public void setGenericSearchString(final String genericSearchString) {
        this.genericSearchString = genericSearchString;
        stagedRequest.setSubjectDnSearchString(genericSearchString);
        stagedRequest.setSubjectAnSearchString(genericSearchString);
        stagedRequest.setUsernameSearchString(genericSearchString);
        stagedRequest.setSerialNumberSearchStringFromDec(genericSearchString);
        stagedRequest.setSerialNumberSearchStringFromHex(genericSearchString);
    }
    
    public int getCriteriaMaxResults() { return stagedRequest.getMaxResults(); }
    public void setCriteriaMaxResults(final int criteriaMaxResults) { stagedRequest.setMaxResults(criteriaMaxResults); }
    public List<SelectItem> getAvailableMaxResults() {
        List<SelectItem> ret = new ArrayList<>();
        for (final int value : new int[]{ RaCertificateSearchRequest.DEFAULT_MAX_RESULTS, 50, 100, 200, 400}) {
            ret.add(new SelectItem(value, raLocaleBean.getMessage("search_certs_page_criteria_results_option", value)));
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
            availableEeps.add(new SelectItem(0, raLocaleBean.getMessage("search_certs_page_criteria_eep_optionany")));
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
            availableCps.add(new SelectItem(0, raLocaleBean.getMessage("search_certs_page_criteria_cp_optionany")));
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
                    return caInfo1.getName().compareTo(caInfo2.getName());
                }
            });
            for (final CAInfo caInfo : caInfos) {
                caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
            }
            availableCas.add(new SelectItem(0, raLocaleBean.getMessage("search_certs_page_criteria_ca_optionany")));
            for (final CAInfo caInfo : caInfos) {
                availableCas.add(new SelectItem(caInfo.getCAId(), "- " + caInfo.getName()));
            }
        }
        return availableCas;
    }

    public String getIssuedAfter() {
        return getDateAsString(issuedAfter, stagedRequest.getIssuedAfter(), 0L);
    }
    public void setIssuedAfter(final String issuedAfter) {
        this.issuedAfter = issuedAfter;
        stagedRequest.setIssuedAfter(parseDateAndUseDefaultOnFail(issuedAfter, 0L));
    }
    public String getIssuedBefore() {
        return getDateAsString(issuedBefore, stagedRequest.getIssuedBefore(), Long.MAX_VALUE);
    }
    public void setIssuedBefore(final String issuedBefore) {
        this.issuedBefore = issuedBefore;
        stagedRequest.setIssuedBefore(parseDateAndUseDefaultOnFail(issuedBefore, Long.MAX_VALUE));
    }
    public String getExpiresAfter() {
        return getDateAsString(expiresAfter, stagedRequest.getExpiresAfter(), 0L);
    }
    public void setExpiresAfter(final String expiresAfter) {
        this.expiresAfter = expiresAfter;
        stagedRequest.setExpiresAfter(parseDateAndUseDefaultOnFail(expiresAfter, 0L));
    }
    public String getExpiresBefore() {
        return getDateAsString(expiresBefore, stagedRequest.getExpiresBefore(), Long.MAX_VALUE);
    }
    public void setExpiresBefore(final String expiresBefore) {
        this.expiresBefore = expiresBefore;
        stagedRequest.setExpiresBefore(parseDateAndUseDefaultOnFail(expiresBefore, Long.MAX_VALUE));
    }
    public String getRevokedAfter() {
        return getDateAsString(revokedAfter, stagedRequest.getRevokedAfter(), 0L);
    }
    public void setRevokedAfter(final String revokedAfter) {
        this.revokedAfter = revokedAfter;
        stagedRequest.setRevokedAfter(parseDateAndUseDefaultOnFail(revokedAfter, 0L));
    }
    public String getRevokedBefore() {
        return getDateAsString(revokedBefore, stagedRequest.getRevokedBefore(), Long.MAX_VALUE);
    }
    public void setRevokedBefore(final String revokedBefore) {
        this.revokedBefore = revokedBefore;
        stagedRequest.setRevokedBefore(parseDateAndUseDefaultOnFail(revokedBefore, Long.MAX_VALUE));
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
                raLocaleBean.addMessageWarn("search_certs_page_warn_invaliddate");
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

    public String getCriteriaStatus() {
        final StringBuilder sb = new StringBuilder();
        final List<Integer> statuses = stagedRequest.getStatuses();
        final List<Integer> revocationReasons = stagedRequest.getRevocationReasons();
        if (statuses.contains(CertificateConstants.CERT_ACTIVE)) {
            sb.append(CertificateConstants.CERT_ACTIVE);
        } else if (statuses.contains(CertificateConstants.CERT_REVOKED)) {
            sb.append(CertificateConstants.CERT_REVOKED);
            if (!revocationReasons.isEmpty()) {
                sb.append("_").append(revocationReasons.get(0));
            }
        }
        return sb.toString();
    }
    public void setCriteriaStatus(final String criteriaStatus) {
        final List<Integer> statuses = new ArrayList<>();
        final List<Integer> revocationReasons = new ArrayList<>();
        if (criteriaStatus!=null && !criteriaStatus.isEmpty()) {
            final String[] criteriaStatusSplit = criteriaStatus.split("_");
            if (String.valueOf(CertificateConstants.CERT_ACTIVE).equals(criteriaStatusSplit[0])) {
                statuses.addAll(Arrays.asList(new Integer[]{ CertificateConstants.CERT_ACTIVE, CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION }));
            } else {
                statuses.addAll(Arrays.asList(new Integer[]{ CertificateConstants.CERT_REVOKED, CertificateConstants.CERT_ARCHIVED }));
                if (criteriaStatusSplit.length>1) {
                    revocationReasons.addAll(Arrays.asList(new Integer[]{ Integer.parseInt(criteriaStatusSplit[1]) }));
                }
            }
        }
        stagedRequest.setStatuses(statuses);
        stagedRequest.setRevocationReasons(revocationReasons);
    }
    
    public List<SelectItem> getAvailableStatuses() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem("", raLocaleBean.getMessage("search_certs_page_criteria_status_option_any")));
        ret.add(new SelectItem(String.valueOf(CertificateConstants.CERT_ACTIVE), raLocaleBean.getMessage("search_certs_page_criteria_status_option_active")));
        ret.add(new SelectItem(String.valueOf(CertificateConstants.CERT_REVOKED), raLocaleBean.getMessage("search_certs_page_criteria_status_option_revoked")));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN));
        ret.add(getAvailableStatusRevoked(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE));
        return ret;
    }
    private SelectItem getAvailableStatusRevoked(final int reason) {
        return new SelectItem(CertificateConstants.CERT_REVOKED + "_" + reason, raLocaleBean.getMessage("search_certs_page_criteria_status_option_revoked_reason_"+reason));
    }

    private <T> List<Entry<T, String>> getAsSortedByValue(final Set<Entry<T, String>> entrySet) {
        final List<Entry<T, String>> entrySetSorted = new ArrayList<>(entrySet);
        Collections.sort(entrySetSorted, new Comparator<Entry<T, String>>() {
            @Override
            public int compare(final Entry<T, String> o1, final Entry<T, String> o2) {
                return o1.getValue().compareTo(o2.getValue());
            }
        });
        return entrySetSorted;
    }
    
    public UIComponent getConfirmPasswordComponent() {
        return confirmPasswordComponent;
    }

    public void setConfirmPasswordComponent(UIComponent confirmPasswordComponent) {
        this.confirmPasswordComponent = confirmPasswordComponent;
    }
    
    /** Chain the results in the current order for certificate details navigation. */
    private void chain() {
        RaCertificateDetails previous = null;
        for (final RaCertificateDetails current: resultsFiltered) {
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

    public void openCertificateDetails(final RaCertificateDetails selected) {
        currentCertificateDetails = selected;
    }
    public RaCertificateDetails getCurrentCertificateDetails() {
        return currentCertificateDetails;
    }
    public void nextCertificateDetails() {
        currentCertificateDetails = currentCertificateDetails.getNext();
    }
    public void previousCertificateDetails() {
        currentCertificateDetails = currentCertificateDetails.getPrevious();
    }
    public void closeCertificateDetails() {
        currentCertificateDetails = null;
    }
}
