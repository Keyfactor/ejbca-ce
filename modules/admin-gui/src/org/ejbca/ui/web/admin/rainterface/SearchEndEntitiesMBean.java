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
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.event.FacesEvent;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

import org.apache.commons.lang3.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.SelectItemComparator;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.TimeMatch;
import org.ejbca.util.query.UserMatch;
import org.primefaces.event.TabChangeEvent;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

/**
 * Backing bean for the Search End Entities page in the CA UI.
 */
@Named("searchEndEntitiesMBean")
@ViewScoped
public class SearchEndEntitiesMBean extends BaseManagedBean {

    private static final long serialVersionUID = 1L;

    private static final int STATUS_ALL = -1;

    private static final int NO_TIME_MATCH = -1;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    private transient List<SelectItem> searchCriteria;
    private transient List<SelectItem> booleanCriteria;
    private transient Map<Integer, MatchHow[]> matchMap;
    private transient List<String> matchWithCa;
    private transient List<String> matchWithCertificateProfile;
    private transient List<String> matchWithEndEntityProfile;
    private transient List<String> availableAdvancedStatusCodes;
    private transient List<SelectItem> availableStatusCodes;
    private transient List<SelectItem> revocationReasons;
    private transient RAAuthorization raAuthorization;

    //Basic mode values:

    private String searchByName = null;
    private String searchBySerialNumber = null;
    private Integer searchByStatusCode = null;
    private Integer searchByExpiryDays = null;

    private List<EndEntitySearchResult> searchResults = new ArrayList<>();

    private List<EndEntitySearchResult> selectedResults = new ArrayList<>();
    private int selectedRevocationReason = 0;

    private SearchMethods lastSearch = null;

    //Advanced mode values:

    private List<QueryLine> queryLines = new ArrayList<>();

    private TimeConstraint timeConstraint;

    private Date after;
    private Date before;

    public SearchEndEntitiesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_VIEWENDENTITY);
    }

    @PostConstruct
    public void initialize() {
        final EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
        availableStatusCodes = new ArrayList<>();
        availableStatusCodes.add(new SelectItem(STATUS_ALL, ejbcaWebBean.getText("ALL")));
        for (Integer statusCode : EndEntityConstants.getAllStatusCodes()) {
            availableStatusCodes.add(new SelectItem(statusCode, ejbcaWebBean.getText(EndEntityConstants.getTranslatableStatusText(statusCode))));
        }

        revocationReasons = new ArrayList<>();
        for (final RevocationReasons revReason : RevocationReasons.values()) {
            final int dbValue = revReason.getDatabaseValue();
            if (dbValue >= 0) {
                revocationReasons.add(new SelectItem(dbValue, ejbcaWebBean.getText(SecConst.reasontexts[dbValue])));
            }
        }

        // First line is the initial search
        queryLines.add(new QueryLine(BooleanCriteria.FIRST, UserMatch.MATCH_NONE));
        // Second line
        queryLines.add(new QueryLine(null, UserMatch.MATCH_NONE));

        searchCriteria = Arrays.asList(
                new SelectItem(UserMatch.MATCH_NONE, ejbcaWebBean.getText("SELECT_CRITERIA")),
                new SelectItem(UserMatch.MATCH_WITH_CA, ejbcaWebBean.getText("MATCHCA")),
                new SelectItem(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, ejbcaWebBean.getText("MATCHCERTIFICATEPROFILE")),
                new SelectItem(UserMatch.MATCH_WITH_ENDENTITYPROFILE, ejbcaWebBean.getText("MATCHENDENTITYPROFILE")),
                new SelectItem(UserMatch.MATCH_WITH_STATUS, ejbcaWebBean.getText("MATCHSTATUS")),
                new SelectItem(UserMatch.MATCH_WITH_EMAIL, ejbcaWebBean.getText("MATCHEMAILADDRESS")),
                new SelectItem(UserMatch.MATCH_WITH_USERNAME, ejbcaWebBean.getText("MATCHUSERNAME")),
                new SelectItem(UserMatch.MATCH_WITH_UID, ejbcaWebBean.getText("MATCHUID")),
                new SelectItem(UserMatch.MATCH_WITH_COMMONNAME, ejbcaWebBean.getText("MATCHCOMMONNAME")),
                new SelectItem(UserMatch.MATCH_WITH_DNSERIALNUMBER, ejbcaWebBean.getText("MATCHDNSERIALNUMBER")),
                new SelectItem(UserMatch.MATCH_WITH_GIVENNAME, ejbcaWebBean.getText("MATCHGIVENNAME")),
                new SelectItem(UserMatch.MATCH_WITH_INITIALS, ejbcaWebBean.getText("MATCHINITIALS")),
                new SelectItem(UserMatch.MATCH_WITH_SURNAME, ejbcaWebBean.getText("MATCHSURNAME")),
                new SelectItem(UserMatch.MATCH_WITH_TITLE, ejbcaWebBean.getText("MATCHTITLE")),
                new SelectItem(UserMatch.MATCH_WITH_ORGANIZATIONALUNIT, ejbcaWebBean.getText("MATCHORGANIZATIONALUNIT")),
                new SelectItem(UserMatch.MATCH_WITH_ORGANIZATION, ejbcaWebBean.getText("MATCHORGANIZATION")),
                new SelectItem(UserMatch.MATCH_WITH_LOCALITY, ejbcaWebBean.getText("MATCHLOCALITY")),
                new SelectItem(UserMatch.MATCH_WITH_STATEORPROVINCE, ejbcaWebBean.getText("MATCHSTATEORPROVINCE")),
                new SelectItem(UserMatch.MATCH_WITH_DOMAINCOMPONENT, ejbcaWebBean.getText("MATCHDOMAINCOMPONENT")),
                new SelectItem(UserMatch.MATCH_WITH_COUNTRY, ejbcaWebBean.getText("MATCHCOUNTRY")));

        booleanCriteria = Arrays.asList(
                new SelectItem(null, "Add Constraint"),
                new SelectItem(BooleanCriteria.AND, "And"),
                new SelectItem(BooleanCriteria.OR, "Or"),
                new SelectItem(BooleanCriteria.AND_NOT, "And not"),
                new SelectItem(BooleanCriteria.OR_NOT, "Or not"));

        matchMap = new HashMap<>();
        matchMap.put(UserMatch.MATCH_WITH_CA, new MatchHow[]{MatchHow.EQUALS});
        matchMap.put(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, new MatchHow[]{MatchHow.EQUALS});
        matchMap.put(UserMatch.MATCH_WITH_ENDENTITYPROFILE, new MatchHow[]{MatchHow.EQUALS});
        matchMap.put(UserMatch.MATCH_WITH_STATUS, new MatchHow[]{MatchHow.EQUALS});
        matchMap.put(UserMatch.MATCH_WITH_EMAIL, new MatchHow[]{MatchHow.EQUALS, MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_USERNAME, new MatchHow[]{MatchHow.EQUALS, MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_UID, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_COMMONNAME, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_DNSERIALNUMBER, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_GIVENNAME, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_INITIALS, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_SURNAME, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_TITLE, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_ORGANIZATIONALUNIT, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_ORGANIZATION, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_LOCALITY, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_STATEORPROVINCE, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_DOMAINCOMPONENT, new MatchHow[]{MatchHow.BEGINSWITH});
        matchMap.put(UserMatch.MATCH_WITH_COUNTRY, new MatchHow[]{MatchHow.BEGINSWITH});

        raAuthorization = new RAAuthorization(getAdmin(), globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);

        matchWithCa = new ArrayList<>();
        for (CAInfo caInfo : caSession.getAuthorizedCaInfos(getAdmin())) {
            matchWithCa.add(Integer.toString(caInfo.getCAId()));
        }

        matchWithCertificateProfile = new ArrayList<>();
        for (int certificateProfileId : certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(), CertificateConstants.CERTTYPE_UNKNOWN)) {
            matchWithCertificateProfile.add(Integer.toString(certificateProfileId));
        }

        matchWithEndEntityProfile = new ArrayList<>();
        for (int endEntityProfileId : endEntityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.VIEW_END_ENTITY)) {
            matchWithEndEntityProfile.add(Integer.toString(endEntityProfileId));
        }

        availableAdvancedStatusCodes = new ArrayList<>();
        for (Integer statusCode : EndEntityConstants.getAllStatusCodes()) {
            availableAdvancedStatusCodes.add(statusCode.toString());
        }
    }

    /**
     * Called when Basic/Advanced mode is toggled
     * @param event Event from JSF
     */
    public void flushCache(final TabChangeEvent<?> event) {
        searchResults = new ArrayList<>();
        searchByName = null;
        searchBySerialNumber = null;
        searchByStatusCode = null;
        searchByExpiryDays = null;

        after = null;
        before = null;
        timeConstraint = null;

        queryLines = new ArrayList<>();
        queryLines.add(new QueryLine(BooleanCriteria.FIRST, UserMatch.MATCH_NONE));
        queryLines.add(new QueryLine(null, UserMatch.MATCH_NONE));
    }

    public String getSearchByName() {
        return searchByName;
    }

    public void setSearchByName(String searchByName) {
        this.searchByName = searchByName;
    }

    /**
     * Search for the end entity with a certain name
     */
    public String performSearchByName() {
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        EndEntityInformation endEntityInformation;
        try {
            endEntityInformation = endEntityAccessSession.findUser(getAdmin(), searchByName);
            if (endEntityInformation == null) {
                addNonTranslatedErrorMessage("No end entity with name " + searchByName + " found.");
                this.searchResults = Collections.emptyList();
            } else {
                EndEntitySearchResult endEntititySearchResult = new EndEntitySearchResult(endEntityInformation,
                        caIdToNameMap.get(endEntityInformation.getCAId()));
                this.searchResults = new ArrayList<>(Arrays.asList(endEntititySearchResult));
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            this.searchResults = Collections.emptyList();
        }
        lastSearch = SearchMethods.BY_NAME;
        return "";
    }

    /**
     * Search for all end entities that have a certain serial number (in hex)
     */
    public String performSearchBySerialNumber() {
        final BigInteger serno;
        try {
            serno = new BigInteger(StringTools.stripWhitespace(searchBySerialNumber), 16);
        } catch (NumberFormatException e) {
            addNonTranslatedErrorMessage("Not a serial number");
            this.searchResults = Collections.emptyList();
            return "";
        }
        final List<CertificateDataWrapper> certificateDataWrappers = certificateStoreSession.getCertificateDataBySerno(serno);
        List<EndEntitySearchResult> results = new ArrayList<>();
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        for (final CertificateDataWrapper next : certificateDataWrappers) {
            final CertificateData certdata = next.getCertificateData();
            try {
                final String username = certdata.getUsername();
                if (username != null) {
                    final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(getAdmin(), username);
                    if (endEntityInformation != null) {
                        results.add(new EndEntitySearchResult(endEntityInformation, caIdToNameMap.get(endEntityInformation.getCAId())));
                    }
                }
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        this.searchResults = new ArrayList<>(results);
        lastSearch = SearchMethods.BY_SERIALNUMBER;
        return "";
    }

    private List<EndEntitySearchResult> compileResults(final Collection<EndEntityInformation> endEntityInformations) {
        List<EndEntitySearchResult> results = new ArrayList<>();
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();

        for (EndEntityInformation endEntityInformation : endEntityInformations) {
            results.add(new EndEntitySearchResult(endEntityInformation, caIdToNameMap.get(endEntityInformation.getCAId())));
        }
        return results;
    }

    /**
     * Search for all end entities with a status
     */
    public String performSearchByStatus() {
        List<EndEntitySearchResult> results;
        if (searchByStatusCode.equals(STATUS_ALL)) {
            results = compileResults(endEntityAccessSession.findAllUsersWithLimit(getAdmin()));
            this.searchResults = new ArrayList<>(results);
        } else {
            Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(searchByStatusCode));
            try {
                Collection<EndEntityInformation> userlist = endEntityAccessSession.query(getAdmin(), query,
                        raAuthorization.getCAAuthorizationString(),
                        raAuthorization.getEndEntityProfileAuthorizationString(true, AccessRulesConstants.VIEW_END_ENTITY), 0,
                        AccessRulesConstants.VIEW_END_ENTITY);
                if (userlist.size() > 0) {
                    results = compileResults(userlist);
                    this.searchResults = new ArrayList<>(results);
                } else {
                    this.searchResults = Collections.emptyList();
                }
            } catch (IllegalQueryException e) {
                addNonTranslatedErrorMessage(e.getMessage());
                this.searchResults = Collections.emptyList();
            }
        }
        lastSearch = SearchMethods.BY_STATUS;
        return "";
    }

    public String performAdvancedSearch() {
        Query query = new Query(Query.TYPE_USERQUERY);
        for (QueryLine queryLine : queryLines) {
            if (queryLine.isComplete()) {
                if (!query.isEmpty()) {
                    query.add(queryLine.getBooleanCriteria().getNumericValue());
                }
                query.add(queryLine.getCriteria(), queryLine.getMatchHow().getNumericValue(), queryLine.getMatchWith());
            }
        }
        List<EndEntitySearchResult> results;
        if (!timeConstraint.equals(TimeConstraint.NONE) && !(before == null && after == null)) {
            query.add(timeConstraint.getNumericValue(), after, before, BooleanCriteria.AND.getNumericValue());
        }
        try {
            Collection<EndEntityInformation> userlist = endEntityAccessSession.query(getAdmin(), query,
                    raAuthorization.getCAAuthorizationString(),
                    raAuthorization.getEndEntityProfileAuthorizationString(true, AccessRulesConstants.VIEW_END_ENTITY), 0,
                    AccessRulesConstants.VIEW_END_ENTITY);
            if (userlist.size() > 0) {
                results = compileResults(userlist);
                this.searchResults = new ArrayList<>(results);
            } else {
                this.searchResults = Collections.emptyList();
            }
        } catch (IllegalQueryException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            this.searchResults = Collections.emptyList();
        }
        lastSearch = SearchMethods.ADVANCED;

        return "";
    }

    public String getCertificatePopupLink(final String username) {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "viewcertificate.xhtml?username=" + username;
    }

    public String getViewEndEntityPopupLink(final String username) {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "ra/viewendentity.jsp?username=" + username;
    }

    public String getEditEndEntityPopupLink(final String username) {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "ra/editendentity.jsp?username=" + username;
    }

    /**
     * Search for all end entities with a status
     */
    public String performSearchByExpiry() {
        if (searchByExpiryDays != null) {
            LocalDate expiryTime = LocalDate.now().plusDays(searchByExpiryDays);
            Collection<String> usernames = certificateStoreSession
                    .findUsernamesByExpireTimeWithLimit(Date.from(expiryTime.atStartOfDay(ZoneId.systemDefault()).toInstant()));
            List<EndEntityInformation> endEntities = new ArrayList<>();
            Iterator<String> i = usernames.iterator();
            while (i.hasNext() && endEntities.size() <= getMaximumQueryRowCount() + 1) {
                EndEntityInformation user = null;
                try {
                    user = endEntityAccessSession.findUser(getAdmin(), i.next());
                } catch (AuthorizationDeniedException e) {
                    // Non super-admin access.
                }
                if (user != null) {
                    endEntities.add(user);
                }
            }
            List<EndEntitySearchResult> results = compileResults(endEntities);
            this.searchResults = new ArrayList<>(results);
            lastSearch = SearchMethods.BY_EXPIRY;
        } else {
            this.searchResults = Collections.emptyList();
        }
        return "";

    }

    public String revokeSelected() {
        for (EndEntitySearchResult selectedResult : selectedResults) {
            try {
                endEntityManagementSession.revokeUser(getAdmin(), selectedResult.getUsername(), selectedRevocationReason);
            } catch (NoSuchEndEntityException | ApprovalException | AlreadyRevokedException |
                     AuthorizationDeniedException
                     | WaitingForApprovalException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        selectedResults = new ArrayList<>();
        repeatLastSearch();

        return "";
    }

    public String revokeAndDeleteSelected() {
        for (EndEntitySearchResult selectedResult : selectedResults) {
            try {
                endEntityManagementSession.revokeAndDeleteUser(getAdmin(), selectedResult.getUsername(), selectedRevocationReason);
            } catch (NoSuchEndEntityException | ApprovalException | AuthorizationDeniedException
                     | WaitingForApprovalException | CouldNotRemoveEndEntityException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        selectedResults = new ArrayList<>();
        repeatLastSearch();

        return "";
    }

    public String deleteSelected() {
        for (EndEntitySearchResult selectedResult : selectedResults) {
            try {
                endEntityManagementSession.deleteUser(getAdmin(), selectedResult.getUsername());
            } catch (NoSuchEndEntityException | AuthorizationDeniedException | CouldNotRemoveEndEntityException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        selectedResults = new ArrayList<>();
        repeatLastSearch();

        return "";
    }


    private void repeatLastSearch() {
        switch (lastSearch) {
            case BY_EXPIRY:
                performSearchByExpiry();
                break;
            case BY_NAME:
                performSearchByName();
                break;
            case BY_SERIALNUMBER:
                performSearchBySerialNumber();
                break;
            case BY_STATUS:
                performSearchByStatus();
                break;
            case ADVANCED:
                performAdvancedSearch();
                break;
            default:
                break;
        }

    }

    /**
     * @return the maximum size of the result from SQL select queries
     */
    private int getMaximumQueryRowCount() {
        GlobalCesecoreConfiguration globalConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        return globalConfiguration.getMaximumQueryCount();
    }

    public List<EndEntitySearchResult> getSearchResults() {
        return searchResults;
    }

    public String getSearchBySerialNumber() {
        return searchBySerialNumber;
    }

    public void setSearchBySerialNumber(String searchBySerialNumber) {
        this.searchBySerialNumber = searchBySerialNumber;
    }

    /**
     * Gets a list of select items of the available certificate profiles.
     *
     * @return the list.
     */
    public List<SelectItem> getAvailableStatuses() {
        return availableStatusCodes;
    }

    public Integer getSearchByStatusCode() {
        return searchByStatusCode;
    }

    public void setSearchByStatusCode(Integer searchByStatusCode) {
        this.searchByStatusCode = searchByStatusCode;
    }

    /**
     * Gets a list of select items of the available certificate profiles.
     *
     * @return the list.
     */
    public List<SelectItem> getRevocationReasons() {
        return revocationReasons;
    }


    public Integer getSearchByExpiryDays() {
        return searchByExpiryDays;
    }

    public void setSearchByExpiryDays(Integer searchByExpiryDays) {
        this.searchByExpiryDays = searchByExpiryDays;
    }

    public List<EndEntitySearchResult> getSelectedResults() {
        return selectedResults;
    }

    public void setSelectedResults(List<EndEntitySearchResult> selectedResults) {
        this.selectedResults = selectedResults;
    }

    /**
     * @return true if current administrator has general revocation rights
     */
    public boolean getMayRevoke() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_REVOKEENDENTITY);
    }

    public boolean getMayDelete() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_DELETEENDENTITY);
    }

    public int getSelectedRevocationReason() {
        return selectedRevocationReason;
    }

    public void setSelectedRevocationReason(int selectedRevocationReason) {
        this.selectedRevocationReason = selectedRevocationReason;
    }

    public List<QueryLine> getQueryLines() {
        return queryLines;
    }

    public void setQueryLines(List<QueryLine> queryLines) {
        this.queryLines = queryLines;
    }

    public List<SelectItem> getSearchCriteria() {
        return searchCriteria;
    }

    public List<SelectItem> getBooleanCriteria() {
        return booleanCriteria;
    }

    /**
     * Adds a new "Add Constraint" line if all existing Boolean Criteria lines are used.
     */
    public void addQueryLine() {
        final long unusedBooleanCriteriaLineCount = queryLines.stream()
                .filter(queryLine -> !queryLine.isBooleanCriteriaChosen())
                .count();

        if (unusedBooleanCriteriaLineCount == 0) {
            queryLines.add(new QueryLine(null, UserMatch.MATCH_NONE));
        }
    }

    public List<SelectItem> getTimeConstraintValues() {
        return Arrays.asList(new SelectItem(TimeConstraint.NONE, TimeConstraint.NONE.getLabel()),
                new SelectItem(TimeConstraint.CREATED, TimeConstraint.CREATED.getLabel()),
                new SelectItem(TimeConstraint.MODIFIED, TimeConstraint.MODIFIED.getLabel()));
    }

    public boolean isTimeConstraintChosen() {
        return timeConstraint != null && !timeConstraint.equals(TimeConstraint.NONE);
    }

    public TimeConstraint getTimeConstraint() {
        return timeConstraint;
    }

    public void setTimeConstraint(TimeConstraint timeConstraint) {
        this.timeConstraint = timeConstraint;
    }

    public Date getAfter() {
        return after;
    }

    public void setAfter(Date after) {
        this.after = after;
    }

    public Date getBefore() {
        return before;
    }

    public void setBefore(Date before) {
        this.before = before;
    }

    public void clearAfter() {
        this.after = null;
    }

    public void clearBefore() {
        this.before = null;
    }

    public class EndEntitySearchResult implements Serializable {
        private static final long serialVersionUID = 1L;
        private final EndEntityInformation endEntityInformation;
        private final String caName;

        public EndEntitySearchResult(final EndEntityInformation endEntityInformation, final String caName) {
            this.endEntityInformation = endEntityInformation;
            this.caName = caName;
        }

        public String getUsername() {
            return endEntityInformation.getUsername();
        }

        public String getCaName() {
            return caName;
        }

        public String getCommonName() {
            return CertTools.getCommonNameFromSubjectDn(endEntityInformation.getCertificateDN());
        }

        public String getStatus() {
            return EndEntityConstants.getStatusText(endEntityInformation.getStatus());
        }
    }

    private enum SearchMethods {
        BY_EXPIRY, BY_NAME, BY_SERIALNUMBER, BY_STATUS, ADVANCED;
    }

    private enum MatchHow {
        EQUALS("Equals", BasicMatch.MATCH_TYPE_EQUALS), BEGINSWITH("Begins with", BasicMatch.MATCH_TYPE_BEGINSWITH);

        private final String label;
        private final int numericValue;

        private MatchHow(String label, int numericValue) {
            this.label = label;
            this.numericValue = numericValue;
            ;
        }

        public String getLabel() {
            return label;
        }

        public int getNumericValue() {
            return numericValue;
        }

    }

    private enum TimeConstraint {
        NONE("None", NO_TIME_MATCH), CREATED("Created", TimeMatch.MATCH_WITH_TIMECREATED), MODIFIED("Modified", TimeMatch.MATCH_WITH_TIMEMODIFIED);

        private final String label;
        private final int numericValue;

        private TimeConstraint(final String label, int numericValue) {
            this.label = label;
            this.numericValue = numericValue;
        }

        public String getLabel() {
            return label;
        }

        public int getNumericValue() {
            return numericValue;
        }

    }

    public class QueryLine implements Serializable {
        private static final long serialVersionUID = 1L;

        private BooleanCriteria booleanCriteria;

        private int criteria;
        private MatchHow matchHow;
        private String matchWith;

        private List<SelectItem> matchOptions = new ArrayList<>();

        public QueryLine(BooleanCriteria booleanCriteria, int criteria) {
            this.booleanCriteria = booleanCriteria;
            this.criteria = criteria;
        }

        public int getCriteria() {
            return criteria;
        }

        public void setCriteria(int criteria) {
            this.criteria = criteria;
            matchOptions = new ArrayList<>();
            if (criteria != UserMatch.MATCH_NONE) {
                for (MatchHow matchHow : matchMap.get(criteria)) {
                    matchOptions.add(new SelectItem(matchHow, matchHow.getLabel()));
                }
            }
        }

        public boolean isNotFirst() {
            return booleanCriteria != BooleanCriteria.FIRST;
        }

        public boolean isNotInitialized() {
            return booleanCriteria == null;
        }

        public BooleanCriteria getBooleanCriteria() {
            return booleanCriteria;
        }

        public void setBooleanCriteria(BooleanCriteria booleanCriteria) {
            this.booleanCriteria = booleanCriteria;
        }

        public boolean isComplete() {
            return isBooleanCriteriaChosen() && isCriteriaChosen() && matchHow != null && !StringUtils.isEmpty(matchWith);
        }

        public boolean isCriteriaChosen() {
            return criteria != UserMatch.MATCH_NONE;
        }

        public boolean isBooleanCriteriaChosen() {
            return this.booleanCriteria != null;
        }

        public MatchHow getMatchHow() {
            return matchHow;
        }

        public void setMatchHow(MatchHow matchHow) {
            this.matchHow = matchHow;
        }

        public List<SelectItem> getMatchOptions() {
            return matchOptions;
        }

        public String getMatchWithLabel(String matchWith) {
            final String returnValue;
            if (StringUtils.isNotEmpty(matchWith)) {
                switch (criteria) {
                    case UserMatch.MATCH_WITH_CA:
                        returnValue = caSession.getCAIdToNameMap().get(Integer.valueOf(matchWith));
                        break;
                    case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
                        returnValue = certificateProfileSession.getCertificateProfileName(Integer.valueOf(matchWith));
                        break;
                    case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
                        returnValue = endEntityProfileSession.getEndEntityProfileName(Integer.valueOf(matchWith));
                        break;
                    case UserMatch.MATCH_WITH_STATUS:
                        returnValue = getEjbcaWebBean().getText(EndEntityConstants.getTranslatableStatusText(Integer.valueOf(matchWith)));
                        break;
                    default:
                        returnValue = matchWith;
                        break;
                }
            } else {
                returnValue = null;
            }

            return returnValue;
        }

        public String getMatchWith() {
            return matchWith;
        }

        public void setMatchWith(String matchWith) {
            this.matchWith = matchWith;
        }

        public List<String> getMatchWithValuesIds() {
            List<String> result = null;
            switch (criteria) {
                case UserMatch.MATCH_NONE:

                    break;
                case UserMatch.MATCH_WITH_CA:
                    result = matchWithCa;
                    break;
                case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
                    result = matchWithCertificateProfile;
                    break;
                case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
                    result = matchWithEndEntityProfile;
                    break;
                case UserMatch.MATCH_WITH_STATUS:
                    result = availableAdvancedStatusCodes;
                    break;

                default:
                    break;
            }
            return result;
        }

        public List<SelectItem> getMatchWithValuesSelectItems() {
            final List<SelectItem> result = new ArrayList<>();
            final List<String> matchIds = getMatchWithValuesIds();
            if (matchIds == null) {
                return null;
            }
            for (final String id : matchIds) {
                result.add(new SelectItem(id, getMatchWithLabel(id)));
            }
            result.sort(new SelectItemComparator());
            return result;
        }

        public boolean isTextEditable() {
            return criteria != UserMatch.MATCH_WITH_CA &&
                    criteria != UserMatch.MATCH_WITH_CERTIFICATEPROFILE &&
                    criteria != UserMatch.MATCH_WITH_ENDENTITYPROFILE &&
                    criteria != UserMatch.MATCH_WITH_STATUS;
        }

        /**
         * Called when the criteria is changed.
         * @param event Event from JSF
         */
        public void criteriaChanged(final FacesEvent event) {
            setMatchWith("");
        }

    }

    private enum BooleanCriteria {
        FIRST(-1), AND(Query.CONNECTOR_AND), OR(Query.CONNECTOR_OR), AND_NOT(Query.CONNECTOR_ANDNOT), OR_NOT(Query.CONNECTOR_ORNOT);

        private final int numericValue;

        private BooleanCriteria(int numericValue) {
            this.numericValue = numericValue;
        }

        protected int getNumericValue() {
            return numericValue;
        }
    }

}