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

import java.math.BigInteger;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.model.ListDataModel;
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
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.TimeMatch;
import org.ejbca.util.query.UserMatch;

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

    private final EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    
    private transient final List<SelectItem> searchCriteria = Arrays.asList(
            new SelectItem(UserMatch.MATCH_NONE, getEjbcaWebBean().getText("SELECT_CRITERIA")),
            new SelectItem(UserMatch.MATCH_WITH_CA, getEjbcaWebBean().getText("MATCHCA")),
            new SelectItem(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, getEjbcaWebBean().getText("MATCHCERTIFICATEPROFILE")),
            new SelectItem(UserMatch.MATCH_WITH_ENDENTITYPROFILE, getEjbcaWebBean().getText("MATCHENDENTITYPROFILE")),
            new SelectItem(UserMatch.MATCH_WITH_STATUS, getEjbcaWebBean().getText("MATCHSTATUS")),
            new SelectItem(UserMatch.MATCH_WITH_EMAIL, getEjbcaWebBean().getText("MATCHEMAILADDRESS")),
            new SelectItem(UserMatch.MATCH_WITH_USERNAME, getEjbcaWebBean().getText("MATCHUSERNAME")),
            new SelectItem(UserMatch.MATCH_WITH_UID, getEjbcaWebBean().getText("MATCHUID")),
            new SelectItem(UserMatch.MATCH_WITH_COMMONNAME, getEjbcaWebBean().getText("MATCHCOMMONNAME")),
            new SelectItem(UserMatch.MATCH_WITH_DNSERIALNUMBER, getEjbcaWebBean().getText("MATCHDNSERIALNUMBER")),
            new SelectItem(UserMatch.MATCH_WITH_GIVENNAME, getEjbcaWebBean().getText("MATCHGIVENNAME")),
            new SelectItem(UserMatch.MATCH_WITH_INITIALS, getEjbcaWebBean().getText("MATCHINITIALS")),
            new SelectItem(UserMatch.MATCH_WITH_SURNAME, getEjbcaWebBean().getText("MATCHSURNAME")),
            new SelectItem(UserMatch.MATCH_WITH_TITLE, getEjbcaWebBean().getText("MATCHTITLE")),
            new SelectItem(UserMatch.MATCH_WITH_ORGANIZATIONALUNIT, getEjbcaWebBean().getText("MATCHORGANIZATIONALUNIT")),
            new SelectItem(UserMatch.MATCH_WITH_ORGANIZATION, getEjbcaWebBean().getText("MATCHORGANIZATION")),
            new SelectItem(UserMatch.MATCH_WITH_LOCALITY, getEjbcaWebBean().getText("MATCHLOCALITY")),
            new SelectItem(UserMatch.MATCH_WITH_STATEORPROVINCE, getEjbcaWebBean().getText("MATCHSTATEORPROVINCE")),
            new SelectItem(UserMatch.MATCH_WITH_DOMAINCOMPONENT, getEjbcaWebBean().getText("MATCHDOMAINCOMPONENT")),
            new SelectItem(UserMatch.MATCH_WITH_COUNTRY, getEjbcaWebBean().getText("MATCHCOUNTRY")));

    private transient final List<SelectItem> booleanCriteria = Arrays.asList(
            new SelectItem(null, "Add Constraint"),
            new SelectItem(BooleanCriteria.AND, "And"),
            new SelectItem(BooleanCriteria.OR, "Or"), 
            new SelectItem(BooleanCriteria.AND_NOT, "And not"),
            new SelectItem(BooleanCriteria.OR_NOT, "Or not"));

    private transient final Map<Integer, MatchHow[]> matchMap = new HashMap<>();

    private transient final List<String> matchWithCa = new ArrayList<>();
    
    private transient final List<String> matchWithCertificateProfile = new ArrayList<>();
    
    private transient final List<String> matchWithEndEntityProfile = new ArrayList<>();
    
    private transient final List<String> availableAdvancedStatusCodes = new ArrayList<>();

    private transient final List<SelectItem> availableStatusCodes;
    
    private transient final List<SelectItem> revocationReasons;

    private transient RAAuthorization raAuthorization;

    //Basic mode values:
    
    private String searchByName = null;
    private String searchBySerialNumber = null;
    private Integer searchByStatusCode = null;
    private Integer searchByExpiryDays = null;

    private ListDataModel<EndEntititySearchResult> searchResults = new ListDataModel<>();
   
    private List<EndEntititySearchResult> selectedResults = new ArrayList<>();
    private int selectedRevocationReason = 0;
    
    private SearchMethods lastSearch = null;
    
    //Advanced mode values:
    
    private List<QueryLine> queryLines = new ArrayList<>();
    
    private TimeConstraint timeConstraint;
    
    private Date notAfter;    
    private Date notBefore;

    public SearchEndEntitiesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_VIEWENDENTITY);
        availableStatusCodes = new ArrayList<>();
        availableStatusCodes.add(new SelectItem(STATUS_ALL, ejbcaWebBean.getText("ALL")));
        for (Integer statusCode : EndEntityConstants.getAllStatusCodes()) {
            availableStatusCodes.add(new SelectItem(statusCode, ejbcaWebBean.getText(EndEntityConstants.getTranslatableStatusText(statusCode))));
        }
        
        revocationReasons = new ArrayList<>();
        for(int i = 0; i < SecConst.reasontexts.length; i++) {
            revocationReasons.add(new SelectItem(i, ejbcaWebBean.getText(SecConst.reasontexts[i])));
        }
        
        //First line is the initial search
        queryLines.add(new QueryLine(BooleanCriteria.FIRST, UserMatch.MATCH_NONE));
        //Second line 
        queryLines.add(new QueryLine(null, UserMatch.MATCH_NONE));

        matchMap.put(UserMatch.MATCH_WITH_CA, new MatchHow[] { MatchHow.EQUALS });
        matchMap.put(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, new MatchHow[] { MatchHow.EQUALS });
        matchMap.put(UserMatch.MATCH_WITH_ENDENTITYPROFILE, new MatchHow[] { MatchHow.EQUALS });
        matchMap.put(UserMatch.MATCH_WITH_STATUS, new MatchHow[] { MatchHow.EQUALS });
        matchMap.put(UserMatch.MATCH_WITH_EMAIL, new MatchHow[] { MatchHow.EQUALS, MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_USERNAME, new MatchHow[] { MatchHow.EQUALS, MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_UID, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_COMMONNAME, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_DNSERIALNUMBER, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_GIVENNAME, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_INITIALS, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_SURNAME, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_TITLE, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_ORGANIZATIONALUNIT, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_ORGANIZATION, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_LOCALITY, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_STATEORPROVINCE, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_DOMAINCOMPONENT, new MatchHow[] { MatchHow.BEGINSWITH });
        matchMap.put(UserMatch.MATCH_WITH_COUNTRY, new MatchHow[] { MatchHow.BEGINSWITH });

    }

    @PostConstruct
    public void initialize() {
        raAuthorization = new RAAuthorization(getAdmin(), globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
        
        for (CAInfo caInfo : caSession.getAuthorizedCaInfos(getAdmin())) {
            matchWithCa.add(Integer.toString(caInfo.getCAId()));
        }
        
        for(int certificateProfileId : certificateProfileSession.getAuthorizedCertificateProfileIds(getAdmin(), CertificateConstants.CERTTYPE_UNKNOWN)) {
            matchWithCertificateProfile.add(Integer.toString(certificateProfileId));
        }
        
        for(int endEntityProfileId : endEntityProfileSession.getAuthorizedEndEntityProfileIds(getAdmin(), AccessRulesConstants.VIEW_END_ENTITY)) {
            matchWithEndEntityProfile.add(Integer.toString(endEntityProfileId));
        }
        
        for (Integer statusCode : EndEntityConstants.getAllStatusCodes()) {
            availableAdvancedStatusCodes.add(statusCode.toString());
        }
    }

    public void flushCache() {
        searchResults = new ListDataModel<>();
        searchByName = null;
        searchBySerialNumber = null;
        searchByStatusCode = null;
        searchByExpiryDays = null;
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
                this.searchResults = new ListDataModel<>();
            } else {
                EndEntititySearchResult endEntititySearchResult = new EndEntititySearchResult(endEntityInformation,
                        caIdToNameMap.get(endEntityInformation.getCAId()));
                this.searchResults = new ListDataModel<>(Arrays.asList(endEntititySearchResult));
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            this.searchResults = new ListDataModel<>();
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
            this.searchResults = new ListDataModel<>();
            return "";
        }
        final List<CertificateDataWrapper> certificateDataWrappers = certificateStoreSession.getCertificateDataBySerno(serno);
        List<EndEntititySearchResult> results = new ArrayList<>();
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        for (final CertificateDataWrapper next : certificateDataWrappers) {
            final CertificateData certdata = next.getCertificateData();
            try {
                final String username = certdata.getUsername();
                if (username != null) {
                    final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(getAdmin(), username);
                    if (endEntityInformation != null) {
                        results.add(new EndEntititySearchResult(endEntityInformation, caIdToNameMap.get(endEntityInformation.getCAId())));
                    }
                }
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        this.searchResults = new ListDataModel<>(results);
        lastSearch = SearchMethods.BY_SERIALNUMBER;
        return "";
    }

    private List<EndEntititySearchResult> compileResults(final Collection<EndEntityInformation> endEntityInformations) {
        List<EndEntititySearchResult> results = new ArrayList<>();
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();

        for (EndEntityInformation endEntityInformation : endEntityInformations) {
            results.add(new EndEntititySearchResult(endEntityInformation, caIdToNameMap.get(endEntityInformation.getCAId())));
        }
        return results;
    }

    /**
     * Search for all end entities with a status
     */
    public String performSearchByStatus() {
        List<EndEntititySearchResult> results;
        if (searchByStatusCode.equals(STATUS_ALL)) {
            results = compileResults(endEntityAccessSession.findAllUsersWithLimit(getAdmin()));
            this.searchResults = new ListDataModel<>(results);
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
                    this.searchResults = new ListDataModel<>(results);
                } else {
                    this.searchResults = new ListDataModel<>();
                }
            } catch (IllegalQueryException e) {
                addNonTranslatedErrorMessage(e.getMessage());
                this.searchResults = new ListDataModel<>();
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
        List<EndEntititySearchResult> results;      
        if(!timeConstraint.equals(TimeConstraint.NONE) && !(notBefore == null && notAfter == null)) {
            query.add(timeConstraint.getNumericValue(), notBefore, notAfter, BooleanCriteria.AND.getNumericValue());
        }        
        try {
            Collection<EndEntityInformation> userlist = endEntityAccessSession.query(getAdmin(), query,
                    raAuthorization.getCAAuthorizationString(),
                    raAuthorization.getEndEntityProfileAuthorizationString(true, AccessRulesConstants.VIEW_END_ENTITY), 0,
                    AccessRulesConstants.VIEW_END_ENTITY);
            if (userlist.size() > 0) {
                results = compileResults(userlist);
                this.searchResults = new ListDataModel<>(results);
            } else {
                this.searchResults = new ListDataModel<>();
            }
        } catch (IllegalQueryException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            this.searchResults = new ListDataModel<>();
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
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "/ra/viewendentity.jsp?username=" + username;
    }
    
    public String getEditEndEntityPopupLink(final String username) {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "/ra/editendentity.jsp?username=" + username;
    }
    
    /**
     * Search for all end entities with a status
     */
    public String performSearchByExpiry() {       
        LocalDate expiryTime = LocalDate.now().plusDays(searchByExpiryDays);
        Collection<String> usernames = certificateStoreSession.findUsernamesByExpireTimeWithLimit(Date.from(expiryTime.atStartOfDay(ZoneId.systemDefault()).toInstant()));
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
        List<EndEntititySearchResult> results = compileResults(endEntities);
        this.searchResults = new ListDataModel<>(results);
        lastSearch = SearchMethods.BY_EXPIRY;
        return "";

    }
    
    public String revokeSelected() {
        for (EndEntititySearchResult selectedResult : selectedResults) {
            try {
                endEntityManagementSession.revokeUser(getAdmin(), selectedResult.getUsername(), selectedRevocationReason);
            } catch (NoSuchEndEntityException | ApprovalException | AlreadyRevokedException | AuthorizationDeniedException
                    | WaitingForApprovalException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        selectedResults = new ArrayList<>();   
        repeatLastSearch();
        
        return "";
    }
    
    public String revokeAndDeleteSelected() {
        for (EndEntititySearchResult selectedResult : selectedResults) {
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
        for (EndEntititySearchResult selectedResult : selectedResults) {
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

    /** @return the maximum size of the result from SQL select queries */
    private int getMaximumQueryRowCount() {
        GlobalCesecoreConfiguration globalConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        return globalConfiguration.getMaximumQueryCount();
    }

    public ListDataModel<EndEntititySearchResult> getSearchResults() {
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

    public List<EndEntititySearchResult> getSelectedResults() {
        return selectedResults;
    }

    public void setSelectedResults(List<EndEntititySearchResult> selectedResults) {
        this.selectedResults = selectedResults;
    }

    /**
     * 
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
    
    public void addQueryLine() {
        //On selecting a boolean criteria, add another potential line 
        queryLines.add(new QueryLine(null, UserMatch.MATCH_NONE));
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

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public class EndEntititySearchResult {
        private final EndEntityInformation endEntityInformation;
        private final String caName;

        public EndEntititySearchResult(final EndEntityInformation endEntityInformation, final String caName) {
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
            this.numericValue = numericValue;;
        }

        public String getLabel() {
            return label;
        }

        public int getNumericValue() {
            return numericValue;
        }

    }

    private enum TimeConstraint {
        NONE("None", NO_TIME_MATCH), CREATED ("Created", TimeMatch.MATCH_WITH_TIMECREATED), MODIFIED("Modified", TimeMatch.MATCH_WITH_TIMEMODIFIED);
        
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
    
    public class QueryLine {
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
            return isCriteriaChosen() && matchHow != null && !StringUtils.isEmpty(matchWith);
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

        public void onCriteraChange() {
            matchOptions = new ArrayList<>();
            if (criteria != UserMatch.MATCH_NONE) {
                for (MatchHow matchHow : matchMap.get(criteria)) {
                    matchOptions.add(new SelectItem(matchHow, matchHow.getLabel()));
                }
            }
        }

        public List<SelectItem> getMatchOptions() {
            return matchOptions;
        }

        public String getMatchWithLabel() {
            final String returnValue;
            if(matchWith != null) {
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
                    returnValue = ejbcaWebBean.getText(EndEntityConstants.getTranslatableStatusText(Integer.valueOf(matchWith)));
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

        public List<String> getMatchWithValues() {
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