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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
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

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    private final EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();

    private transient final List<SelectItem> availableStatusCodes;

    private transient RAAuthorization raAuthorization;

    private String selectedTab = null;
    private String searchByName = null;
    private String searchBySerialNumber = null;
    private Integer searchByStatusCode = null;
    private Integer searchByExpiryDays = null;

    private ListDataModel<EndEntititySearchResult> searchResults = new ListDataModel<>();

    public SearchEndEntitiesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
        availableStatusCodes = new ArrayList<>();
        availableStatusCodes.add(new SelectItem(STATUS_ALL, ejbcaWebBean.getText("ALL")));
        for (Integer statusCode : EndEntityConstants.getAllStatusCodes()) {
            availableStatusCodes.add(new SelectItem(statusCode, ejbcaWebBean.getText(EndEntityConstants.getTranslatableStatusText(statusCode))));
        }

    }

    @PostConstruct
    public void initialize() {
        raAuthorization = new RAAuthorization(getAdmin(), globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
    }

    public List<String> getAvailableTabs() {
        return Arrays.asList("Basic", "Advanced");
    }

    public String getSelectedTab() {
        final String tabHttpParam = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("tab");
        // First, check if the user has requested a valid tab
        List<String> availableTabs = getAvailableTabs();
        if (tabHttpParam != null && availableTabs.contains(tabHttpParam)) {
            // The requested tab is an existing tab. Flush caches so we reload the page content
            flushCache();
            selectedTab = tabHttpParam;
        }
        if (selectedTab == null) {
            // If no tab was requested, we use the first available tab as default
            selectedTab = availableTabs.get(0);
        }
        return selectedTab;
    }

    public void flushCache() {
        searchResults = null;
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
            } else {
                EndEntititySearchResult endEntititySearchResult = new EndEntititySearchResult(endEntityInformation,
                        caIdToNameMap.get(endEntityInformation.getCAId()));
                this.searchResults = new ListDataModel<>(Arrays.asList(endEntititySearchResult));
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e.getMessage());
        }
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

                results = compileResults(userlist);
                this.searchResults = new ListDataModel<>(results);
            } catch (IllegalQueryException e) {
                addNonTranslatedErrorMessage(e.getMessage());
                this.searchResults = new ListDataModel<>();
            }
        }
        return "";
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
        return "";

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

    public Integer getSearchByExpiryDays() {
        return searchByExpiryDays;
    }

    public void setSearchByExpiryDays(Integer searchByExpiryDays) {
        this.searchByExpiryDays = searchByExpiryDays;
    }

}