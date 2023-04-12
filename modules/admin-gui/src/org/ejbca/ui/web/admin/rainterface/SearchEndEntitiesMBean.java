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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

/**
 * Backing bean for the Search End Entities page in the CA UI. 
 */
@Named("searchEndEntitiesMBean")
@RequestScoped
public class SearchEndEntitiesMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    
    private String selectedTab = null;
    private String searchByName = null;
    private String searchBySerialNumber = null;

    private ListDataModel<EndEntititySearchResult> searchResults = new ListDataModel<>();

    public SearchEndEntitiesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
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
        searchResults = new ListDataModel<>();
        searchByName = null;
        searchBySerialNumber = null;
    }

    public String getSearchByName() {
        return searchByName;
    }

    public void setSearchByName(String searchByName) {
        this.searchByName = searchByName;
    }

    public void performSearchByName() {
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        EndEntityInformation endEntityInformation;
        try {
            endEntityInformation = endEntityAccessSession.findUser(getAdmin(), searchByName);
            if(endEntityInformation == null) {
                addNonTranslatedErrorMessage("No end entity with name " + searchByName + " found.");
            } else {
            String caName = caIdToNameMap.get(endEntityInformation.getCAId());
            EndEntititySearchResult endEntititySearchResult = new EndEntititySearchResult(endEntityInformation, caName);
            
            this.searchResults = new ListDataModel<>(Arrays.asList(endEntititySearchResult));
            }
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e.getMessage());
        }     
    }
    
    public void performSearchBySerialNumber() {
        final BigInteger serno = new BigInteger(StringTools.stripWhitespace(searchBySerialNumber), 16);
        final List<CertificateDataWrapper> certificateDataWrappers = certificateStoreSession.getCertificateDataBySerno(serno);             
        List<EndEntititySearchResult> results = new ArrayList<>();
        for (final CertificateDataWrapper next : certificateDataWrappers) {
            final CertificateData certdata = next.getCertificateData();
            try {
                final String username = certdata.getUsername();
                if (username != null) {
                    final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(getAdmin(), username);
                    if (endEntityInformation != null) {
                        results.add(new EndEntititySearchResult(endEntityInformation, username));
                    }
                }
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }
        this.searchResults = new ListDataModel<>(results);
    }

    public ListDataModel<EndEntititySearchResult> getSearchResults() {
        return searchResults;
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

}