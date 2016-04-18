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
import java.util.Arrays;
import java.util.List;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

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

    private final List<CertificateDataWrapper> results = new ArrayList<>();
    private final List<CertificateDataWrapper> resultsFiltered = new ArrayList<>();
    private List<CAInfo> caInfos = null;
    private int criteriaCaId;
    private String filterUsername = "";

    private RaCertificateSearchRequest lastExecutedRequest = new RaCertificateSearchRequest();
    private RaCertificateSearchResponse lastExecutedResponse = new RaCertificateSearchResponse();
    private String basicSearch = "";
    public String getBasicSearch() { return basicSearch; }
    public void setBasicSearch(final String basicSearch) { this.basicSearch = basicSearch; }
    
    public void basicSearchAction() {
        basicSearchCommon();
    }

    public void basicSearchAjaxListener(final AjaxBehaviorEvent event) {
        basicSearchCommon();
    }
    
    public void basicSearchCommon() {
        // TODO: Have a "current" request object that has functions for comparisons of all values with last request
        if (!basicSearch.trim().isEmpty() && basicSearch.equals(lastExecutedRequest.getBasicSearch())) {
            log.info("DEVELOP: Same search. Ignoring.");
            return;
        }
        boolean search = true;
        if (!basicSearch.trim().isEmpty() && basicSearch.contains(lastExecutedRequest.getBasicSearch())) {
            // More narrow search → filter and check if there are sufficient results left
            log.info("DEVELOP: More narrow → filter");
            basicSearchCommonFilter();
            // Check if there are sufficient results to fill screen and search for more
            if (resultsFiltered.size()<20 && lastExecutedResponse.isMightHaveMoreResults()) {
                log.info("DEVELOP: Trying to load more results since filter left too few results");
                search = true;
            } else {
                search = false;
            }
        }
        if (search) {
            // Wider search → Query back-end
            log.info("DEVELOP: Wider → Query");
            RaCertificateSearchRequest request = new RaCertificateSearchRequest();
            final List<Integer> caIds = new ArrayList<>(Arrays.asList(new Integer[]{ criteriaCaId }));
            request.setCaIds(caIds);
            request.setBasicSearch(basicSearch);
            lastExecutedResponse = raMasterApiProxyBean.searchForCertificates(raAuthenticationBean.getAuthenticationToken(), request);
            lastExecutedRequest = request;
            results.clear();
            results.addAll(lastExecutedResponse.getCdws());
            resultsFiltered.clear();
            resultsFiltered.addAll(results);
        }
    }

    private void basicSearchCommonFilter() {
        resultsFiltered.clear();
        for (final CertificateDataWrapper cdw : results) {
            if (!basicSearch.isEmpty() && (
                    (cdw.getCertificateData().getUsername() == null || !cdw.getCertificateData().getUsername().contains(basicSearch)) &&
                    (cdw.getCertificateData().getSubjectDN() == null || !cdw.getCertificateData().getSubjectDN().contains(basicSearch)))) {
                continue;
            }
            // if (this or that) { ...
            resultsFiltered.add(cdw);
        }
    }

    public int getCriteriaCaId() { return criteriaCaId; }
    public void setCriteriaCaId(int criteriaCaId) { this.criteriaCaId = criteriaCaId; }

    public String getFilterUsername() { return filterUsername; }
    public void setFilterUsername(String filterUsername) { this.filterUsername = filterUsername.trim().toLowerCase(raLocaleBean.getLocale()); }

    public List<SelectItem> getAvailableCas() {
        if (caInfos==null) {
            caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
        }
        final List<SelectItem> ret = new ArrayList<>();
        for (CAInfo caInfo : caInfos) {
            ret.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
        }
        return ret;
    }

    public List<CertificateDataWrapper> getSearchResults() {
        return results;
    }

    public List<CertificateDataWrapper> getFilteredResults() {
        return resultsFiltered;
    }
}
