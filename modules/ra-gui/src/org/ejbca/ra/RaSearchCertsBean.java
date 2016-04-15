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
import java.util.Locale;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
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

    public void actionSearch() {
        final List<Integer> caIds = new ArrayList<>(Arrays.asList(new Integer[]{ criteriaCaId }));
        results.clear();
        results.addAll(raMasterApiProxyBean.searchForCertificates(raAuthenticationBean.getAuthenticationToken(), caIds));
        // Apply default filter
        actionFilter();
    }

    public void filterAjaxListener(final AjaxBehaviorEvent event) {
        actionFilter();
    }
    
    public void actionFilter() {
        resultsFiltered.clear();
        final Locale locale = raLocaleBean.getLocale();
        for (final CertificateDataWrapper cdw : results) {
            if (!filterUsername.isEmpty() && (cdw.getCertificateData().getUsername() == null ||
                    !cdw.getCertificateData().getUsername().toLowerCase(locale).contains(filterUsername))) {
                continue;
            }
            // if (this or that) { ...
            resultsFiltered.add(cdw);
        }
    }
}
