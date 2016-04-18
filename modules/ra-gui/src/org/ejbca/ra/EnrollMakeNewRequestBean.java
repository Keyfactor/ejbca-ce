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

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Example of JSF Managed Bean for backing a page. 
 * 
 * @version $Id: EnrollMakeNewRequest.java 23135 2016-04-05 23:05:35Z jeklund $
 */
@ManagedBean
@ViewScoped
public class EnrollMakeNewRequestBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollMakeNewRequestBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    private Map<String, EndEntityProfile> authorizedEndEntityProfiles;
    private String selectedEndEntityProfile;

    @PostConstruct
    private void postContruct() {
        try {
            authorizedEndEntityProfiles = new HashMap<String, EndEntityProfile>();
            setAuthorizedEndEntityProfiles(raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken()));
        } catch (AuthorizationDeniedException e) {
            raLocaleBean.addMessageError("page_initialization_fail", e.getMessage());
        }
    }

    public void submitEndEntityProfiles() throws IOException {
        raLocaleBean.addMessageInfo("somefunction_testok", "Dummy Result", selectedEndEntityProfile);
    }

    /**
     * @return the authorizedEndEntityProfiles
     */
    public Map<String, EndEntityProfile> getAuthorizedEndEntityProfiles() {
        return authorizedEndEntityProfiles;
    }

    /**
     * @param authorizedEndEntityProfiles the authorizedEndEntityProfiles to set
     */
    private void setAuthorizedEndEntityProfiles(Map<String, EndEntityProfile> authorizedEndEntityProfiles) {
        this.authorizedEndEntityProfiles = authorizedEndEntityProfiles;
    }

    /**
     * @return the selectedEndEntityProfile
     */
    public String getSelectedEndEntityProfile() {
        return selectedEndEntityProfile;
    }

    /**
     * @param selectedEndEntityProfile the selectedEndEntityProfile to set
     */
    public void setSelectedEndEntityProfile(String selectedEndEntityProfile) {
        this.selectedEndEntityProfile = selectedEndEntityProfile;
    }

    public final void endEntityProfileListener(final AjaxBehaviorEvent event) {
        raLocaleBean.addMessageInfo("somefunction_testok", "Dummy Result", selectedEndEntityProfile);
    }
}
