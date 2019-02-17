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
package org.ejbca.ui.web.admin.mypreferences;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.configuration.WebLanguage;
import org.ejbca.ui.web.configuration.exception.AdminDoesntExistException;
import org.ejbca.ui.web.configuration.exception.AdminExistsException;

/**
 * JavaServer Faces Managed Bean for managing MyPreferences.
 * Session scoped and will cache the user preferences.
 *
 * @version $Id$
 */
public class MyPreferencesMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 2L;

    private AdminPreference adminPreference;

    List<SelectItem> availableLanguages;
    List<SelectItem> availableThemes;
    List<SelectItem> possibleEntriesPerPage;


    // Authentication check and audit log page access request
    public void initialize(final ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);

            adminPreference = getEjbcaWebBean().getAdminPreference();
            initAvailableLanguages();
            initThemes();
            initPossibleEntriesPerPage();
        }
    }

    private void initAvailableLanguages() {
        availableLanguages = new ArrayList<>();
        final List<WebLanguage> availableWebLanguages = getEjbcaWebBean().getWebLanguagesList();
        for (final WebLanguage availableWebLanguage : availableWebLanguages) {
            final SelectItem availableLanguage = new SelectItem(availableWebLanguage.getId(), availableWebLanguage.toString());
            availableLanguages.add(availableLanguage);
        }
    }

    private void initThemes() {
        availableThemes = new ArrayList<>();
        final String[] themes = getEjbcaWebBean().getGlobalConfiguration().getAvailableThemes();
        for (final String theme : themes) {
            final SelectItem availableTheme = new SelectItem(theme);
            availableThemes.add(availableTheme);
        }
    }

    private void initPossibleEntriesPerPage() {
        possibleEntriesPerPage = new ArrayList<>();
        final String[] possibleEntiresPerPage = getEjbcaWebBean().getGlobalConfiguration().getPossibleEntiresPerPage();
        for (final String value : possibleEntiresPerPage) {
            final SelectItem possibleEntryValue = new SelectItem(Integer.parseInt(value));
            possibleEntriesPerPage.add(possibleEntryValue);
        }
    }

    public AdminPreference getAdminPreference() {
        return adminPreference;
    }

    public List<SelectItem> getAvailableLanguages() {
        return availableLanguages;
    }

    public List<SelectItem> getAvailableThemes() {
        return availableThemes;
    }

    public List<SelectItem> getPossibleEntriesPerPage() {
        return possibleEntriesPerPage;
    }

    /**
     * Save and redirect to adminweb root page.
     * @throws IOException
     */
    public void save() throws IOException {
        try {
            if(!getEjbcaWebBean().existsAdminPreference()){
                getEjbcaWebBean().addAdminPreference(adminPreference);
            }
            else{
                getEjbcaWebBean().changeAdminPreference(adminPreference);
            }
        } catch (final AdminExistsException e) {
            addNonTranslatedErrorMessage(e);
        } catch (final AdminDoesntExistException e) {
            addNonTranslatedErrorMessage(e);
        }
        redirectToAdminweb();
    }

    /**
     * revert all values on page and redirect to adminweb root page
     * @throws IOException
     */
    public void cancel() throws IOException {
        reset();
        redirectToAdminweb();
    }

    private void redirectToAdminweb() throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(ec.getRequestContextPath());
    }

    private void reset() {
        adminPreference = getEjbcaWebBean().getAdminPreference();
    }
}
