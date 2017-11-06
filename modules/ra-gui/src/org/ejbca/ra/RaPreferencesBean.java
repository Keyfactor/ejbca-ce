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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * This is the backing bean supporting the preferences.xhtml page in RA web.
 * Together with preferrences.xhtml it is used to produce the Preferences menu in RA web GUI.
 * 
 * @version $Id$
 *
 */

@ManagedBean
@ViewScoped
public class RaPreferencesBean implements Converter, Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaPreferencesBean.class);
    private static final int DUMMY_STYLE_ARCHIVE_ID = 0;

    @EJB
    private AdminPreferenceSessionLocal adminPreferenceSession;

    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    private Locale currentLocale;

    private RaStyleInfo currentStyle;
    
    /** The previousStyle property is used to keep track of changes in Preferred style dropdown
     *  in case there is no entry in adminprefdata table for current admin. 
    **/ 
    private RaStyleInfo previousStyle; 
 
    private boolean showLocaleInfo = false;

    private boolean showStyleInfo = false;
    
    private boolean applyDisabled = true;

    @PostConstruct
    public void init() {
        initLocale();
        initRaStyle();
    }
    
    public boolean isApplyDisabled() {
        return applyDisabled;
    }
    
    public boolean isShowLocaleInfo() {
        return showLocaleInfo;
    }

    public boolean isShowStyleInfo() {
        return showStyleInfo;
    }
    
    public void toggleShowLocaleInfo() {
        this.showLocaleInfo = !showLocaleInfo;
    }
    
    public void toggleShowStyleInfo() {
        this.showStyleInfo = !showStyleInfo;
    }

    public RaStyleInfo getCurrentStyle() {
        return currentStyle;
    }

    public void setCurrentStyle(final RaStyleInfo newStyle) {
        currentStyle = newStyle;
        if (previousStyle.getArchiveId() == newStyle.getArchiveId()) {
            this.applyDisabled = true;
            return;
        }
        this.applyDisabled = false;
    }

    public Locale getCurrentLocale() {
        return currentLocale;
    }

    public void setCurrentLocale(final Locale locale) {
        this.currentLocale = locale;
    }

    public List<Locale> getLocales() {
        return raLocaleBean.getSupportedLocales();
    }

    public List<RaStyleInfo> getStyles() {

        List<RaStyleInfo> raStyleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());
        
        // This extra list is used to avoid the dummy default RaStyleInfo ending up in the style cache.
        List<RaStyleInfo> raStyleInfosArchiveName = new ArrayList<>();
        
        raStyleInfosArchiveName.add(buildDummyStyleInfo());
        
        for (RaStyleInfo raStyleInfo : raStyleInfos) {
            raStyleInfosArchiveName.add(raStyleInfo);
        }

        return raStyleInfosArchiveName;
    }

    public void localeChanged(final Locale locale) {
        if (raLocaleBean.getLocale().equals(locale)) {
            this.applyDisabled = true;
            return;
        }
        this.applyDisabled = false;
    }

    /**
     * Updates ra admin preferences data in database.
     * Does nothings in case the current data is equal to the data going to be set.
     */
    public void updatePreferences() {

        checkAdminHasRowInDbOrCreateOne();

        Locale previousLocale = adminPreferenceSession.getCurrentRaLocale(raAuthenticationBean.getAuthenticationToken());
        Integer previousRaStyleId = adminPreferenceSession.getCurrentRaStyleId(raAuthenticationBean.getAuthenticationToken());

        if (previousLocale == null || previousRaStyleId == null) {
            adminPreferenceSession.setCurrentRaLocale(currentLocale, raAuthenticationBean.getAuthenticationToken());
            adminPreferenceSession.setCurrentRaStyleId(currentStyle.getArchiveId(), raAuthenticationBean.getAuthenticationToken());
            raLocaleBean.setLocale(currentLocale);
            this.applyDisabled = true;
        } else {
            if (!currentLocale.equals(previousLocale) && (currentStyle.getArchiveId() != previousRaStyleId)) {
                adminPreferenceSession.setCurrentRaLocale(currentLocale, raAuthenticationBean.getAuthenticationToken());
                adminPreferenceSession.setCurrentRaStyleId(currentStyle.getArchiveId(), raAuthenticationBean.getAuthenticationToken());
                raLocaleBean.setLocale(currentLocale);
                this.applyDisabled = true;
            } else if (currentLocale.equals(previousLocale) && (currentStyle.getArchiveId() != previousRaStyleId)) {
                adminPreferenceSession.setCurrentRaStyleId(currentStyle.getArchiveId(), raAuthenticationBean.getAuthenticationToken());
                this.applyDisabled = true;
            } else if (!currentLocale.equals(previousLocale) && (currentStyle.getArchiveId() == previousRaStyleId)) {
                adminPreferenceSession.setCurrentRaLocale(currentLocale, raAuthenticationBean.getAuthenticationToken());
                raLocaleBean.setLocale(currentLocale);
                this.applyDisabled = true;
                return;
            } else {
                return;
            }
        }
        try {
            redirect();
        } catch (IOException e) {
            log.warn("Unexpected error happened while redirecting to index page!");
            reset();
        }
    }

    /**
     * The following two methods are used in converting RaStyleInfo to String and vice versa.
     * Required by JSF.
     */
    @Override
    public Object getAsObject(FacesContext context, UIComponent component, String value) {

        List<RaStyleInfo> styleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());

        for (RaStyleInfo raStyleInfo : styleInfos) {
            if (raStyleInfo.getArchiveName().equals(value)) {
                return raStyleInfo;
            }
        }

        return buildDummyStyleInfo();
    }

    /**
     * Returns the string representation of style items to which are used (and required) by
     * the preferences.xhtml page.
     * It returns the archive name of the style info object to be displayed in the 
     * select preferred theme dropdown in Preferences page in RA-WEB.
     * 
     */
    @Override
    public String getAsString(FacesContext context, UIComponent component, Object value) {

        RaStyleInfo raStyleInfo = (RaStyleInfo) value;
        return raStyleInfo.getArchiveName();
    }

    /**
     * Private helpers
     */

    private void initLocale() {
        Locale localeFromDB = adminPreferenceSession.getCurrentRaLocale(raAuthenticationBean.getAuthenticationToken());

        if (localeFromDB != null) {
            currentLocale = localeFromDB;
        } else {
            currentLocale = raLocaleBean.getLocale();
        }
    }

    private void initRaStyle() {

        RaStyleInfo preferedRaStyle = adminPreferenceSession.getPreferedRaStyleInfo(raAuthenticationBean.getAuthenticationToken());

        if (preferedRaStyle == null) {
            currentStyle = buildDummyStyleInfo();
            previousStyle = buildDummyStyleInfo();
        } else {
            currentStyle = preferedRaStyle;
            previousStyle = preferedRaStyle;
        }
    }
    
    /**
     * This method is used to create a dummy style info object.
     * Since we don't have any item in the styles list to represent the 
     * Default style (which is needed by Preferences page) hence this method
     * is used to create that dummy style when required. Example use in initRaStyle 
     * function above. 
     * @return
     */
    private RaStyleInfo buildDummyStyleInfo() {

        RaStyleInfo dummyStyle = new RaStyleInfo("Default", null, null, "");
        dummyStyle.setArchiveId(DUMMY_STYLE_ARCHIVE_ID);

        return dummyStyle;

    }

    /**
     * Used to reset the preferences page
     * @return
     */
    public String reset() {
        String viewId = FacesContext.getCurrentInstance().getViewRoot().getViewId();
        return viewId + "?faces-redirect=true";
    }
    
    /**
     * Redirects to the pereferences.xhtml. Triggers the java script reload.
     * @throws IOException
     */
    private void redirect() throws IOException {
        ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
        context.redirect(context.getRequestContextPath() + "/preferences.xhtml");
    }
    
    /**
     * Create a row in Admin Preferences Data table for the current admin if it has not any row already.
     * Returns otherwise. 
     */
    private void checkAdminHasRowInDbOrCreateOne() {

        String certificatefingerprint = CertTools
                .getFingerprintAsString(((X509CertificateAuthenticationToken) raAuthenticationBean.getAuthenticationToken()).getCertificate());

        if (!adminPreferenceSession.existsAdminPreference(certificatefingerprint)) {
            adminPreferenceSession.addAdminPreference((X509CertificateAuthenticationToken) raAuthenticationBean.getAuthenticationToken(),
                    new AdminPreference());
        }
    }
}
