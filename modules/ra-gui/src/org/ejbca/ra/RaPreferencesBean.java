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
import java.util.List;
import java.util.Locale;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.convert.Converter;

import org.apache.log4j.Logger;
import org.cesecore.config.RaStyleInfo;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;

/**
 * 
 * @version $Id$
 *
 */

@ManagedBean
@ViewScoped
public class RaPreferencesBean implements Converter, Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaPreferencesBean.class);

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

    @PostConstruct
    public void init() {
        initLocale();
        initRaStyle();
    }

    public RaStyleInfo getCurrentStyle() {
        return currentStyle;
    }

    public void setCurrentStyle(final RaStyleInfo currentStyle) {
        this.currentStyle = currentStyle;
    }

    public Locale getCurrentLocale() {
        return currentLocale;
    }

    public void setCurrentLocale(final Locale locale) {
        this.currentLocale = locale;
        raLocaleBean.setLocale(locale);
    }

    public List<Locale> getLocales() {
        return raLocaleBean.getSupportedLocales();
    }

    public List<RaStyleInfo> getStyles() {

        List<RaStyleInfo> raStyleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());

        RaStyleInfo dummStyleInfo = new RaStyleInfo("Default", null, null, "");

        dummStyleInfo.setArchiveId(0);

        if (raStyleInfos.contains(dummStyleInfo)) {
            return raStyleInfos;
        } else {
            raStyleInfos.add(0, dummStyleInfo);
            return raStyleInfos;
        }
    }

    /**
     * Updates ra admin preferences data in database.
     * Does nothings in case the current data is equal to the data going to be set.
     */
    public void updatePreferences() {
        adminPreferenceSession.setCurrentRaLocale(currentLocale, raAuthenticationBean.getAuthenticationToken());
        adminPreferenceSession.setCurrentRaStyleId(currentStyle.getArchiveId(), raAuthenticationBean.getAuthenticationToken());
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

        return null;
    }

    @Override
    public String getAsString(FacesContext context, UIComponent component, Object value) {

        RaStyleInfo raStyleInfo = (RaStyleInfo) value;

        return raStyleInfo.getArchiveName();
    }

    /**
     * Used to reset the preferences page
     * @return
     */
    public String reset() {
        String viewId = FacesContext.getCurrentInstance().getViewRoot().getViewId();
        return viewId + "?faces-redirect=true";
    }

    private void initLocale() {
        Locale localeFromDB = adminPreferenceSession.getCurrentRaLocale(raAuthenticationBean.getAuthenticationToken());

        if (localeFromDB != null) {
            currentLocale = localeFromDB;
        } else {
            currentLocale = raLocaleBean.getLocale();
        }

    }

    private void initRaStyle() {

        Integer raStyleFromDB = adminPreferenceSession.getCurrentRaStyleId(raAuthenticationBean.getAuthenticationToken());

        if (raStyleFromDB != null) {

            List<RaStyleInfo> raStyleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());

            for (RaStyleInfo raStyleInfo : raStyleInfos) {
                if (raStyleInfo.getArchiveId() == raStyleFromDB) {
                    currentStyle = raStyleInfo;
                    return;
                }
            }
        }

    }

}
