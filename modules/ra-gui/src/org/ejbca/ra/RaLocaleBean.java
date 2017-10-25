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
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import javax.ejb.EJB;
import javax.faces.application.Application;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;

/**
 * JSF Managed Bean for handling localization of clients.
 * 
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class RaLocaleBean implements Serializable {

    private static final String LEFT_TO_RIGHT = "ltr";
    private static final String RIGHT_TO_LEFT = "rtl";
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaLocaleBean.class);
    
    private Locale locale = null;
    private boolean directionLeftToRight = true;

    @EJB
    private AdminPreferenceSessionLocal adminPreferenceSession;
    
    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    
    public void setRaAuthenticationBean(RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }
    
    /** @return this sessions Locale */
    public Locale getLocale() {

        Locale localeFromDB = adminPreferenceSession.getCurrentRaLocale(raAuthenticationBean.getAuthenticationToken());

        if (localeFromDB != null) {
            locale = localeFromDB;
        } else {
            if (locale == null) {
                final FacesContext facesContext = FacesContext.getCurrentInstance();
                final Locale requestLocale = facesContext.getExternalContext().getRequestLocale();
                if (getSupportedLocales().contains(requestLocale)) {
                    locale = requestLocale;
                } else {
                    locale = facesContext.getApplication().getDefaultLocale();
                }
                directionLeftToRight = isDirectionLeftToRight(locale);
            }
        }
        return locale;
    }
    /** Set this sessions Locale */
    public void setLocale(final Locale locale) {

        this.locale = locale;
        directionLeftToRight = isDirectionLeftToRight(locale);
    }

    /** @return a list of all locales as defined in faces-config.xml */
    public List<Locale> getSupportedLocales() {
        final Application application = FacesContext.getCurrentInstance().getApplication();
        final Iterator<Locale> iterator = application.getSupportedLocales();
        final List<Locale> ret = new ArrayList<Locale>();
        while (iterator.hasNext()) {
            ret.add(iterator.next());
        }
        final Locale defaultLocale = application.getDefaultLocale();
        if (!ret.contains(defaultLocale)) {
            ret.add(defaultLocale);
        }
        Collections.sort(ret, new Comparator<Locale>() {
            @Override
            public int compare(Locale o1, Locale o2) {
                return o1.getLanguage().compareTo(o2.getLanguage());
            }
        });
        return ret;
    }

    /** @return true if the language direction is left to right */
    private boolean isDirectionLeftToRight(final Locale locale) {
        final int directionality = Character.getDirectionality(locale.getDisplayName(locale).charAt(0));
        log.debug("directionality is " + directionality + " for " + locale.getLanguage() + " (" + locale.getDisplayName(locale) + ").");
        return directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT && directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC &&
                directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_EMBEDDING && directionality != Character.DIRECTIONALITY_RIGHT_TO_LEFT_OVERRIDE;
    }

    /** @return true if the language direction is left to right */
    public String getDirection() {
        return directionLeftToRight ? LEFT_TO_RIGHT : RIGHT_TO_LEFT;
    }

    /** @return true if the language direction is left to right */
    public String getIndentionDirection() {
        return directionLeftToRight ? "left" : "right";
    }
    
    /** @returns the reverse of the standard value, for cases when text needs to be aligned to the other side. */
    public String getReverseIndentationDirection() {
        return !directionLeftToRight ? "left" : "right";
    }

    /** Add a faces message with the localized message summary with level FacesMessage.SEVERITY_ERROR. */
    public void addMessageError(final String messageKey, final Object...params) {
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getMessage(messageKey, params), null));
    }
    
    /** Add a faces message with the localized error code message with level FacesMessage.SEVERITY_ERROR. */
    public void addMessageError(ErrorCode errorCode) {
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, getErrorCodeMessage(errorCode), null));
    }

    /** Add a faces message with the localized message summary with level FacesMessage.SEVERITY_WARN. */
    public void addMessageWarn(final String messageKey, final Object...params) {
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_WARN, getMessage(messageKey, params), null));
    }

    /** Add a faces message with the localized message summary with level FacesMessage.SEVERITY_INFO. */
    public void addMessageInfo(final String messageKey, final Object...params) {
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, getMessage(messageKey, params), null));
    }

    /**
     * Find localized message template and replace the {number} place holders with the provided parameters.
     * In the case where the localized language template is not available, the template from the default language will be tried.
     * 
     * @param messageKey the message key
     * @param params to replace place holders with. Evaluated with String.valueOf() (null-safe).
     * @return the localized message or "???messageKey???" if no key way found.
     */
    public String getMessage(final String messageKey, final Object...params) {
        if (messageKey==null) {
            return "???null???";
        }
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        String messageTemplate = null;
        try {
            final ResourceBundle resourceBundle = facesContext.getApplication().getResourceBundle(facesContext, "msg");
            messageTemplate = resourceBundle.getString(messageKey);
        } catch (MissingResourceException e) {
            // Fall-back to trying the default locale
            facesContext.getViewRoot().setLocale(facesContext.getApplication().getDefaultLocale());
            try {
                final ResourceBundle resourceBundle = facesContext.getApplication().getResourceBundle(facesContext, "msg");
                messageTemplate = resourceBundle.getString(messageKey);
            } catch (MissingResourceException e2) {
                return "???" + messageKey + "???";
            } finally {
                FacesContext.getCurrentInstance().getViewRoot().setLocale(getLocale());
            }
        }
        final StringBuilder sb = new StringBuilder(messageTemplate);
        // Go backwards so if the value was the same a placeholder tag, we wont be affected
        if (params.length>0) {
            for (int i=params.length-1; i>=0; i--) {
                final String placeHolder = "{"+i+"}";
                final int currentIndex = sb.indexOf(placeHolder);
                if (currentIndex==-1) {
                    if (log.isDebugEnabled()) {
                        log.debug("messageKey '" + messageKey + "' was referenced using parameter '" + params[i] + "', but no " + placeHolder + " exists.");
                    }
                    continue;
                }
                sb.replace(currentIndex, currentIndex+placeHolder.length(), String.valueOf(params[i]));
            }
        }
        return sb.toString();
    }
    
    /**
     * Get localized error code.
     * @param errorCode
     * @return localized error code
     */
    public String getErrorCodeMessage(final ErrorCode errorCode){
        if(errorCode == null){
            return "???errorCodeNull???";
        }
        return getMessage("errorcode_" + errorCode.getInternalErrorCode());
    }
    
    /**
     * Wraps the RaLocaleBean.getMessage()
     * @param messageKey the message key
     * @param params to replace place holders with. Evaluated with String.valueOf() (null-safe).
     * @return the localized message or "???messageKey???" if no key way found.
     * @see RaLocalBean.getMessage 
     */
    public FacesMessage getFacesMessage(final String messageKey, final Object...params){
        return new FacesMessage(getMessage(messageKey, params));
    }
}
