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
import java.util.Map;

import javax.faces.application.ViewExpiredException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.ejbca.core.model.era.RaMasterBackendUnavailableException;
import org.ejbca.ra.jsfext.RaExceptionHandlerFactory;

/**
 * Bean used to display a summary of unexpected errors and debug log the cause.
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaErrorBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaErrorBean.class);

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private List<Throwable> throwables = null;
    private Integer httpErrorCode = null;

    /** Invoked when error.xhtml is rendered. Add all errors using the current localization. */
    @SuppressWarnings("unchecked")
    public void onErrorPageLoad() {
        final Map<String, Object> requestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
        // Render error caught by RaExceptionHandlerFactory
        if (throwables==null) {
            throwables = (List<Throwable>) requestMap.get(RaExceptionHandlerFactory.REQUESTMAP_KEY);
            requestMap.remove(RaExceptionHandlerFactory.REQUESTMAP_KEY);
        }
        if (throwables==null) {
            log.debug("No error messages to renderer.");
        } else {
            for (final Throwable throwable : throwables) {
                if (throwable instanceof ViewExpiredException) {
                    raLocaleBean.addMessageError("generic_unexpected_problem_sessiontimeout");
                } else if (throwable instanceof RaMasterBackendUnavailableException) {
                    raLocaleBean.addMessageError("generic_unavailable");
                } else {
                    // Return the message of the root cause exception
                    Throwable cause = throwable;
                    while (cause.getCause()!=null) {
                        cause = cause.getCause();
                    }
                    // Log the entire exception stack trace
                    if (log.isDebugEnabled()) {
                        log.debug("Client got the following error message: " + cause.getMessage(), throwable);
                    }
                    raLocaleBean.addMessageError("generic_unexpected_problem_cause", cause.getMessage());
                }
            }
        }
        // Render error caught by web.xml error-page definition
        if (httpErrorCode==null) {
            final Object httpErrorCodeObject = requestMap.get("javax.servlet.error.status_code");
            if (httpErrorCodeObject!=null && httpErrorCodeObject instanceof Integer) {
                httpErrorCode = (Integer) httpErrorCodeObject;
                if (log.isDebugEnabled()) {
                    final String httpErrorUri = String.valueOf(requestMap.get("javax.servlet.error.request_uri"));
                    final String httpErrorMsg = String.valueOf(requestMap.get("javax.servlet.error.message"));
                    log.debug("Client got HTTP error " + httpErrorCode + " when trying to access '" + httpErrorUri + "'. Message was: " + httpErrorMsg);
                }
            }
        }
        if (httpErrorCode!=null) {
            switch (httpErrorCode) {
            case 403: raLocaleBean.addMessageError("generic_unexpected_httperror_403"); break;
            case 404: raLocaleBean.addMessageError("generic_unexpected_httperror_404"); break;
            default: raLocaleBean.addMessageError("generic_unexpected_httperror_default", httpErrorCode); break;
            }
        }
    }
}
