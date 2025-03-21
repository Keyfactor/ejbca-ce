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

package org.ejbca.ui.web.admin;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.application.FacesMessage.Severity;
import jakarta.faces.context.FacesContext;
import jakarta.faces.context.Flash;
import jakarta.faces.context.PartialViewContext;
import jakarta.faces.model.SelectItem;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.SelectItemComparator;

/**
 * Base EJBCA JSF Managed Bean, all managed beans of EJBCA should inherit this class
 *
 */
public abstract class BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -8019234011853194880L;
    private static final Logger log = Logger.getLogger(BaseManagedBean.class);

    private static final Map<String, Map<String, Object>> publicConstantCache = new ConcurrentHashMap<>();

    // Reference to AccessRulesConstants.* and StandardRules.*
    final String[] accessRulesConstantString;
    
    /**
     * Initializes authorization assuming authorization required to following resources.
     * @param resources Reference to AccessRulesConstants.* and StandardRules.*
     */
    public BaseManagedBean(final String... resources) {
        this.accessRulesConstantString = resources;
    }
    
    /**
     * Invoked on preRenderView
     * @throws Exception 
     */
    public void authorizedResources() throws Exception {
     // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, accessRulesConstantString);
        } else if (!getEjbcaWebBean().isAuthorizedNoLogSilent(accessRulesConstantString)) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
    }
    
    protected EjbcaWebBean getEjbcaWebBean() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean();
    }

    /**
     * @return returns EjbcaWebBean initialized in "error-mode". Should only be used for error pages
     */
    protected EjbcaWebBean getEjbcaErrorWebBean() {
        return EjbcaJSFHelper.getBean().getEjbcaErrorWebBean();
    }

    /**
     * @return true if the current admin is authorized to the resources or false otherwise
     */
    protected boolean isAuthorizedTo(final String... resources) {
        return getEjbcaWebBean().getEjb().getAuthorizationSession().isAuthorizedNoLogging(getAdmin(), resources);
    }

    protected void addGlobalMessage(final Severity severity, final String messageResource, final Object... params) {
        final String msg = getEjbcaWebBean().getText(messageResource, true, params);
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(severity, msg, msg));
    }

    protected void addErrorMessage(String messageResource, Object... params) {
        if (log.isDebugEnabled()) {
            log.debug("Adding error message: " + messageResource + ": " + StringUtils.join(params, "; "));
        }
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR, getEjbcaWebBean().getText(messageResource, false, params),
                getEjbcaWebBean().getText(messageResource, false, params)));
    }

    protected void addNonTranslatedErrorMessage(String message) {
        if (log.isDebugEnabled()) {
            log.debug("Adding error message: " + message);
        }
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
    }

    /**
     * Adds the message from an exception, or a general error message refering to the logs if the exception lacks a message.
     *
     * @param exception Exception. Intentionally takes an Exception and rather than a Throwable, since you shouldn't catch Throwable anyway.
     */
    protected void addNonTranslatedErrorMessage(final Exception exception) {
        String msg = exception.getMessage();
        if (msg == null) {
            msg = "An error occurred. The server log may contain more details.";
            log.info("Exception occurred in Admin Web interface", exception);
        } else {
            msg = "Error: " + msg;
            log.debug("Exception occurred in Admin Web interface, adding error message", exception);
        }
        addNonTranslatedErrorMessage(msg);
    }

    protected void addInfoMessage(String messageResource, Object... params) {
        if (log.isDebugEnabled()) {
            log.debug("Adding info message: " + messageResource + ": " + StringUtils.join(params, "; "));
        }
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_INFO, getEjbcaWebBean().getText(messageResource, false, params),
                getEjbcaWebBean().getText(messageResource, false, params)));
    }

    protected void addNonTranslatedInfoMessage(final String message) {
        if (log.isDebugEnabled()) {
            log.debug("Adding info message: " + message);
        }
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_INFO, message, message));
    }

    /**
     * Removes all messages added with addErrorMessage, addInfoMessage, etc.
     */
    protected void clearMessages() {
        FacesContext.getCurrentInstance().getClientIdsWithMessages().forEachRemaining(clientId -> {
            final List<FacesMessage> messageList = FacesContext.getCurrentInstance().getMessageList(clientId);
            if (messageList != null && !messageList.isEmpty()) { // Don't try to clear Collections.EMPTY_LIST
                messageList.clear();
            }
        });
    }

    protected AuthenticationToken getAdmin() {
        return EjbcaJSFHelper.getBean().getAdmin();
    }

    /**
     * Return the public constants of classObject as a Map, so they can be referenced from the JSF page.
     * (The implementation caches the Map for subsequent calls.)
     */
    protected Map<String, Object> getPublicConstantsAsMap(Class<?> classObject) {
        Map<String, Object> result = publicConstantCache.get(classObject.getName());
        if (result != null) {
            return result;
        }
        result = new HashMap<>();
        Field[] publicFields = classObject.getFields();
        for (Field publicField : publicFields) {
            String name = publicField.getName();
            try {
                result.put(name, publicField.get(null));
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
        publicConstantCache.put(classObject.getName(), result);
        return result;
    }

    /**
     * Sort the provided list by the SelectItems' labels.
     */
    protected void sortSelectItemsByLabel(List<SelectItem> selectItems) {
        selectItems.sort(new SelectItemComparator());
    }

    /**
     * Perform a post-redirect-get if the requests is not invoked via AJAX to the current view id with the specified request string appended.
     * <p>
     * It will try to preserve FacesMessages using the bug-riddled Flash scope.
     */
    protected void nonAjaxPostRedirectGet(final String requestString) {
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        final PartialViewContext partialViewContext = facesContext.getPartialViewContext();
        if (!partialViewContext.isAjaxRequest()) {
            final String viewUrl = facesContext.getApplication().getViewHandler().getActionURL(facesContext, facesContext.getViewRoot().getViewId());
            final Flash flash = facesContext.getExternalContext().getFlash();
            flash.setKeepMessages(true);
            final String url = viewUrl + (requestString == null ? "" : requestString);
            if (log.isDebugEnabled()) {
                log.debug("Trying Post-Redirect-Get to '" + url + "'.");
            }
            try {
                facesContext.getExternalContext().redirect(url);
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Post-Redirect-Get to '" + url + "' failed: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Performs a redirect with the given parameters names and parameter values.
     *
     * @param url                    URL (without query string)
     * @param parameterKeysAndValues Alternating names and values. These are escaped.
     * @throws IllegalArgumentException if a parameter name is invalid.
     */
    protected void redirect(final String url, final Object... parameterKeysAndValues) {
        boolean firstParam = url.indexOf('?') == -1;
        try {
            final StringBuilder sb = new StringBuilder(url);
            for (int i = 0; i < parameterKeysAndValues.length; i += 2) {
                final String name = (String) parameterKeysAndValues[i];
                if (!name.matches("^[a-zA-Z0-9_:-]+$")) {
                    final RuntimeException exception = new IllegalArgumentException("Internal error: Invalid URL parameter name");
                    log.warn("Invalid URL request parameter name, this is a bug: " + name, exception);
                    throw exception;
                }
                final String value = URLEncoder.encode(String.valueOf(parameterKeysAndValues[i + 1]), "UTF-8");
                sb.append(firstParam ? '?' : '&');
                sb.append(name);
                sb.append('=');
                sb.append(value);
                firstParam = false;
            }
            final String fullUrl = sb.toString();
            if (log.isDebugEnabled()) {
                log.debug("Redirecting to URL: " + fullUrl);
            }
            FacesContext.getCurrentInstance().getExternalContext().redirect(fullUrl);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Dummy method to force a client-server roundtrip, for example for "reload" buttons
     */
    public void doNothing() {
        // does nothing
    }
    
    public List<SelectItem> getAvailableApprovalProfiles() {
        List<SelectItem> ret = new ArrayList<>();
        ApprovalProfileSession approvalProfileSession = getEjbcaWebBean().getEjb().getApprovalProfileSession();
        Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        Set<Entry<Integer, String>> entries = approvalProfiles.entrySet();
        for(Entry<Integer, String> entry : entries) {
            ret.add(new SelectItem(entry.getKey(), entry.getValue()));
        }
        // Sort list by name
        ret.sort((a, b) -> a.getLabel().compareToIgnoreCase(b.getLabel()));
        ret.add(0, new SelectItem(-1, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("NONE")));
        return ret;
    }

}
