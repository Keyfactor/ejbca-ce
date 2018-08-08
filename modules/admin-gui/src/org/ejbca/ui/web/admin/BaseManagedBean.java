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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.faces.application.FacesMessage;
import javax.faces.application.FacesMessage.Severity;
import javax.faces.context.FacesContext;
import javax.faces.context.Flash;
import javax.faces.context.PartialViewContext;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.util.SelectItemComparator;

/**
 * Base EJBCA JSF Managed Bean, all managed beans of EJBCA should inherit this class
 *
 * @version $Id$
 */
public abstract class BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -8019234011853194880L;
    private static final Logger log = Logger.getLogger(BaseManagedBean.class);

    private static final Map<String, Map<String, Object>> publicConstantCache = new ConcurrentHashMap<>();

	protected EjbcaWebBean getEjbcaWebBean(){
		return EjbcaJSFHelper.getBean().getEjbcaWebBean();
	}

	/** @return true if the current admin is authorized to the resources or false otherwise */
    protected boolean isAuthorizedTo(final String...resources) {
        return getEjbcaWebBean().getEjb().getAuthorizationSession().isAuthorizedNoLogging(getAdmin(), resources);
    }

    protected void addGlobalMessage(final Severity severity, final String messageResource, final Object... params) {
        final String msg = getEjbcaWebBean().getText(messageResource, true, params);
        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(severity, msg, msg));
    }

	protected void addErrorMessage(String messageResource, Object... params) {
		FacesContext ctx = FacesContext.getCurrentInstance();
		ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,getEjbcaWebBean().getText(messageResource, true, params),getEjbcaWebBean().getText(messageResource, true, params)));
	}

	protected void addNonTranslatedErrorMessage(String messageResource){
		FacesContext ctx = FacesContext.getCurrentInstance();
		ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,messageResource,messageResource));
	}

	protected void addInfoMessage(String messageResource, Object... params) {
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_INFO,getEjbcaWebBean().getText(messageResource, true, params),getEjbcaWebBean().getText(messageResource, true, params)));
    }

    protected void addNonTranslatedInfoMessage(String messageResource){
        FacesContext ctx = FacesContext.getCurrentInstance();
        ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_INFO,messageResource,messageResource));
    }

	protected AuthenticationToken getAdmin(){
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
		for (int i = 0; i < publicFields.length; i++) {
			Field field = publicFields[i];
			String name = field.getName();
			try {
				result.put(name, field.get(null));
			} catch (IllegalArgumentException e) {
				throw new RuntimeException(e);
			} catch (IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		}
		publicConstantCache.put(classObject.getName(), result);
		return result;
	}

	/** Sort the provided list by the SelectItems' labels. */
	protected void sortSelectItemsByLabel(List<SelectItem> selectItems) {
	    Collections.sort(selectItems, new SelectItemComparator());
	}

    /**
     * Perform a post-redirect-get if the requests is not invoked via AJAX to the current view id with the specified request string appended.
     *
     * It will try to preserve FacesMessages using the bug-riddled Flash scope.
     */
    protected void nonAjaxPostRedirectGet(final String requestString) {
        final FacesContext facesContext = FacesContext.getCurrentInstance();
        final PartialViewContext partialViewContext = facesContext.getPartialViewContext();
        if (!partialViewContext.isAjaxRequest()) {
            final String viewUrl = facesContext.getApplication().getViewHandler().getActionURL(facesContext, facesContext.getViewRoot().getViewId());
            final Flash flash = facesContext.getExternalContext().getFlash();
            flash.setKeepMessages(true);
            final String url = viewUrl + (requestString==null ? "" : requestString);
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
}
