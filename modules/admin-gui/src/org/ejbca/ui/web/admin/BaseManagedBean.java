/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Base EJBCA JSF Managed Bean, all managed beans of EJBCA should inherit this class
 * 
 * @author Philip Vendil
 * @version $Id: BaseManagedBean.java 6244 2008-09-03 08:56:16Z jeklund $
 */
public abstract class BaseManagedBean implements Serializable{

	private static final Map publicConstantCache = new ConcurrentHashMap();

	protected EjbcaWebBean getEjbcaWebBean(){
		return EjbcaJSFHelper.getBean().getEjbcaWebBean();
	}

	protected void isAuthorizedNoLog(String resource) throws AuthorizationDeniedException{
		getEjbcaWebBean().isAuthorizedNoLog(resource);
	}

	protected void addErrorMessage(String messageResource){
		FacesContext ctx = FacesContext.getCurrentInstance();
		ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,getEjbcaWebBean().getText(messageResource, true),getEjbcaWebBean().getText(messageResource, true)));
	}

	protected void addNonTranslatedErrorMessage(String messageResource){
		FacesContext ctx = FacesContext.getCurrentInstance();
		ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,messageResource,messageResource));
	}

	protected Admin getAdmin(){
		return EjbcaJSFHelper.getBean().getAdmin();
	}

	/**
	 * Return the public constants of classObject as a Map, so they can be referenced from the JSF page.
	 * (The implemetation caches the Map for subsequent calls.)
	 */
	protected Map getPublicConstantsAsMap(Class classObject) {
		Map result = (Map) publicConstantCache.get(classObject.getName());
		if (result != null) {
			return result;
		}
		result = new HashMap();
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
}
