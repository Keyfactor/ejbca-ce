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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;


/**
 * JSF backing bean for CA info popup view.
 * View scoped
 * 
 * @version $Id$
 */
@ViewScoped
@ManagedBean(name="viewCAInfoMBean")
public class ViewCAInfoMBean extends BaseManagedBean implements Serializable {
		 
	private static final long serialVersionUID = 109073226626366410L;

    public static final String CA_PARAMETER = "caid";
    
    private CAInterfaceBean caBean;
    private int caId = 0;
	private CAInfoView caInfo = null;
    

    /**
     * Method that initializes the bean.
     *
     * @throws Exception 
     */
    public void initialize() throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            
            try {
                final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
                
                RequestHelper.setDefaultCharacterEncoding(request);
                
                getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);
                
                initCaBean(request);
                
                final String caIdParameter = request.getParameter(CA_PARAMETER);
                if (caIdParameter != null) {
                    try {
                        caId = Integer.parseInt(caIdParameter);
                    } catch (final NumberFormatException e) {
                        addErrorMessage("YOUMUSTSPECIFYCAID");
                    }
                    
                    caInfo = caBean.getCAInfo(caId);
                    if (caInfo == null) {
                        addErrorMessage("CADOESNTEXIST");  
                    }
                }
            } catch (final AuthorizationDeniedException e) {
                addErrorMessage("NOTAUTHORIZEDTOVIEWCA");
            }
        }
    }

    private void initCaBean(final HttpServletRequest request) throws Exception {
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if ( caBean == null ) {
            try {
                caBean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (final ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (final Exception exc) {
                throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        try{
            caBean.initialize(getEjbcaWebBean());
        } catch(final Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
    }

    public CAInfoView getCaInfo() {
        return caInfo;
    }
}
