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

import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.bean.SessionBeans;

/**
 * JSF backing bean for CA info popup view.
 * View scoped
 * 
 */
@ViewScoped
@Named("viewCAInfoMBean")
public class ViewCAInfoMBean extends BaseManagedBean implements Serializable {
		 
	private static final long serialVersionUID = 109073226626366410L;

    private static final String CA_PARAMETER = "caid";

    private int caId = 0;
	private CAInfoView caInfo = null;
    
	public ViewCAInfoMBean() throws Exception {
	    super(AccessRulesConstants.ROLE_ADMINISTRATOR);
        try {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);
            final CAInterfaceBean caBean = SessionBeans.getCaBean(request);
            RequestHelper.setDefaultCharacterEncoding(request);


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

    public CAInfoView getCaInfo() {
        return caInfo;
    }
}
