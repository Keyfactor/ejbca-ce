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
package org.ejbca.ui.web.admin.ca;

import java.beans.Beans;
import java.io.IOException;
import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the ca cert sign page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CertSignRequestMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CertSignRequestMBean.class);

    
    private CAInterfaceBean caBean;
    private String selectedCaName;
    private int selectedCaId;
    private UploadedFile uploadedFile;
    
    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        }
    }
    
    @PostConstruct
    public void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if (caBean == null) {
            try {
                caBean = (CAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException | IOException e) {
                log.error("Error while instantiating the ca bean!", e);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        caBean.initialize(getEjbcaWebBean());
        
        selectedCaName = (String) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("selectedCaName");
        selectedCaId = (Integer) FacesContext.getCurrentInstance().getExternalContext().getRequestMap().get("selectedCaId");

    }
    
    public String getSelectedCaNameSignCertRequest() {
        return getEjbcaWebBean().getText("CANAME") + " : " + selectedCaName;
    }

    public UploadedFile getUploadedFile() {
        return uploadedFile;
    }

    public void setUploadedFile(final UploadedFile uploadedFile) {
        this.uploadedFile = uploadedFile;
    }
    
    public String signRequest() {
        byte[] fileBuffer = null;
        try {
            fileBuffer = uploadedFile.getBytes();
        } catch (IOException e) {
            log.error("Error happened while uploading file!", e);
        }
        try {
            if (caBean.createAuthCertSignRequest(selectedCaId, fileBuffer)) {
                return EditCaUtil.MANAGE_CA_NAV;
            }
        } catch (Exception e) {
            addErrorMessage(e.getMessage());
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

}
