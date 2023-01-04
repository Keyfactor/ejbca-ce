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

import java.io.Serializable;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.SESSION;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the ca cert sign page.
 *
 */
@Named
@ViewScoped
public class CertSignRequestMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private CAInterfaceBean caBean;
    private String selectedCaName;
    private int selectedCaId;
    private UploadedFile uploadedFile;
    
    public CertSignRequestMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
    }
    
    @PostConstruct
    public void init() {
        EditCaUtil.navigateToManageCaPageIfNotPostBack();
        
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }
        
        final Map<String, Object> requestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
        selectedCaName = (String) requestMap.get("selectedCaName");
        selectedCaId = (Integer) requestMap.get("selectedCaId");

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
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(uploadedFile);
        try {
            if (caBean.createAuthCertSignRequest(selectedCaId, fileBuffer)) {
                final Map<String, Object> facesContextRequestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
                facesContextRequestMap.put("filemode", EditCaUtil.CERTREQGENMODE);
                facesContextRequestMap.put(SESSION.CA_INTERFACE_BEAN, caBean);
                facesContextRequestMap.put("caname", selectedCaName);
                return EditCaUtil.DISPLAY_RESULT_NAV;
            }
            return "";
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

}
