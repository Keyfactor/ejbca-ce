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
import org.ejbca.ui.web.admin.cainterface.CADataHandler;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

/**
 * 
 * JSF MBean backing the import ca page.
 *
 * @version $Id$
 * 
 */
@ManagedBean
@ViewScoped
public class ImportCaMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ImportCaMBean.class);
    
    private CAInterfaceBean caBean;
    private CADataHandler cadatahandler;
    private String importCaName;
    private String importPassword;
    private String importSigAlias;
    private String importEncAlias;
    private UploadedFile uploadedFile;

    public void initAccess() throws Exception {
        // To check access 
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        }
    }
    
    @PostConstruct
    public void init() {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if (caBean == null) {
            try {
                caBean = (CAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException | IOException e) {
                log.error("Error while instantiating the ca bean!", e);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        caBean.initialize(getEjbcaWebBean());
        cadatahandler = caBean.getCADataHandler();
        
        // Set the defaults
        importSigAlias = "signKey";
        importEncAlias = "encryptKey";
    }

    public String getImportCaName() {
        return importCaName;
    }

    public void setImportCaName(final String importCaName) {
        this.importCaName = importCaName;
    }

    public UploadedFile getUploadedFile() {
        return uploadedFile;
    }

    public void setUploadedFile(final UploadedFile uploadedFile) {
        this.uploadedFile = uploadedFile;
    }
    
    public String getImportPassword() {
        return importPassword;
    }

    public void setImportPassword(String importPassword) {
        this.importPassword = importPassword;
    }

    public String getImportSigAlias() {
        return importSigAlias;
    }

    public void setImportSigAlias(String importSigAlias) {
        this.importSigAlias = importSigAlias;
    }

    public String getImportEncAlias() {
        return importEncAlias;
    }

    public void setImportEncAlias(String importEncAlias) {
        this.importEncAlias = importEncAlias;
    }    
    
    public String importCaCertificate() {
        byte[] fileBuffer = null;
        try {
            fileBuffer = uploadedFile.getBytes();
        } catch (IOException e) {
            log.error("Error happened while uploading file!", e);
        }
        try {
            cadatahandler.importCAFromKeyStore(importCaName, fileBuffer, importPassword, importSigAlias, importEncAlias);
        } catch (Exception e) {
            addErrorMessage(e.getMessage());
            log.error("Error happened while importing ca!", e);
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
}
