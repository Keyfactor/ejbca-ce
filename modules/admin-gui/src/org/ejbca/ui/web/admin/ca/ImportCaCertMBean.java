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

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the import ca cert page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class ImportCaCertMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ImportCaCertMBean.class);

    @EJB
    private CAAdminSessionLocal caAdminSession;

    private String importCaCertName;
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
        EditCaUtil.navigateToManageCaPageIfNotPostBack();
    }
    
    public String getImportCaCertName() {
        return importCaCertName;
    }

    public void setImportCaCertName(final String importCaCertName) {
        this.importCaCertName = importCaCertName;
    }
    
    public UploadedFile getUploadedFile() {
        return uploadedFile;
    }

    public void setUploadedFile(final UploadedFile uploadedFile) {
        this.uploadedFile = uploadedFile;
    }    
    
    public String importCaCertificate() {
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(uploadedFile);
        try {
            Collection<Certificate> certs = null;
            try {
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(fileBuffer), Certificate.class);
            } catch (CertificateException e) {
                log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
                // See if it is a single binary certificate
                Certificate cert = CertTools.getCertfromByteArray(fileBuffer, Certificate.class);
                certs = new ArrayList<>();
                certs.add(cert);
            }
            caAdminSession.importCACertificate(getAdmin(), importCaCertName, EJBTools.wrapCertCollection(certs));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e.getMessage());
            log.error("Error happened while importing ca cert!", e);
            return "";
        }
    }
}
