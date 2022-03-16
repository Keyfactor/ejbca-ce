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

import org.apache.commons.lang.StringUtils;
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
    
    public ImportCaCertMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
    }
    
    @PostConstruct
    public void init() {
        EditCaUtil.navigateToManageCaPageIfNotPostBack();
    }
    
    public String getImportCaCertName() {
        return importCaCertName;
    }

    public void setImportCaCertName(final String importCaCertName) {
        this.importCaCertName = StringUtils.trim(importCaCertName);
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
            if(uploadedFile.getName().endsWith(".oer")) {
                caAdminSession.importItsCACertificate(getAdmin(), importCaCertName, fileBuffer);
                return EditCaUtil.MANAGE_CA_NAV;
            }
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
            addNonTranslatedErrorMessage(e);
            log.info("Error happened while importing ca cert!", e);
            return "";
        }
    }
}
