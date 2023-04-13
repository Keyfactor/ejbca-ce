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

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;
import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;

@Named
@SessionScoped
public class InitExistingPkiMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(InitExistingPkiMBean.class);
    
    private Part uploadFile;
    private String importedCaName;
    private boolean caImported = false;

    @EJB
    private CAAdminSessionLocal caAdminSession;
    
    public InitExistingPkiMBean() {
        super(StandardRules.ROLE_ROOT.resource());
    }
    
    public void actionImportCa() {
        if (StringUtils.isEmpty(importedCaName)) {
            addErrorMessage("CA_NAME_EMPTY");
            return;
        }
        if (uploadFile == null) {
            addErrorMessage("YOUMUSTSELECT");
            return;
        }
        try {
            final byte[] fileBytes = IOUtils.toByteArray(getUploadFile().getInputStream(), uploadFile.getSize());
            Collection<Certificate> certs = null;
            try {
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(fileBytes), Certificate.class);
            } catch (CertificateException e) {
                log.debug("Input stream is not PEM certificate(s): " + e.getMessage());
                // See if it is a single binary certificate
                Certificate cert = CertTools.getCertfromByteArray(fileBytes, Certificate.class);
                certs = new ArrayList<>();
                certs.add(cert);
            }
            caAdminSession.importCACertificate(getAdmin(), importedCaName, EJBTools.wrapCertCollection(certs));
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e);
            log.info("Error occurred while importing ca cert!", e);
            return;
        }
        caImported = true;
        addInfoMessage("IMPORTCA_SUCCESSFUL", importedCaName);
    }
    
    
    public boolean isCaImported() {
        return caImported;
    }

    public void setCaImported(boolean caImported) {
        this.caImported = caImported;
    }

    public String getImportedCaName() {
        return importedCaName;
    }

    public void setImportedCaName(String importedCaName) {
        this.importedCaName = importedCaName.trim();
    }

    public void setUploadFile(final Part uploadFile) {
        this.uploadFile = uploadFile;
    }

    public Part getUploadFile() {
        return uploadFile;
    }
    
    public String getRoleHelpText() {
        return getEjbcaWebBean().getText("IMPORTCA_ROLE_HELP", false, getAdmin());
    }
    
    public String actionNext() {
        return "next";
    }
    
    public String actionBack() {
        return "back";
    }
    
}
