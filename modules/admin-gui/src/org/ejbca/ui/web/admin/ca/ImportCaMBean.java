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
import java.io.IOException;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authorization.control.StandardRules;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.admin.BaseManagedBean;

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

    @EJB
    private CAAdminSessionLocal caAdminSession;

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
        EditCaUtil.navigateToManageCaPageIfNotPostBack();
        // Set the defaults
        importSigAlias = "SignatureKeyAlias";
        importEncAlias = "EncryptionKeyAlias";
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
        final byte[] fileBuffer = EditCaUtil.getUploadedFileBuffer(uploadedFile);
        try {
            detectAliases(fileBuffer);
            caAdminSession.importCAFromKeyStore(getAdmin(), importCaName, fileBuffer, importPassword, importPassword, importSigAlias, importEncAlias);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (ParameterException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            log.info("Could not determine key alias in uploaded file. " + e.getMessage());
        } catch (KeyStoreException | NoSuchProviderException e) {
            addNonTranslatedErrorMessage("Internal error. " + e.getMessage());
            log.error("Internal error while importing CA.", e);
        } catch (NoSuchAlgorithmException e) {
            addNonTranslatedErrorMessage("Unsupported algorithm. " + e.getMessage());
            log.info(e.getMessage(), e);
        } catch (IOException | CertificateException e) {
            // These errors tend to have a human readable text, so they are shown as is.
            // For example: "PKCS12 key store mac invalid - wrong password or corrupted file."
            addNonTranslatedErrorMessage(e);
            log.info(e.getMessage(), e);
        }
        return "";
    }

    /**
     * Auto-detects importSigAlias and importEncAlias if blank.
     * @param p12file PKCS#12 file contents
     */
    private void detectAliases(final byte[] p12file)
            throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, ParameterException {
        final KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ks.load(new ByteArrayInputStream(p12file), importPassword.toCharArray());
        Enumeration<String> aliases = ks.aliases();
        if (aliases == null || !aliases.hasMoreElements()) {
            throw new ParameterException("This file does not contain any aliases.");
        }
        final String firstAlias = aliases.nextElement();
        boolean multipleAliases = false;
        final StringBuilder availableAliases = new StringBuilder();
        availableAliases.append("You have to specify any of the following aliases: ");
        availableAliases.append(firstAlias);
        while (aliases.hasMoreElements()) {
            availableAliases.append(' ');
            availableAliases.append(aliases.nextElement());
            multipleAliases = true;
        }
        if (StringUtils.isBlank(importSigAlias)) {
            if (multipleAliases) {
                throw new ParameterException(availableAliases.toString());
            }
            importSigAlias = firstAlias;
        } else if (!ks.isKeyEntry(importSigAlias)) {
            throw new ParameterException("Alias '" + importSigAlias + "' does not exist. " + availableAliases);
        }
        if (StringUtils.isBlank(importEncAlias)) {
            importEncAlias = null;
        } else if (!ks.isKeyEntry(importEncAlias)) {
            throw new ParameterException("Alias '" + importEncAlias + "' does not exist. " + availableAliases);
        }
    }
}
