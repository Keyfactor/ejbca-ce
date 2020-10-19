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

import java.io.IOException;

import javax.ejb.EJB;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.resource.spi.IllegalStateException;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;

/**
 * Class used for checking if we are accessing the EJBCA GUI with normal admin or a
 * OAuth pki initialization.
 *
 */
public class CheckAdmin extends BaseManagedBean {

    private static final long serialVersionUID = 1L;
    
    private static final String INIT_PKI_PATH = "initpki.xhtml";
    private static final String INIT_NEW_PKI_PATH = "initnewpki.xhtml";
    private static final String INIT_PKI_ADMIN_PATH = "initpkiadmin.xhtml";
    private static final String INIT_PKI_SUMMARY_PATH = "initpkisummary.xhtml";
    private static final String INIT_EXISTING_PKI_PATH = "initexistingpki.xhtml";
    private static final String INIT_EXISTING_PKI_ROLE_PATH = "initexistingpkirole.xhtml";
    
    @EJB
    public CaSessionLocal caSession;
    
    public CheckAdmin(final String... resources) {
        super(resources);
    }
    
    /**
     * Invoked on preRenderView
     * @throws Exception 
     */
    public void authorizedResources() throws Exception {
        HttpServletRequest origRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        if (isInitPkiPage(origRequest.getRequestURL().toString())) {
            checkAccess();
        } else {
            shouldRedirectToInitPKI();
        }
    }
    
    private void checkAccess() throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, accessRulesConstantString);
        } else if (!getEjbcaWebBean().isAuthorizedNoLogSilent(accessRulesConstantString)) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
    }
    
    private boolean isInitPkiPage(final String url) {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        final String requestContextPath = ec.getRequestContextPath();
        
        return url.endsWith(requestContextPath + "/" + INIT_PKI_PATH) 
                || url.endsWith(requestContextPath + "/" + INIT_NEW_PKI_PATH)
                || url.endsWith(requestContextPath + "/" + INIT_PKI_ADMIN_PATH)
                || url.endsWith(requestContextPath + "/" + INIT_PKI_SUMMARY_PATH)
                || url.endsWith(requestContextPath + "/" + INIT_EXISTING_PKI_PATH)
                || url.endsWith(requestContextPath + "/" + INIT_EXISTING_PKI_ROLE_PATH);
    }

    private void shouldRedirectToInitPKI() throws Exception {
        if (caSession.getAllCaIds().isEmpty()
                && getAdmin() instanceof OAuth2AuthenticationToken) {
            try {
                redirectToInitPkiPage();
            } catch (IOException e) {
                throw new IllegalStateException("Error while redirecting to init pki page.");
            }
        } else {
            checkAccess();
        }
    }
    
    private void redirectToInitPkiPage() throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(ec.getRequestContextPath() + "/" + INIT_PKI_PATH);
    }
    
}
