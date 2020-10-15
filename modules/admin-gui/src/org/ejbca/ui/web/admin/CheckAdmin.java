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
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import javax.ejb.EJB;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
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

    private static final Logger log = Logger.getLogger(CheckAdmin.class);
    
    private static final String INIT_PKI_PATH = "initpki.xhtml";
    
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
        Pattern pattern = Pattern.compile("(?=.initnewpki*)|(?=.initpki*)");
        return pattern.matcher(url).find();
    }

    private void shouldRedirectToInitPKI() throws Exception {
        final List<Integer> canames = caSession.getAllCaIds();
        
        if (canames.isEmpty()
                && getAdmin() instanceof OAuth2AuthenticationToken) {
            try {
                redirectToInitPkiPage();
            } catch (IOException e) {
                log.warn("Error while redirecting to init pki page.", e);
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
