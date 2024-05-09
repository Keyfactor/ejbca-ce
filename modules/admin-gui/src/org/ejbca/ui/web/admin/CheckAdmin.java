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

import jakarta.ejb.EJB;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.resource.spi.IllegalStateException;

import org.cesecore.certificates.ca.CaSessionLocal;

/**
 * Class used for checking if we are accessing the EJBCA GUI with normal admin or a
 * OAuth pki initialization etc.
 *
 */
public class CheckAdmin extends BaseManagedBean {

    private static final long serialVersionUID = 1L;

    private static final String INIT_PKI_PATH = "initpki.xhtml";

    @EJB
    private CaSessionLocal caSession;

    public CheckAdmin(final String... resources) {
        super(resources);
    }

    /**
     * Invoked on preRenderView
     * @throws Exception 
     */
    @Override
    public void authorizedResources() throws Exception {
        super.authorizedResources();
        shouldRedirectToInitPKI();
    }

    private void shouldRedirectToInitPKI() throws IllegalStateException {
        if (caSession.getAllCaIds().isEmpty()) {
            try {
                redirectToInitPkiPage();
            } catch (IOException e) {
                throw new IllegalStateException("Error while redirecting to init pki page.");
            }
        }
    }

    private void redirectToInitPkiPage() throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(ec.getRequestContextPath() + "/" + INIT_PKI_PATH);
    }

}
