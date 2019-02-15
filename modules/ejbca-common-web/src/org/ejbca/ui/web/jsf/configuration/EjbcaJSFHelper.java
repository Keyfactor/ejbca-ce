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
package org.ejbca.ui.web.jsf.configuration;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;

/**
 * Interface  used to integrate the old jsp framework with the new JSF one.
 *
 * Contains methods for such things as language, themes ext
 *
 * @version $Id$
 */
public interface EjbcaJSFHelper {

    void setEjbcaWebBean(EjbcaWebBean ejbcawebbean);

    /** Returns the EJBCA version */
    String getEjbcaVersion();

    /** Returns the EJBCA title */
    String getEjbcaTitle();

    /** Returns the EJBCA theme */
    String getTheme();

    /** Returns the EJBCA base url */
    String getEjbcaBaseURL();

    /** Returns the EJBCA content string */
    String getContent();

    /** Used for language resources. */
    EjbcaJSFLanguageResource getText();

    /** Used for image resources. */
    EjbcaJSFImageResource getImage();

    /**
     * Special function for approval pages since it has two different accessrules.
     *
     * @throws AuthorizationDeniedException authorization exception.
     */
    void authorizedToApprovalPages() throws AuthorizationDeniedException;

    int getEntriesPerPage();

    EjbcaWebBean getEjbcaWebBean();

    EjbcaWebBean getEjbcaErrorWebBean();

    AuthenticationToken getAdmin();

    static EjbcaJSFHelper getBean(){
        FacesContext context = FacesContext.getCurrentInstance();
        Application app = context.getApplication();
        EjbcaJSFHelper value = app.evaluateExpressionGet(context, "#{web}", EjbcaJSFHelper.class);
        return value;
    }

    /** @return true if the client browser has identified itself as a legacy Internet Explorer 10 (or earlier) */
    boolean isLegacyInternetExplorer();

}
