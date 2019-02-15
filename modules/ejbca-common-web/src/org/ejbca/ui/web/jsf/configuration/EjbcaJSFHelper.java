package org.ejbca.ui.web.configuration;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;

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
