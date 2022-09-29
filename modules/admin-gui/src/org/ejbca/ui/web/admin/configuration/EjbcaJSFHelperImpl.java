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
package org.ejbca.ui.web.admin.configuration;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * Class used to integrate the old jsp framework with the new JSF one.
 * Contains methods for such things as language, themes ext
 * 
 * @version $Id$
 */
public class EjbcaJSFHelperImpl implements EjbcaJSFHelper {

	private static final Logger log = Logger.getLogger(EjbcaJSFHelperImpl.class);
		
	private org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource text = null;
	private EjbcaJSFImageResource image = null;
	private EjbcaWebBean ejbcawebbean;
    private Boolean legacyInternetExplorer = null;

	private boolean initialized = false;
	
	public EjbcaJSFHelperImpl() {}
	
    @Override
    public void setEjbcaWebBean(EjbcaWebBean ejbcawebbean) {
    	if(!initialized){
    		this.ejbcawebbean = ejbcawebbean;
    		text = new EjbcaJSFLanguageResourceImpl(ejbcawebbean);
    		image = new EjbcaJSFImageResourceImpl(ejbcawebbean);
    		initialized = true;
    	}
    }
    
    /** Returns the EJBCA version */
    @Override
    public String getEjbcaVersion() {
        if (getEjbcaWebBean().isRunningEnterprise()) {
            return GlobalConfiguration.EJBCA_VERSION;
        }
        return GlobalConfiguration.EJBCA_COMMUNITY_VERSION;
    }

    /** Returns the EJBCA title */
    @Override
    public String getEjbcaTitle() {
        GlobalConfiguration gc = getEjbcaWebBean().getGlobalConfiguration();
        if (gc == null) {
            log.warn("GlobalConfiguration is null trying to get from EjbcaWebBean, returning default Title.");
            return  GlobalConfiguration.getEjbcaDefaultTitle();
        }
        return gc.getEjbcaTitle();
    }
    
    /** Returns the EJBCA theme */
    @Override
    public String getTheme() {
    	return getEjbcaWebBean().getCssFile();
    }
    
    /** Returns the EJBCA base url */
    @Override
    public String getEjbcaBaseURL() {
    	return getEjbcaWebBean().getBaseUrl();
    }   
    
    /** Returns the EJBCA content string */
    @Override
    public String getContent() {
    	return "text/html; charset=" + WebConfiguration.getWebContentEncoding();
    } 
    
   /** Used for language resources. */
    @Override
    public org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource getText() {
    	setEjbcaWebBean(getEjbcaWebBean());
    	return text;
    }
    
    /** Used for image resources. */
    @Override
    public org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource getImage() {
        setEjbcaWebBean(getEjbcaWebBean());
     	return image;
     }
    
     /**
      * Special function for approval pages since it has two different accessrules
     * @throws AuthorizationDeniedException 
      *
      */
    @Override
    public void authorizedToApprovalPages() throws AuthorizationDeniedException {
		// Check Authorization
        boolean approveendentity = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        boolean approvecaaction = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVECAACTION);
 		if (!approveendentity && !approvecaaction) {
 			throw new AuthorizationDeniedException("Not authorized to view approval pages");
 		}
     }
     
    @Override
    public int getEntriesPerPage() {
    	 return getEjbcaWebBean().getEntriesPerPage();
     }
    
     @Override
    public org.ejbca.ui.web.jsf.configuration.EjbcaWebBean getEjbcaWebBean() {
         if(ejbcawebbean == null) {
             final FacesContext ctx = FacesContext.getCurrentInstance();
             final HttpSession session = (HttpSession) ctx.getExternalContext().getSession(true);
             try {
                 ejbcawebbean = SessionBeans.getEjbcaWebBean(session);
                 ejbcawebbean.initialize((HttpServletRequest) ctx.getExternalContext().getRequest(), AccessRulesConstants.ROLE_ADMINISTRATOR);
             } catch (Exception e) {
                 log.error("Failed to initialize EjbcaWebBean", e);
             }
         }
         return ejbcawebbean;
     }

     @Override
    public org.ejbca.ui.web.jsf.configuration.EjbcaWebBean getEjbcaErrorWebBean() {
         if(ejbcawebbean == null) {
             final FacesContext ctx = FacesContext.getCurrentInstance();
             final HttpSession session = (HttpSession) ctx.getExternalContext().getSession(true);
             try {
                 ejbcawebbean = SessionBeans.getEjbcaWebBean(session);
                 ejbcawebbean.initialize_errorpage((HttpServletRequest) ctx.getExternalContext().getRequest());
             } catch (Exception e) {
                 log.error("Failed to initialize EjbcaWebBean for error page", e);
             }
         }
         return ejbcawebbean;
     }
     
     @Override
    public AuthenticationToken getAdmin() {
    	 return getEjbcaWebBean().getAdminObject();
     }

     public static EjbcaJSFHelper getBean() {
    	 FacesContext context = FacesContext.getCurrentInstance();    
    	 Application app = context.getApplication();   
    	 return app.evaluateExpressionGet(context, "#{web}", EjbcaJSFHelper.class);
     }

     /** @return true if the client browser has identified itself as a legacy Internet Explorer 10 (or earlier) */
     @Override
    public boolean isLegacyInternetExplorer() {
         if (legacyInternetExplorer == null) {
             final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
             final String userAgent = httpServletRequest.getHeader("User-Agent");
             if (log.isDebugEnabled()) {
                 log.debug("User-Agent: " + userAgent);
             }
             // Check stolen from org.ejbca.ui.web.pub.ApplyBean.detectBrowser(HttpServletRequest)
             // "Gecko"==Firefox, "MSIE"==Internet Exploder 10-, "Trident"==IE11
             legacyInternetExplorer = userAgent != null && userAgent.contains("MSIE") && !userAgent.contains("Gecko");
         }
         return legacyInternetExplorer;
     }
}
