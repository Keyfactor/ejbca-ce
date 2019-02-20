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
	
	public EjbcaJSFHelperImpl(){}
	
    public void setEjbcaWebBean(EjbcaWebBean ejbcawebbean){
    	if(!initialized){
    		this.ejbcawebbean = ejbcawebbean;
    		text = new EjbcaJSFLanguageResourceImpl(ejbcawebbean);
    		image = new EjbcaJSFImageResourceImpl(ejbcawebbean);
    		initialized = true;
    	}
    }
    
    /** Returns the EJBCA version */
    public String getEjbcaVersion(){
    	return GlobalConfiguration.EJBCA_VERSION;
    }

    /** Returns the EJBCA title */
    public String getEjbcaTitle(){
        GlobalConfiguration gc = getEjbcaWebBean().getGlobalConfiguration();
        if (gc == null) {
            log.warn("GlobalConfiguration is null trying to get from EjbcaWebBean, returning default Title.");
            return  GlobalConfiguration.getEjbcaDefaultTitle();
        }
        return gc.getEjbcaTitle();
    }
    
    /** Returns the EJBCA theme */
    public String getTheme(){
    	return getEjbcaWebBean().getCssFile();
    }
    
    /** Returns the EJBCA base url */
    public String getEjbcaBaseURL(){
    	return getEjbcaWebBean().getBaseUrl();
    }   
    
    /** Returns the EJBCA content string */
    public String getContent(){
    	return "text/html; charset=" + WebConfiguration.getWebContentEncoding();
    } 
    
   /** Used for language resources. */
    public org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource getText(){
    	setEjbcaWebBean(getEjbcaWebBean());
    	return text;
    }
    
    /** Used for image resources. */
     public org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource getImage(){
        setEjbcaWebBean(getEjbcaWebBean());
     	return image;
     }
    
     /**
      * Special function for approval pages since it has two different accessrules
     * @throws AuthorizationDeniedException 
      *
      */
     public void authorizedToApprovalPages() throws AuthorizationDeniedException{
		  // Check Authorization
        boolean approveendentity = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        boolean approvecaaction = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVECAACTION);
 		if (!approveendentity && !approvecaaction) {
 			throw new AuthorizationDeniedException("Not authorized to view approval pages");
 		}
     }
     
     public int getEntriesPerPage(){
    	 return getEjbcaWebBean().getEntriesPerPage();
     }
    
     public org.ejbca.ui.web.jsf.configuration.EjbcaWebBean getEjbcaWebBean(){
         FacesContext ctx = FacesContext.getCurrentInstance();    		    	
         HttpSession session = (HttpSession) ctx.getExternalContext().getSession(true);
         synchronized (session) {
             ejbcawebbean = (EjbcaWebBean) session.getAttribute("ejbcawebbean");
             if (ejbcawebbean == null){
                 ejbcawebbean = new EjbcaWebBeanImpl();
                 try {
                     ejbcawebbean.initialize((HttpServletRequest) ctx.getExternalContext().getRequest(), AccessRulesConstants.ROLE_ADMINISTRATOR);
                     session.setAttribute("ejbcawebbean", ejbcawebbean);
                 } catch (Exception e) {
                     log.error(e);
                 }
             }
         }
         return ejbcawebbean;
     }

     public org.ejbca.ui.web.jsf.configuration.EjbcaWebBean getEjbcaErrorWebBean(){
         FacesContext ctx = FacesContext.getCurrentInstance();
         HttpSession session = (HttpSession) ctx.getExternalContext().getSession(true);
         synchronized (session) {
             ejbcawebbean = (EjbcaWebBean) session.getAttribute("ejbcawebbean");
             if (ejbcawebbean == null){
                 ejbcawebbean = new EjbcaWebBeanImpl();
                 try {
                     ejbcawebbean.initialize_errorpage((HttpServletRequest) ctx.getExternalContext().getRequest());
                     session.setAttribute("ejbcawebbean", ejbcawebbean);
                 } catch (Exception e) {
                     log.error(e);
                 }
             }
         }
         return ejbcawebbean;
     }
     
     public AuthenticationToken getAdmin() {
    	 return getEjbcaWebBean().getAdminObject();
     }

     public static EjbcaJSFHelper getBean(){
    	 FacesContext context = FacesContext.getCurrentInstance();    
    	 Application app = context.getApplication();   
    	 return (EjbcaJSFHelper) app.evaluateExpressionGet(context, "#{web}", EjbcaJSFHelper.class);
     }

     /** @return true if the client browser has identified itself as a legacy Internet Explorer 10 (or earlier) */
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
