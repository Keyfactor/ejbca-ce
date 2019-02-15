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

/**
 * Class used to integrate the old jsp framework with the new JSF one.
 * Contains methods for such things as language, themes ext
 * 
 * $Id$
 */
public class EjbcaJSFHelper implements org.ejbca.ui.web.configuration.EjbcaJSFHelper {

	private static final Logger log = Logger.getLogger(EjbcaJSFHelper.class);
		
	private org.ejbca.ui.web.jsf.configuration.EjbcaJSFLanguageResource text = null;
	private org.ejbca.ui.web.jsf.configuration.EjbcaJSFImageResource image = null;
	private org.ejbca.ui.web.jsf.configuration.EjbcaWebBean ejbcawebbean;
    private Boolean legacyInternetExplorer = null;

	private boolean initialized = false;
	
	public EjbcaJSFHelper(){}
	
    public void setEjbcaWebBean(org.ejbca.ui.web.jsf.configuration.EjbcaWebBean ejbcawebbean){
    	if(!initialized){
    		this.ejbcawebbean = ejbcawebbean;
    		text = new EjbcaJSFLanguageResource(ejbcawebbean);
    		image = new EjbcaJSFImageResource(ejbcawebbean);
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
             ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) session.getAttribute("ejbcawebbean");
             if (ejbcawebbean == null){
                 ejbcawebbean = new org.ejbca.ui.web.admin.configuration.EjbcaWebBean();
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
             ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) session.getAttribute("ejbcawebbean");
             if (ejbcawebbean == null){
                 ejbcawebbean = new org.ejbca.ui.web.admin.configuration.EjbcaWebBean();
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
    	 EjbcaJSFHelper value = (EjbcaJSFHelper) app.evaluateExpressionGet(context, "#{web}", EjbcaJSFHelper.class);
    	 return value;
     }

     /** @return true if the client browser has identified itself as a legacy Internet Explorer 10 (or earlier) */
     public boolean isLegacyInternetExplorer() {
         if (legacyInternetExplorer==null) {
             final HttpServletRequest httpServletRequest = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
             final String userAgent = httpServletRequest.getHeader("User-Agent");
             if (log.isDebugEnabled()) {
                 log.debug("User-Agent: " + userAgent);
             }
             // Check stolen from org.ejbca.ui.web.pub.ApplyBean.detectBrowser(HttpServletRequest)
             // "Gecko"==Firefox, "MSIE"==Internet Exploder 10-, "Trident"==IE11
             legacyInternetExplorer = Boolean.valueOf(userAgent != null && userAgent.contains("MSIE") && !userAgent.contains("Gecko"));
         }
         return legacyInternetExplorer.booleanValue();
     }
}
