package org.ejbca.ui.web.admin.configuration;

import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocalHome;
import org.ejbca.core.ejb.services.IServiceSessionLocal;
import org.ejbca.core.ejb.services.IServiceSessionLocalHome;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;




/**
 * Class used to integrate the old jsp framework with the new JSF one.
 * Contains methods for such things as language, themes ext
 * 
 * @author Philip Vendil
 * $Id$
 */

public class EjbcaJSFHelper  {
	private static final Logger log = Logger.getLogger(EjbcaJSFHelper.class);
		
	private EjbcaJSFLanguageResource text = null;
	private EjbcaJSFImageResource image = null;
	private EjbcaWebBean ejbcawebbean;
	
	private boolean initialized = false;
	

	private IRaAdminSessionLocal raadminsession;
	private ICAAdminSessionLocal caadminsession;
	private IApprovalSessionLocal approvalsession;
	private IServiceSessionLocal servicesession;
	private IUserDataSourceSessionLocal userdatasourcesession;
	private IPublisherSessionLocal publishersession;
	private IAuthorizationSessionLocal authorizationsession;
	
	private FacesContext ctx = FacesContext.getCurrentInstance();
	  
	public EjbcaJSFHelper(){}
	
    public void setEjbcaWebBean(EjbcaWebBean ejbcawebbean){
    	if(!initialized){
    		this.ejbcawebbean = ejbcawebbean;
    		text = new EjbcaJSFLanguageResource(ejbcawebbean);
    		image = new EjbcaJSFImageResource(ejbcawebbean);
    		initialized = true;
    	}
    }
    
    /**
     * Returns the EJBCA title
     */
    public String getEjbcaTitle(){
    	return getEjbcaWebBean().getGlobalConfiguration().getEjbcaTitle();
    }
    
    /**
     * Returns the EJBCA theme
     */
    public String getTheme(){
    	return getEjbcaWebBean().getCssFile();
    }
    
    /**
     * Returns the EJBCA base url
     */
    public String getEjbcaBaseURL(){
    	return getEjbcaWebBean().getBaseUrl();
    }   
    
    /**
     * Returns the EJBCA content string
     */
    public String getContent(){
    	return "text/html; charset=" + WebConfiguration.getWebContentEncoding();
    } 
    
   /**
    * Used for language resources.
    */
    public Map getText(){
    	setEjbcaWebBean(getEjbcaWebBean());
    	return text;
    }
    
    /**
     * Used for image resources.
     */
     public Map getImage(){
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
 		boolean approveendentity = false;
 		boolean approvecaaction = false;
 		try{
 			approveendentity = getEjbcaWebBean().isAuthorizedNoLog(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
 		}catch(AuthorizationDeniedException e){}
 		try{
 			approvecaaction = getEjbcaWebBean().isAuthorizedNoLog(AccessRulesConstants.REGULAR_APPROVECAACTION);
 		}catch(AuthorizationDeniedException e){}		
 		if(!approveendentity && !approvecaaction){
 			throw new AuthorizationDeniedException("Not authorized to view approval pages");
 		}
     }
     
     /**
      * Only superadmins are authorized to services pages
     * @throws AuthorizationDeniedException 
      *
      */
     public void authorizedToServicesPages() throws AuthorizationDeniedException{
		getEjbcaWebBean().isAuthorizedNoLog(AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
     }
     public void authorizedToReportPages() throws AuthorizationDeniedException{
 		getEjbcaWebBean().isAuthorizedNoLog(AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
      }
     
    public int getEntriesPerPage(){
        return getEjbcaWebBean().getEntriesPerPage();
    }
    
    public EjbcaWebBean getEjbcaWebBean(){
    	
    	if(ejbcawebbean == null){
    		FacesContext ctx = FacesContext.getCurrentInstance();    		    	

    		HttpSession session = (HttpSession) ctx.getExternalContext().getSession(true);
 
    		    		
    		synchronized (session) {
    			ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) session.getAttribute("ejbcawebbean");
    			if (ejbcawebbean == null){
    				ejbcawebbean = new org.ejbca.ui.web.admin.configuration.EjbcaWebBean();
    				session.setAttribute("ejbcawebbean", ejbcawebbean);
    			}
    		}
    		
    		try {
				ejbcawebbean.initialize((HttpServletRequest) ctx.getExternalContext().getRequest(), "/administrator");
			} catch (Exception e) {
				log.error(e);
			}
    	}
    	
    	return ejbcawebbean;
    }
 
	public Admin getAdmin() {
		return getEjbcaWebBean().getAdminObject();
	  }
    
    public static EjbcaJSFHelper getBean(){    
    	FacesContext context = FacesContext.getCurrentInstance();    
    	Application app = context.getApplication();    
    	ValueBinding binding = app.createValueBinding("#{web}");    
    	Object value = binding.getValue(context);    
    	return (EjbcaJSFHelper) value;
    }
    
    public IRaAdminSessionLocal getRaAdminSession(){
    	if(raadminsession == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
    		try {
    			raadminsession = raadminsessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}

    	return raadminsession;
    }

    public ICAAdminSessionLocal getCAAdminSession(){
    	if(caadminsession == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) locator.getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
    		try {
    			caadminsession = caadminsessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return caadminsession;
    }
    
    public IApprovalSessionLocal getApprovalSession(){
    	if(approvalsession == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IApprovalSessionLocalHome approvalsessionhome = (IApprovalSessionLocalHome) locator.getLocalHome(IApprovalSessionLocalHome.COMP_NAME);
    		try {
    			approvalsession = approvalsessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return approvalsession;
    }    
	
    
    public IServiceSessionLocal getServiceSession(){
    	if(servicesession == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IServiceSessionLocalHome servicesessionhome = (IServiceSessionLocalHome) locator.getLocalHome(IServiceSessionLocalHome.COMP_NAME);
    		try {
    			servicesession = servicesessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return servicesession;
    }
    
    public IUserDataSourceSessionLocal getUserDataSourceSession(){
		if(userdatasourcesession  == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IUserDataSourceSessionLocalHome userdatasourcesessionhome = (IUserDataSourceSessionLocalHome) locator.getLocalHome(IUserDataSourceSessionLocalHome.COMP_NAME);
    		try {
    			userdatasourcesession = userdatasourcesessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return userdatasourcesession;
    }

    public IPublisherSessionLocal getPublisherSession(){
		if(publishersession  == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) locator.getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
    		try {
    			publishersession = publishersessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return publishersession;
    }

    public IAuthorizationSessionLocal getAuthorizationSession(){
		if(authorizationsession  == null){ 
    		ServiceLocator locator = ServiceLocator.getInstance();
    		IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
    		try {
    			authorizationsession = authorizationsessionhome.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}
    	}
    	return authorizationsession;
    }
}
