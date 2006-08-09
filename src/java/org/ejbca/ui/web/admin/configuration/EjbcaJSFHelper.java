package org.ejbca.ui.web.admin.configuration;

import java.security.cert.X509Certificate;
import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.Approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.ra.Approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.RequestHelper;




/**
 * Class used to intergrate the old jsp framework with the new JSF one.
 * Contains methods for such things as language, themes ext
 * 
 * @author Philip Vendil
 * $Id: EjbcaJSFHelper.java,v 1.1 2006-08-09 07:29:47 herrvendil Exp $
 */

public class EjbcaJSFHelper  {
	private static final Logger log = Logger.getLogger(EjbcaJSFHelper.class);
		
	private EjbcaJSFLanguageResource text = null;
	private EjbcaJSFImageResource image = null;
	private EjbcaWebBean ejbcawebbean;
	

	private IRaAdminSessionLocal raadminsession;
	private ICAAdminSessionLocal caadminsession;
	private IApprovalSessionLocal approvalsession;

	
	private FacesContext ctx = FacesContext.getCurrentInstance();
	  
	private Admin admin = null;

	
	public EjbcaJSFHelper(){}
	
    public void setEjbcaWebBean(EjbcaWebBean ejbcawebbean){
       this.ejbcawebbean = ejbcawebbean;
       text = new EjbcaJSFLanguageResource(ejbcawebbean);
       image = new EjbcaJSFImageResource(ejbcawebbean);
       admin = getAdmin();
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
    	return "text/html; charset=" + RequestHelper.getDefaultContentEncoding();
    } 
    
   /**
    * Used for language resources.
    */
    public Map getText(){
    	return text;
    }
    
    /**
     * Used for image resources.
     */
     public Map getImage(){
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
 			approveendentity = getEjbcaWebBean().isAuthorizedNoLog(AvailableAccessRules.REGULAR_APPROVEENDENTITY);
 		}catch(AuthorizationDeniedException e){}
 		try{
 			approvecaaction = getEjbcaWebBean().isAuthorizedNoLog(AvailableAccessRules.REGULAR_APPROVECAACTION);
 		}catch(AuthorizationDeniedException e){}		
 		if(!approveendentity && !approvecaaction){
 			throw new AuthorizationDeniedException("Not authorized to view approval pages");
 		}
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
		  if(admin == null){
			  X509Certificate[] certificates = (X509Certificate[]) ((HttpServletRequest )ctx.getExternalContext().getRequest()).getAttribute( "javax.servlet.request.X509Certificate" );
		      admin = new Admin(certificates[0]);
		  }
		  return admin;
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
	
}
