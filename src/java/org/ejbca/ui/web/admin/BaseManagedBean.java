package org.ejbca.ui.web.admin;

import java.io.Serializable;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
/**
 * Base EJBCA JSF Managed Bean, all managed beans of EJBCA should inherit this class
 * 
 * @author Philip Vendil
 * $id$
 */
public abstract class BaseManagedBean implements Serializable{
   
  
  protected EjbcaWebBean getEjbcaWebBean(){
	  return EjbcaJSFHelper.getBean().getEjbcaWebBean();
  }
  
  protected void isAuthorizedNoLog(String resource) throws AuthorizationDeniedException{
	  getEjbcaWebBean().isAuthorizedNoLog(resource);
  }
  
  protected void addErrorMessage(String messageResource){
	  FacesContext ctx = FacesContext.getCurrentInstance();
	  ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,getEjbcaWebBean().getText(messageResource),getEjbcaWebBean().getText(messageResource)));
  }
  

  

	
}
