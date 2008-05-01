/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.Serializable;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Base EJBCA JSF Managed Bean, all managed beans of EJBCA should inherit this class
 * 
 * @author Philip Vendil
 * @version $Id$
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
	  ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,getEjbcaWebBean().getText(messageResource, true),getEjbcaWebBean().getText(messageResource, true)));
  }
  
  protected void addNonTranslatedErrorMessage(String messageResource){
	  FacesContext ctx = FacesContext.getCurrentInstance();
	  ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,messageResource,messageResource));
  }
  
  
  protected Admin getAdmin(){
	  return EjbcaJSFHelper.getBean().getAdmin();
  }
  

	
}
