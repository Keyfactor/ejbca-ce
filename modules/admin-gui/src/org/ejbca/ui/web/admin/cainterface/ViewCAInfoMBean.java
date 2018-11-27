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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;


/**
 * JSF backing bean for CA info popup view.
 * 
 * @version $Id: ViewCAInfoMBean.java 30423 2018-11-07 09:11:23Z tarmo_r_helmes $
 */
@ViewScoped
@ManagedBean(name="viewCAInfoMBean")
public class ViewCAInfoMBean extends BaseManagedBean implements Serializable {
		 
	private static final long serialVersionUID = 109073226626366410L;

    public static final String CA_PARAMETER             = "caid";
/*
	public static final String CERTSERNO_PARAMETER      = "certsernoparameter"; 
	  
	public static final String PASSWORD_AUTHENTICATIONCODE  = "passwordactivationcode";
	
    public static final String CHECKBOX_VALUE                = BasePublisher.TRUE;
	  
	public static final String BUTTON_ACTIVATE          = "buttonactivate";
	public static final String BUTTON_MAKEOFFLINE       = "buttonmakeoffline";
	public static final String BUTTON_CLOSE             = "buttonclose"; 
	public static final String CHECKBOX_INCLUDEINHEALTHCHECK = "includeinhealthcheck";
	public static final String SUBMITHS					= "submiths";
*/
    
    //@ManagedProperty(value = "#{cAInterfaceBean}") //<- CAInterfaceBean doesn't seem to be managed
    private CAInterfaceBean caBean;
    
    int caId = 0;
	private CAInfoView caInfo = null;
    
    /** Creates new LogInterfaceBean */
    public ViewCAInfoMBean() {
        
    }

    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize() throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);
            
            initCaBean(request);
            
            final String caIdParameter = request.getParameter(CA_PARAMETER);
            if (caIdParameter != null) {
                caId = Integer.parseInt(caIdParameter);
                caInfo = caBean.getCAInfo(caId);
            }
        }
    }

    private void initCaBean(final HttpServletRequest request) throws Exception {
        caBean = (CAInterfaceBean) request.getSession().getAttribute("caBean");
        if ( caBean == null ) {
            try {
                caBean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (final ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (final Exception exc) {
                throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
            }
            request.getSession().setAttribute("cabean", caBean);
        }
        try{
            caBean.initialize(getEjbcaWebBean());
        } catch(final Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
    }

    public CAInfoView getCaInfo() {
        return caInfo;
    }

    
    /**
     * Method that parses the request and take appropriate actions.
     * @param request the http request
     * @throws Exception
     */
    /*
    public void parseRequest(final HttpServletRequest request) throws Exception {
        generalerrormessage = null;
        activationerrormessage = null;   
        activationmessage = null;
        RequestHelper.setDefaultCharacterEncoding(request);
        if (request.getParameter(CA_PARAMETER) != null){
            caid = Integer.parseInt(request.getParameter(CA_PARAMETER));
            // Get currentstate
            status = CAConstants.CA_OFFLINE;
            try {
                cainfo = cabean.getCAInfo(caid);
                if (cainfo==null) {
                    generalerrormessage = "CADOESNTEXIST";  
                } else {
                    status = cainfo.getCAInfo().getStatus();
                }
            } catch(final AuthorizationDeniedException e) {
                generalerrormessage = "NOTAUTHORIZEDTOVIEWCA";
                return;
            } 
        } else {
            generalerrormessage = "YOUMUSTSPECIFYCAID";
        }
    }
    */
}
