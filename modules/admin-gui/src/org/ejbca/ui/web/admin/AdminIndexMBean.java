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
package org.ejbca.ui.web.admin;

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.cainterface.EditPublisherJSPHelper;

/**
 *  * JSF Managed Bean or the index page in the Admin GUI.
 *
 * @version $Id: AdminIndexMBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@ManagedBean
@SessionScoped
public class AdminIndexMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AdminIndexMBean.class);

    private CAInterfaceBean caBean;
    private EditPublisherJSPHelper editPublisherJSPHelper;

    @PostConstruct
    private void postConstruct() throws Exception {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        caBean = (CAInterfaceBean) req.getSession().getAttribute("caBean");
        if ( caBean == null ){
            try {
                caBean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (Exception exc) {
                throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
            }
            req.getSession().setAttribute("cabean", caBean);
        }
        try{
            caBean.initialize(getEjbcaWebBean());
        } catch(Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
        editPublisherJSPHelper = (EditPublisherJSPHelper) req.getSession().getAttribute("editPublisherJSPHelper");
        if ( editPublisherJSPHelper == null ){
            try {
                editPublisherJSPHelper = (EditPublisherJSPHelper) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), EditPublisherJSPHelper.class.getName());
            } catch (ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (Exception exc) {
                throw new ServletException (" Cannot create bean of class "+EditPublisherJSPHelper.class.getName(), exc);
            }
            req.getSession().setAttribute("editPublisherJSPHelper", editPublisherJSPHelper);
        }
        try{
            editPublisherJSPHelper.initialize(req, getEjbcaWebBean(), caBean);
        } catch(Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
    }

    public CAInterfaceBean getCaBean(){
        return caBean;
    }

    public String getUsersCommonName() {
        return "Kotik";
    }
}
