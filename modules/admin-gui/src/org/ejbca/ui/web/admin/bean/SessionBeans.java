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
package org.ejbca.ui.web.admin.bean;

import java.beans.Beans;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

import static org.ejbca.ui.web.admin.attribute.AttributeMapping.SESSION;

/**
 * Session utility class responsible for a Bean creation, initialization and its persistence within session.
 *
 * @version $Id$
 */
public class SessionBeans {

    /**
     * Returns the EjbcaWebBean object from the request's session, or creates an uninitialized one otherwise.
     *
     * @param httpServletRequest HttpServletRequest
     * @return an instance of EjbcaWebBean
     * @throws ServletException in case of creation/initialization failures.
     */
    public static EjbcaWebBean getEjbcaWebBean(final HttpServletRequest httpServletRequest) throws ServletException {
        return getEjbcaWebBean(httpServletRequest.getSession(true));
    }

    public static EjbcaWebBean getEjbcaWebBean(final HttpSession httpSession) throws ServletException {
        synchronized (httpSession) {
            EjbcaWebBean ejbcaWebBean = (EjbcaWebBean) httpSession.getAttribute(SESSION.EJBCA_WEB_BEAN);
            if (ejbcaWebBean == null) {
                ejbcaWebBean = getBeanInstance(EjbcaWebBeanImpl.class);
                httpSession.setAttribute(SESSION.EJBCA_WEB_BEAN, ejbcaWebBean);
            }
            return ejbcaWebBean;
        }
    }

    /**
     * Returns the CAInterfaceBean object from the request's session, or creates and initializes a new one otherwise.
     *
     * @param httpServletRequest HttpServletRequest
     * @return an instance of CAInterfaceBean
     * @throws ServletException in case of creation/initialization failures.
     */
    public static CAInterfaceBean getCaBean(final HttpServletRequest httpServletRequest) throws ServletException {
        final HttpSession httpSession = httpServletRequest.getSession(true);
        synchronized (httpSession) {
            CAInterfaceBean caBean = (CAInterfaceBean) httpSession.getAttribute(SESSION.CA_INTERFACE_BEAN);
                caBean = getBeanInstance(CAInterfaceBean.class);
                try {
                    caBean.initialize(getEjbcaWebBean(httpServletRequest));
                } catch (Exception e) {
                    throw new ServletException("Error initializing CACertReqServlet");
                }
                httpSession.setAttribute(SESSION.CA_INTERFACE_BEAN, caBean);
            return caBean;
        }
    }

    /**
     * Returns the RAInterfaceBean object from the request's session, or creates and initializes a new one otherwise.
     *
     * @param httpServletRequest HttpServletRequest
     * @return an instance of RAInterfaceBean
     * @throws ServletException in case of creation/initialization failures.
     */
    public static RAInterfaceBean getRaBean(final HttpServletRequest httpServletRequest) throws ServletException {
        final HttpSession httpSession = httpServletRequest.getSession(true);
        synchronized (httpSession) {
            RAInterfaceBean raBean = (RAInterfaceBean) httpSession.getAttribute(SESSION.RA_INTERFACE_BEAN);
            if (raBean == null) {
                raBean = getBeanInstance(RAInterfaceBean.class);
                try {
                    raBean.initialize(getEjbcaWebBean(httpServletRequest));
                } catch (Exception e) {
                    throw new ServletException("Cannot initialize RAInterfaceBean", e);
                }
                httpSession.setAttribute(SESSION.RA_INTERFACE_BEAN, raBean);
            }
            return raBean;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T getBeanInstance(Class<T> beanClass) throws ServletException {
        try {
            return (T) Beans.instantiate(
                    Thread.currentThread().getContextClassLoader(),
                    beanClass.getName()
            );
        } catch (ClassNotFoundException e) {
            throw new ServletException(e);
        } catch (Exception e) {
            throw new ServletException("Unable to instantiate " + beanClass.getName(), e);
        }
    }
}
