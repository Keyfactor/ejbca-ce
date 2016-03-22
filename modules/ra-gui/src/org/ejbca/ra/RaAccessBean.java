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
package org.ejbca.ra;

import java.io.Serializable;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;

/**
 * Managed bean with isAuthorized method. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaAccessBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaAccessBean.class);
    
    @ManagedProperty(value="#{raMasterApiBean}")
    private RaMasterApiBean raMasterApiBean;
    public void setRaMasterApiBean(final RaMasterApiBean raMasterApiBean) { this.raMasterApiBean = raMasterApiBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }
    
    private AccessSet myAccess = null;
    
    //public boolean isAuthorized(String... resources) {
    public boolean isAuthorized(String resources) {
        if (myAccess == null) {
            final AuthenticationToken authenticationToken = raAuthenticationBean.getAuthenticationToken();
            try {
                myAccess = raMasterApiBean.getUserAccessSet(authenticationToken);
            } catch (AuthenticationFailedException e) {
                log.info("Failed to match authentication token '" + authenticationToken + "' to a role.");
                myAccess = new AccessSet(); // empty access set
            }
        }
        return myAccess.isAuthorized(resources);
    }
    
    @Deprecated
    public boolean isAuthorizedToRootTEST() {
        return isAuthorized("/");
    }
}
