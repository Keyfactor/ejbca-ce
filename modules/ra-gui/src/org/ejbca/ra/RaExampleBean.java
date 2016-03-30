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
import java.util.Random;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;

/**
 * Example of JSF Managed Bean for backing a page. 
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaExampleBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaExampleBean.class);
    
    @ManagedProperty(value="#{raMasterApiBean}")
    private RaMasterApiBean raMasterApiBean;
    public void setRaMasterApiBean(final RaMasterApiBean raMasterApiBean) { this.raMasterApiBean = raMasterApiBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private String value = null;

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value.trim(); }

    @Deprecated
    public void throwException() throws Exception {
        throw new Exception("RaErrorBean.throwException " + new Random().nextInt(100));
    }

    public void testAction() {
        try {
            final long timeBefore = System.currentTimeMillis();
            final String result = raMasterApiBean.testCall(raAuthenticationBean.getAuthenticationToken(), value, 12345);
            final long timeAfter = System.currentTimeMillis();
            raLocaleBean.addMessageInfo("somefunction_testok", result, timeAfter-timeBefore);
        } catch (AuthorizationDeniedException | EjbcaException e) {
            raLocaleBean.addMessageError("somefunction_testfail", e.getMessage());
        }
    }
}
