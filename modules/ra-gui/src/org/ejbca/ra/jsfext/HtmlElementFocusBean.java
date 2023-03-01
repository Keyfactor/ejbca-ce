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
package org.ejbca.ra.jsfext;

import javax.enterprise.context.RequestScoped;
import javax.inject.Named;

/**
 * Request scoped managed bean that can be used to focus an html element after form submit
 * Usage:
 * 1) For the element want to focus, add a new boolean property (etc. HtmlElementFocusBean.booleanForElementX)
 * 2) Set styleClass to that element: styleClass="#{htmlElementFocusBean.booleanForElementX?'jsAutoFocusJsf':''}
 * 3) Add action listener to the element that submits form <f:actionListener binding="#{htmlElementFocusBean.setBooleanForElementX(true)}"/>
 * Note: Preferably bean property name should be the same as xhtml id.
 * 
 */
@Named
@RequestScoped
public class HtmlElementFocusBean {

    private boolean requestPreviewMoreDetails = false;

    public boolean isRequestPreviewMoreDetails() {
        return requestPreviewMoreDetails;
    }

    public void setRequestPreviewMoreDetails(boolean requestPreviewMoreDetails) {
        this.requestPreviewMoreDetails = requestPreviewMoreDetails;
    }

}
