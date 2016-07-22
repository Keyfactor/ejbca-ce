package org.ejbca.ra.jsfext;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.RequestScoped;

/**
 * Request scoped managed bean that can be used to focus an html element after form submit
 * Usage:
 * 1) For the element want to focus, add a new boolean property (etc. HtmlElementFocusBean.booleanForElementX)
 * 2) Set styleClass to that element: styleClass="#{htmlElementFocusBean.booleanForElementX?'jsAutoFocusJsf':''}
 * 3) Add action listener to the element that submits form <f:actionListener binding="#{htmlElementFocusBean.setBooleanForElementX(true)}"/>
 * Note: Preferably bean property name should be the same as xhtml id.
 * 
 * @version $Id$
 */
@ManagedBean
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
