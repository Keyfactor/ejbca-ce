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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * JSF validator to check that input fields are valid urls
 */
@FacesValidator("urlValidator")
public class UrlValidator implements Validator<Object> {
    private static final Logger log = Logger.getLogger(UrlValidator.class);
    
    

    @Override
    public void validate(FacesContext facesContext, UIComponent uiComponent, Object o) throws ValidatorException {
        String urlValue = o.toString();
        if (StringUtils.isNotEmpty(urlValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Validating component " + uiComponent.getClientId(facesContext) + " with value \"" + urlValue + "\"");
            }
            boolean error;
            if (urlValue.toString().indexOf(':') == -1) {
                error = true;
            } else {
                try {
                    new URI(urlValue.toString());
                    error = false;
                } catch (URISyntaxException e) {
                    error = true;
                }
            }
            if (error) {
                String msg = (String) uiComponent.getAttributes().get("errorMessage");
                if (StringUtils.isEmpty(msg)) {
                    msg = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("INVALIDURL");
                    
                }
                throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
            }
        }
    }
}
