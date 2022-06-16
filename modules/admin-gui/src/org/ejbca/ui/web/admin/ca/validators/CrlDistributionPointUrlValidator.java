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

package org.ejbca.ui.web.admin.ca.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * JSF validator to check that input fields are valid urls while allowing for quotation marks
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.CrlDistributionPointUrlValidator")
public class CrlDistributionPointUrlValidator implements Validator<Object> {
    private static final Logger log = Logger.getLogger(CrlDistributionPointUrlValidator.class);
    
    @Override
    public void validate(FacesContext facesContext, UIComponent uiComponent, Object o) throws ValidatorException {
        String urlValue = o.toString();
        if (StringUtils.isNotEmpty(urlValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Validating component " + uiComponent.getClientId(facesContext) + " with value \"" + urlValue + "\"");
            }
            boolean error;
            // Ignore quotation marks, see ECA-10623
            urlValue = urlValue.replace("\"", "");
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
