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
import org.cesecore.util.NetworkTools;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;
import java.net.URL;

/**
 * Input should be a valid uri
 * @version $Id$
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.UriValidator")
public class UriValidator implements Validator {

    @Override
    public void validate(FacesContext facesContext, UIComponent uiComponent, Object o) throws ValidatorException {
        String input = (String) o;
        if (StringUtils.isNotEmpty(input)) {
            final URL url = NetworkTools.getValidHttpUrl(input);
            if (url == null) {
                String errormessage = (String) uiComponent.getAttributes().get("errorMessage");
                FacesMessage msg = new FacesMessage(errormessage, "");
                msg.setSeverity(FacesMessage.SEVERITY_ERROR);
                throw new ValidatorException(msg);
            }
        }
    }

}
