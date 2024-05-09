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

import java.util.regex.Pattern;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

/**
 * Validator to validate a comma separated list of ports.
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.PortListValidator")
public class PortListValidator implements Validator<String> {

    @Override
    public void validate(FacesContext context, UIComponent component, String value) throws ValidatorException {
        boolean isValid = true;
        if (value != null && value.length() > 0) {
            if (Pattern.matches("^([0-9]{1,5})(,([0-9]{1,5}))*$", value)) {
                final String[] tokens = value.split(",");
                for (String token : tokens) {
                    final int port = Integer.parseInt(token);
                    if (port < 1 || port > 65535) {
                        isValid = false;
                        break;
                    }
                }
            } else {
                isValid = false;
            }
        }
        if (!isValid) {
            FacesMessage msg = new FacesMessage("The list of ports separated by comma must contain valid ports from 1 to 65.535.");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
