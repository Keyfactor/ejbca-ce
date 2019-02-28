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

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;

/**
 * Validator used in validating CA Serial Number Octet Size field.
 * 
 * @version $Id$
 *
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.OctetSizeValidator")
public class OctetSizeValidator implements Validator {

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        boolean isValid = true;
        String valueString = (String)value;
        if (!StringUtils.isNumeric(valueString) || valueString.equals("")) {
            isValid = false;
        } else {
            int octetSize = Integer.parseInt((String)value);
            if (octetSize < 4 || octetSize > 20) {
                isValid = false;
            }
        }
        
        if (!isValid) {
            FacesMessage msg = new FacesMessage("CA Serial Number Octet Size must be a number between 4 and 20");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
