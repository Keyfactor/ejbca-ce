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
import org.cesecore.util.SimpleTime;

/**
 * Validator used in validating CRL and Validity fields.
 * 
 * @version $Id: CRLFieldValidator.java 30439 2018-11-08 13:35:31Z aminkh $
 *
 */
@FacesValidator("org.ejbca.ui.web.admin.ca.validators.CRLFieldValidator")
public class CRLFieldValidator implements Validator {

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        SimpleTime simpleTime = SimpleTime.getInstance((String)value, StringUtils.EMPTY);

        if (!value.toString().equals(StringUtils.EMPTY) && (simpleTime == null)) {
            FacesMessage msg = new FacesMessage("Invalid CRL or Validity field input!");
            msg.setSeverity(FacesMessage.SEVERITY_ERROR);
            throw new ValidatorException(msg);
        }
    }
}
