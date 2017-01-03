/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.validator;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.cesecore.util.ui.PropertyValidationException;

/**
 * Validator which will validate an integer to greater or equal to 0, mirrors {@link org.cesecore.util.ui.PositiveIntegerValidator}
 * 
 * @version $Id$
 *
 */
public class PositiveIntegerValidator implements Validator {

    @Override
    public void validate(FacesContext context, UIComponent component, Object object) throws ValidatorException {
        try {
            org.cesecore.util.ui.PositiveIntegerValidator.validateInteger((Integer) object);
        } catch (PropertyValidationException e) {
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, e.getMessage(), null));
        }
        
    }




}
