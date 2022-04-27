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
package org.ejbca.util.validator;

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.FacesValidator;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

/**
 * JSF validator that shows an error if a checkbox is not checked.
 *
 * @version $Id$
 */
@FacesValidator("org.ejbca.util.validator.RequiredCheckboxValidator")
public class RequiredCheckboxValidator implements Validator<Object> {

    @Override
    public void validate(final FacesContext facesContext, final UIComponent uiComponent, final Object o) throws ValidatorException {
        if (o == null || (boolean) o != true) {
            final String message = (String) uiComponent.getAttributes().get("errorMessage");
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, null));
        }
    }

}
