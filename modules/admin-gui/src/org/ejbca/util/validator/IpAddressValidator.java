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

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import com.keyfactor.util.StringTools;

/**
 * Validator used in validating IP addresses in jsf pages (Acme alias configuration for example).
 */
@FacesValidator("org.ejbca.util.validator.ipAddressValidator")
public class IpAddressValidator implements Validator<Object> {
 
    @Override
    public void validate(FacesContext context, UIComponent component, Object value) {
        if (!StringTools.isIpAddress((String) value)) {
            throw new ValidatorException(new FacesMessage("Incorrectly formatted IP address!"));
        }
    }
}
