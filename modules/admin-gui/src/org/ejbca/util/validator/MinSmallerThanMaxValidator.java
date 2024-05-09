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

import java.math.BigInteger;

import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.validator.FacesValidator;
import jakarta.faces.validator.Validator;
import jakarta.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;

/**
 * Validator which will validate that a BigInteger value is smaller than another input value.
 * 
 */
@FacesValidator("minSmallerThanMaxValidator")
public class MinSmallerThanMaxValidator implements Validator<Object> {
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(MinSmallerThanMaxValidator.class);

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final BigInteger minValue = (BigInteger) value;
        final String maxInput = (String) component.getAttributes().get("maxFieldInput");
        
        if (StringUtils.isNotBlank(maxInput) && minValue != null && minValue.compareTo(new BigInteger(maxInput)) == 1) {
            final String field = (String) component.getAttributes().get("fieldName");
            final String message = intres.getLocalizedMessage("validator.error.minimum_bigger", field, minValue, maxInput);
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
        }
    }
}
