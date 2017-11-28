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

import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.Validator;
import javax.faces.validator.ValidatorException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;

/**
 * Validator which will validate that a BigInteger value is smaller than another input value.
 * 
 * @version $Id$
 */
public class MinSmallerThanMaxValidator implements Validator {
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(MinSmallerThanMaxValidator.class);

    @Override
    public void validate(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        final BigInteger minValue = (BigInteger) value;
        final String maxInput = (String) component.getAttributes().get("maxFieldInput");
        if (StringUtils.isNotBlank(maxInput) && minValue != null) {
            final BigInteger maxValue = new BigInteger(maxInput);
                if (minValue.compareTo(maxValue) == 1) {
                    final String field = (String) component.getAttributes().get("fieldName");
                    final String message = intres.getLocalizedMessage("validator.error.minimum_bigger", field, minValue, maxValue);
                    if (log.isDebugEnabled()) {
                        log.debug(message);
                    }
                    throw new ValidatorException(new FacesMessage(FacesMessage.SEVERITY_ERROR, message, message));
                }
        }
    }
}
