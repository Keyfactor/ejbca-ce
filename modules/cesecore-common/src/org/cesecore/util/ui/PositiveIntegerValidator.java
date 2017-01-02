/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util.ui;

import org.cesecore.internal.InternalResources;

/**
 * Validator which will validate an integer to greater or equal to 0
 * 
 * @version $Id$
 *
 */
public class PositiveIntegerValidator implements DynamicUiPropertyValidator<Integer> {

  
    private static final long serialVersionUID = 1L;

    private static final String VALIDATOR_TYPE = "positiveIntegerValidator";
    
    private static final InternalResources intres = InternalResources.getInstance();
    
    @Override
    public void validate(Integer value) throws PropertyValidationException{
        validateInteger(value);
    }

    @Override
    public String getValidatorType() {
        return VALIDATOR_TYPE;
    }
    
    public static void validateInteger(Integer value) throws PropertyValidationException{
        if(value.intValue() < 0) {
            throw new PropertyValidationException(intres.getLocalizedMessage("dynamic.property.validation.positiveinteger.failure", value.toString()));
        }
    }


}
