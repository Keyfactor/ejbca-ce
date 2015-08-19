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
package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;

/**
 * Performs validation of fields in End Entities.
 * 
 * @version $Id$
 */
public interface EndEntityFieldValidator {
    
    /**
     * Checks if the given validator data is valid.
     * 
     * @param field Name of field that is being checked. Can be a DN component name or another field name.
     * @param validatorData Validator-specific data (e.g. a regex for the RegexFieldValidator)
     * @throws EndEntityFieldValidatorException if the validator data is not valid.
     */
    void checkValidatorData(String field, Serializable validatorData) throws EndEntityFieldValidatorException;
    
    /**
     * @param field A field name string from EndEntityProfile or DnComponents.
     * @return true if the validator is applicable to the given field.
     */
    boolean isApplicableTo(String field);
    
    /**
     * Validates a value of a field.
     * 
     * @param validatorData Validator-specific data (e.g. a regex for the RegexFieldValidator)
     * @param field Name of field that is being checked. Can be a DN component name or another field name.
     * @param value Value of field that is being checked.
     * @return A language string describing the error, or null if there's no error.
     * @throws EndEntityFieldValidatorException If the value is not valid.
     */
    void validate(String field, Serializable validatorData, String value) throws EndEntityFieldValidatorException;
    
}
