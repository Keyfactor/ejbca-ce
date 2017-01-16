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
package org.ejbca.core.model.ra.raadmin.validators;

import java.io.Serializable;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.ejbca.core.model.ra.raadmin.EndEntityFieldValidator;
import org.ejbca.core.model.ra.raadmin.EndEntityFieldValidatorException;

/**
 * Validator for end entity fields that validates using regex'es specified in the end entity profile.
 * 
 * @version $Id$
 */
public class RegexFieldValidator implements EndEntityFieldValidator {
    
    @Override
    public void checkValidatorData(String field, Serializable validatorData) throws EndEntityFieldValidatorException {
        final String regex = (String)validatorData;
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new EndEntityFieldValidatorException("Invalid regex for field "+field+": "+e.getMessage());
        }
    }
    
    @Override
    public boolean isApplicableTo(final String field) {
        // Can be used with all fields
        return true;
    }

    @Override
    public void validate(final String field, final Serializable validatorData, final String value) throws EndEntityFieldValidatorException {
        // The DN component name is not used by this validator.
        final String regex = (String)validatorData;
        if (!Pattern.matches(regex, value == null ? "":value)) {
            throw new EndEntityFieldValidatorException("Technical details: Value \""+value+"\" does not match regex "+regex);
        }
    }

}
