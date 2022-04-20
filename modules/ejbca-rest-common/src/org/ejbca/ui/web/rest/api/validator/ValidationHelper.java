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
package org.ejbca.ui.web.rest.api.validator;

import javax.validation.ConstraintValidatorContext;

/**
 * A helper class to manage constraint violation cases.
 *
 * @version $Id: ValidationHelper.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class ValidationHelper {

    // Private constructor
    private ValidationHelper() {
    }

    /**
     * Adds a violation to context.
     *
     * @param context context.
     * @param template key value of the template to use.
     */
    public static void addConstraintViolation(
            final ConstraintValidatorContext context,
            final String template) {
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(template).addConstraintViolation();
    }

}
