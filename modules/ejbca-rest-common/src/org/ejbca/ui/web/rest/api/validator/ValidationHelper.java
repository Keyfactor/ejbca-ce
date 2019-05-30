/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
