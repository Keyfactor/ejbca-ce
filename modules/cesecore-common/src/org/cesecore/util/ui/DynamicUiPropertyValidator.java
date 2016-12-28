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
package org.cesecore.util.ui;

import java.io.Serializable;

/**
 * This interface defines common methods for all Validator types, i.e classes which can be attached to DynamicUiProperties in order to validate 
 * their values. Extends javax.faces.validator.Validator, meaning that it can be used both internally (through the validate(T value) method 
 * defined here) and through the one defined in Validator. 
 *
 * @version $Id$
 *
 */
public interface DynamicUiPropertyValidator<T extends Serializable> extends Serializable {
    
    /**
     * 
     * @param value the value to be validated
     * @return true if the value passes validation
     * 
     * @throws PropertyValidationException if the validation failed, including a detailed error message.
     */
    void validate(T value) throws PropertyValidationException;
    
    /**
     * This method allows the JSF frontend to use different validators, depending on 
     * 
     * @return the ID of this validator, for JSF purposes. Must math an ID defined in modules/admin-gui/resources/WEB-INF/faces-config.xml
     */
    String getValidatorType();

}
