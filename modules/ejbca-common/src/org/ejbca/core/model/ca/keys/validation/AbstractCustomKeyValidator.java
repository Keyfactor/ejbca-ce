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

package org.ejbca.core.model.ca.keys.validation;

import java.security.PublicKey;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.validation.BaseKeyValidator;
import org.cesecore.keys.validation.KeyValidationException;

/**
 * AbstractCustomKeyValidator is a class handling a custom key validator. It is used 
 * to store and retrieve custom key validator configurations to database.
 * 
 *
 * @version $Id: AbstractCustomKeyValidator.java 25281 2017-03-01 12:12:00Z anjakobs $
 */
public abstract class AbstractCustomKeyValidator extends BaseKeyValidator {

    private static final long serialVersionUID = -3460671964358399488L;

    /** The key validator type. */
    public static final int KEY_VALIDATOR_TYPE = 0;

    protected static final String CLASSPATH = "classpath";

    protected static final String PROPERTYDATA = "propertydata";

    /**
     * Creates a new instance.
     */
    protected AbstractCustomKeyValidator() {
        super();
        setType(Integer.valueOf(KEY_VALIDATOR_TYPE));
        setClassPath(getClass().getName());
        setPropertyData(StringUtils.EMPTY);
    }

    @Override
    public Integer getKeyValidatorType() {
        return KEY_VALIDATOR_TYPE;
    }

    /**
     *  Gets the class path of custom key validator used.
     */
    public String getClassPath() {
        return (String) data.get(CLASSPATH);
    }

    /**
     *  Sets the class path of custom key validator used.
     */
    public void setClassPath(final String classpath) {
        data.put(CLASSPATH, classpath);
    }

    /**
     *  Gets the property data used to configure this custom key validator.
     */
    public String getPropertyData() {
        return (String) data.get(PROPERTYDATA);
    }

    /**
     * Sets the property data used to configure this custom key validator.
     * @param value the the value to set.
     */
    public void setPropertyData(final String value) {
        data.put(PROPERTYDATA, value);
    }

    /**
     * Custom access rules supported.
     * 
     * @return true if the implementation class is an instance of {@link CustomKeyValidatorAccessRulesSupport}.
     */
    public boolean isCustomAccessRulesSupported() {
        return this instanceof CustomKeyValidatorAccessRulesSupport;
    }

    /**
     * Custom UI rendering supported.
     * 
     * @return true if the implementation class is an instance of {@link CustomKeyValidatorUiSupport}.
     */
    public boolean isCustomUiRenderingSupported() {
        return this instanceof CustomKeyValidatorUiSupport;
    }

    /**
     * Checks authorization to edit key validators.
     * @param authenticationToken the administrator.
     * @return true if the administrator is allows to edit key validators.
     */
    public boolean isAuthorizedToKeyValidator(final AuthenticationToken authenticationToken) {
        if (this instanceof CustomKeyValidatorAccessRulesSupport) {
            return ((CustomKeyValidatorAccessRulesSupport) this).isAuthorizedToKeyValidator(authenticationToken);
        }
        return true;
    }

    public abstract List<CustomKeyValidatorProperty> getCustomUiPropertyList();

    @Override
    public abstract String getTemplateFile();

    @Override
    public abstract Object clone() throws CloneNotSupportedException;

    @Override
    public abstract void before();

    @Override
    public abstract boolean validate(final PublicKey publicKey) throws KeyValidationException, Exception;

    @Override
    public abstract void after();
}
