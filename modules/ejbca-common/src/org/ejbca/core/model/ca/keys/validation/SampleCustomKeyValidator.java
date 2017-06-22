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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.keys.validation.ICustomKeyValidator;
import org.cesecore.keys.validation.KeyValidationException;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;

/**
 * Sample custom key validator implementation for demo purposes (set read only to true).
 * 
 * @version $Id$
 */
public class SampleCustomKeyValidator extends AbstractCustomKeyValidator
        implements ICustomKeyValidator, CustomKeyValidatorUiSupport, CustomKeyValidatorAccessRulesSupport {

    private static final long serialVersionUID = -346987196113439948L;

    /** Class logger. */
    protected static final Logger LOG = Logger.getLogger(SampleCustomKeyValidator.class);

    /** View template in /ca/editkeyvalidators. */
    protected static final String TEMPLATE_FILE = "editCustomKeyValidator.xhtml";

    // Sample property keys.
    protected static final String PROPERTYKEY_INTID = "intId";
    protected static final String PROPERTYKEY_BOOLEANVALUE = "booleanValue";
    protected static final String PROPERTYKEY_STRINGVALUE = "stringValue";
    protected static final String PROPERTYKEY_STRINGOUTPUT = "stringOutput";

    // Sample properties.
    private int intId = 0;
    private boolean booleanValue = true;
    private String stringValue = "DefaultStringValue";
    private String stringOutput = "DefaultStringOutput";

    List<CustomKeyValidatorProperty> customProperties;

    @Override
    public String getTemplateFile() {
        return TEMPLATE_FILE;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void init() {
        // Load from data store.
        final Properties properties = CustomKeyValidatorTools.getProperties(getPropertyData());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Init sample custom key validator with properties:");
            final List<String> list = (List<String>) Collections.list(properties.propertyNames());
            Collections.sort(list);
            for (String key : list) {
                LOG.debug(key + " - " + properties.getProperty(key));
            }
        }
        intId = Integer.parseInt(properties.getProperty(PROPERTYKEY_INTID, "0"));
        booleanValue = Boolean.parseBoolean(properties.getProperty(PROPERTYKEY_BOOLEANVALUE, Boolean.TRUE.toString()));
        stringValue = properties.getProperty(PROPERTYKEY_STRINGVALUE, "SampleStringValue");
        stringOutput = properties.getProperty(PROPERTYKEY_STRINGOUTPUT, "SampleStringOutput");
    }

    @Override
    public List<CustomKeyValidatorProperty> getCustomUiPropertyList() {
        if (null == customProperties) {
            customProperties = new ArrayList<CustomKeyValidatorProperty>();
            final List<String> intIdOptions = new ArrayList<String>();
            final List<String> intIdOptionTexts = new ArrayList<String>();
            intIdOptions.add(Integer.toString(0));
            intIdOptions.add(Integer.toString(1));
            intIdOptions.add(Integer.toString(2));
            intIdOptionTexts.add("Option 0");
            intIdOptionTexts.add("Option 1");
            intIdOptionTexts.add("Option 2");
            customProperties.add(new CustomKeyValidatorProperty(PROPERTYKEY_INTID, CustomPublisherProperty.UI_SELECTONE, intIdOptions,
                    intIdOptionTexts, Integer.toString(intId)));
            customProperties.add(new CustomKeyValidatorProperty(PROPERTYKEY_STRINGVALUE, CustomKeyValidatorProperty.UI_TEXTINPUT, stringValue));
            customProperties.add(
                    new CustomKeyValidatorProperty(PROPERTYKEY_BOOLEANVALUE, CustomKeyValidatorProperty.UI_BOOLEAN, Boolean.toString(booleanValue)));
            customProperties.add(new CustomKeyValidatorProperty(PROPERTYKEY_STRINGOUTPUT, CustomKeyValidatorProperty.UI_TEXTOUTPUT, stringOutput));
        }
        return customProperties;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        final SampleCustomKeyValidator clone = new SampleCustomKeyValidator();
        @SuppressWarnings("unchecked")
        final HashMap<Object, Object> clonedata = (HashMap<Object, Object>) clone.saveData();
        for (Object key : this.data.keySet()) {
            clonedata.put(key, this.data.get(key));
        }
        clone.loadData(clonedata);
        return clone;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public void before() {
        if (LOG.isDebugEnabled()) {
            LOG.debug(getClassPath() + ".before called: ");
        }
    }

    @Override
    public boolean validate(PublicKey publicKey) throws KeyValidationException, Exception {
        boolean result = true;
        if (LOG.isDebugEnabled()) {
            LOG.debug(getClassPath() + ".validate called: " + result);
        }
        return result;
    }

    @Override
    public void after() {
        if (LOG.isDebugEnabled()) {
            LOG.debug(getClassPath() + ".after called: ");
        }
    }
}
