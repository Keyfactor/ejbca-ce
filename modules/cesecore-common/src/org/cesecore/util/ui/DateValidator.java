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

import java.text.ParseException;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.ValidityDate;

import com.keyfactor.util.StringTools;

/**
 * DynamicUIProperty Validator. Validating ISO8601 dates. 
 */
public class DateValidator implements DynamicUiPropertyValidator<String> {

    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(DateValidator.class);
    private static final InternalResources intres = InternalResources.getInstance();
    
    private static final String VALIDATOR_TYPE = "dateValidator";
    
    private String name;
    
    @Override
    public void validate(String value) throws PropertyValidationException {
        if (!StringUtils.isEmpty(value)) {
            if (StringTools.hasSqlStripChars(value).isEmpty()) {
                try {
                    ValidityDate.parseAsIso8601(value);
                } catch (ParseException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Validating ISO8601 date component with value '" + value + "' failed.");
                    }        
                    throw new PropertyValidationException(intres.getLocalizedMessage("dynamic.property.validation.dateformat.failure", value.toString()));
                }            
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Date component contains offending SQL strip characters: '" + value + "'");
                }
                throw new PropertyValidationException(intres.getLocalizedMessage("dynamic.property.validation.dateformat.failure", value.toString()));
            }
        }
    }

    @Override
    public String getValidatorType() {
        return VALIDATOR_TYPE;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

}