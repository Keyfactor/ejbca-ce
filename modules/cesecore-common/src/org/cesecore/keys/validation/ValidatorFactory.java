/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import org.apache.commons.collections4.CollectionUtils;

/**
 * Reads in the implementations of the Validator interface.  
 */
public enum ValidatorFactory {
    INSTANCE;

    private Map<String, Validator> identifierToImplementationMap = new HashMap<>();

    private ValidatorFactory() {
        ServiceLoader<Validator> svcloader = ServiceLoader.load(Validator.class);
        for(Validator type : svcloader) {
            type.initialize();
            identifierToImplementationMap.put(type.getValidatorTypeIdentifier(), type);
        }
    }
    
    public List<Validator> getAllImplementations() {
        return new ArrayList<>(identifierToImplementationMap.values());
    }
    
    public List<Validator> getAllImplementations(final List<Class<?>> excludeClasses) {
        if (CollectionUtils.isNotEmpty(excludeClasses)) {
            final List<Validator> result = new ArrayList<>();
            for (Validator validator : getAllImplementations()) {
                if (!excludeClasses.contains(validator.getClass())) {
                    result.add(validator);
                }
            }
            return result;
        } else {
            return getAllImplementations();
        }
    }
    
    public Validator getArcheType(String identifier) {
        return identifierToImplementationMap.get(identifier).clone();
    }
    
   
}
