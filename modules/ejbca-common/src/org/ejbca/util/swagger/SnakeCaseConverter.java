/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.swagger;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import io.swagger.converter.ModelConverter;
import io.swagger.converter.ModelConverterContext;
import io.swagger.models.Model;
import io.swagger.models.properties.Property;

/**
 * Converter for Swagger to be able to accept input parameters in snake_case format
 *
 * @version $Id: SnakeCaseConverter.java 29080 2018-05-31 11:12:13Z tarmor_r_helmes $
 */
public class SnakeCaseConverter implements ModelConverter {

    @Override
    public Property resolveProperty(Type type, ModelConverterContext context, Annotation[] annotations, Iterator<ModelConverter> chain) {
        if (chain.hasNext()) {
            final ModelConverter converter = chain.next();
            return converter.resolveProperty(type, context, annotations, chain);
        }
        return null;
    }

    @Override
    public Model resolve(Type type, ModelConverterContext context, Iterator<ModelConverter> chain) {
        if (chain.hasNext()) {
            final ModelConverter converter = chain.next();
            final Model model = converter.resolve(type, context, chain);
            if (model != null) {
                final Map<String, Property> properties = model.getProperties();
                final Map<String, Property> newProperties = new LinkedHashMap<>();
                for (String key : properties.keySet()) {
                    newProperties.put(toSnakeCase(key), properties.get(key));
                }
                model.getProperties().clear();
                model.setProperties(newProperties);
                return model;
            }
        }
        return null;
    }
    
    private static String toSnakeCase(String input) {
        if (input == null) {
            return input;
        }
        int length = input.length();
        StringBuilder result = new StringBuilder(length * 2);
        int resultLength = 0;
        boolean wasPrevTranslated = false;
        for (int i = 0; i < length; i++) {
            char c = input.charAt(i);
            if (i > 0 || c != '_') // skip first starting underscore
            {
                if (Character.isUpperCase(c)) {
                    if (!wasPrevTranslated && resultLength > 0 && result.charAt(resultLength - 1) != '_') {
                        result.append('_');
                        resultLength++;
                    }
                    c = Character.toLowerCase(c);
                    wasPrevTranslated = true;
                } else {
                    wasPrevTranslated = false;
                }
                result.append(c);
                resultLength++;
            }
        }
        return (resultLength > 0) ? result.toString() : input;
    }
}