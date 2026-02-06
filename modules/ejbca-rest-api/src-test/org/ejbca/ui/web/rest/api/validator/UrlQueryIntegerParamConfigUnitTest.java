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

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import org.ejbca.ui.web.rest.api.resource.swagger.ConfigdumpRestResourceSwagger;
import org.ejbca.util.UrlQueryParamsValidator;
import org.junit.Assert;
import org.junit.Test;
import org.reflections.Reflections;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import jakarta.ws.rs.QueryParam;


public class UrlQueryIntegerParamConfigUnitTest {
    
    boolean properlyConfigured = true;
    StringBuilder stringBuilder = new StringBuilder();
    
    @Test
    public void testUrlQueryIntegerParamConfigs() {
        Reflections reflections = new Reflections("org.ejbca.ui.web.rest.api.resource.swagger");
        
        reflections.getTypesAnnotatedWith(OpenAPIDefinition.class)
                    .forEach(x -> scan(x));
        
        if (!stringBuilder.isEmpty()) {
            Assert.fail(stringBuilder.toString());
        }
        
    }
    
    private void scan(Class<?> clazz) {
        
        if (clazz.equals(ConfigdumpRestResourceSwagger.class)) {
            return;
        }
        
        for (Method method : clazz.getDeclaredMethods()) {

            for (Parameter parameter : method.getParameters()) {
                QueryParam qp = parameter.getAnnotation(QueryParam.class);
                
                if (qp==null) {
                    continue;
                }

                if (parameter.getType().toString().equals("int") && 
                        !UrlQueryParamsValidator.INTEGER_QUERY_PARAMS.contains(qp.value())) {
                    stringBuilder.append(
                            "Class: " + clazz.getSimpleName()
                            + ", Method: " + method.getName()
                            + ", Param: " + parameter.getName()
                            + ", QueryParam value: " + qp.value()
                            + ", type: " + parameter.getType()
                    );
                }
                
                if (parameter.getType().toString().equals("boolean") && 
                        !UrlQueryParamsValidator.BOOLEAN_QUERY_PARAMS.contains(qp.value())) {
                    stringBuilder.append(
                            "Class: " + clazz.getSimpleName()
                            + ", Method: " + method.getName()
                            + ", QueryParam value: " + qp.value()
                            + ", type: " + parameter.getType()
                    );
                }
            }
        }
    }

}
