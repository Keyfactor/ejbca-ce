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
package org.ejbca.ui.web.rest.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.core.jackson.ModelResolver;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

import org.reflections.Reflections;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

/**
 * EJBCA REST API application based on RESTEasy
 */
@ApplicationPath("/")
public class RestApiApplication extends Application {

    private static final Logger log = Logger.getLogger(RestApiApplication.class);

    public RestApiApplication() {
        if (!EjbcaConfiguration.getIsInProductionMode()) {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

            ModelConverters.getInstance().addConverter(new ModelResolver(mapper));
        }
    }

    /* In order to use swagger which requires manual registration, we also need to manually register out @Provider annotated classes now. */
    @Override
    public Set<Class<?>> getClasses() {
        final Set<Class<?>> resources = new HashSet<>();
        resources.add(org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver.class);
        resources.add(org.ejbca.ui.web.rest.api.config.ExceptionHandler.class);
        resources.add(org.ejbca.ui.web.rest.api.exception.IllegalWildCardSyntaxExceptionWrapper.class);
        resources.add(org.ejbca.ui.web.rest.api.exception.ValidationExceptionMapper.class);
        resources.add(org.ejbca.ui.web.rest.api.exception.JsonProcessingExceptionMapper.class);

        Reflections restResourceDefinitions = new Reflections("org.ejbca.ui.web.rest.api.resource.swagger");
        Set<Class<?>> restResources = restResourceDefinitions.getTypesAnnotatedWith(OpenAPIDefinition.class);
        resources.addAll(restResources);

        if (EjbcaConfiguration.getIsInProductionMode()) {
            log.debug("Swagger is not available in distribution.");
        } else {
            resources.add(io.swagger.v3.jaxrs2.integration.resources.OpenApiResource.class);
            resources.add(io.swagger.v3.jaxrs2.SwaggerSerializers.class);
        }
        return resources;
    }
}
