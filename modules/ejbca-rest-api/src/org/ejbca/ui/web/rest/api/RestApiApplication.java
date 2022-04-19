/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api;

import io.swagger.annotations.SwaggerDefinition;
import io.swagger.converter.ModelConverters;
import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.util.swagger.SnakeCaseConverter;
import org.reflections.Reflections;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
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
            ModelConverters.getInstance().addConverter(new SnakeCaseConverter());
        }
    }

    /* In order to use swagger which requires manual registration, we also need to manually register out @Provider annotated classes now. */
    @Override
    public Set<Class<?>> getClasses() {
        final Set<Class<?>> resources = new HashSet<>();
        resources.add(org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver.class);
        resources.add(org.ejbca.ui.web.rest.api.config.ExceptionHandler.class);
        resources.add(org.ejbca.ui.web.rest.api.exception.IllegalWildCardSyntaxExceptionWrapper.class);

        Reflections restResourceDefinitions = new Reflections("org.ejbca.ui.web.rest.api.resource.swagger");
        Set<Class<?>> restResources = restResourceDefinitions.getTypesAnnotatedWith(SwaggerDefinition.class);
        resources.addAll(restResources);

        if (EjbcaConfiguration.getIsInProductionMode()) {
            log.debug("Swagger is not available in distribution.");
        } else {
            resources.add(io.swagger.jaxrs.listing.ApiListingResource.class);
            resources.add(io.swagger.jaxrs.listing.SwaggerSerializers.class);
        }
        return resources;
    }
}
