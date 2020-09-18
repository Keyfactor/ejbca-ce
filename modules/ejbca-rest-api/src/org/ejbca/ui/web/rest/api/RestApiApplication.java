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

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.util.swagger.SnakeCaseConverter;

import io.swagger.converter.ModelConverters;

/**
 * EJBCA rest api application based on RESTEasy
 *  
 * @version $Id$
 */
@ApplicationPath("/")
public class RestApiApplication extends Application {

    private static final Logger log = Logger.getLogger(RestApiApplication.class);

    public RestApiApplication() {
        if (!EjbcaConfiguration.getIsInProductionMode()) {
            ModelConverters.getInstance().addConverter(new SnakeCaseConverter());
        }
        
        // Configure what can't be configured with annotations using a BeanConfig
        //final io.swagger.jaxrs.config.BeanConfig beanConfig = new io.swagger.jaxrs.config.BeanConfig();
        //beanConfig.setPrettyPrint(true);
        //beanConfig.setBasePath("/ejbca/ejbca-rest-api");
        //beanConfig.setResourcePackage("org.ejbca.ui.web.rest.api");
        //beanConfig.setScan(true);
        
    }

    /* In order to use swagger which requires manual registration, we also need to manually register out @Provider annotated classes now. */
    @Override
    public Set<Class<?>> getClasses() {
        final Set<Class<?>> resources = new HashSet<>();
        resources.add(org.ejbca.ui.web.rest.api.resource.CertificateRestResource.class);
        resources.add(org.ejbca.ui.web.rest.api.resource.CaRestResource.class);
        resources.add(org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver.class);
        resources.add(org.ejbca.ui.web.rest.api.config.ExceptionHandler.class);
        
        resources.add(org.ejbca.ui.web.rest.api.resource.swagger.CryptoTokenRestResourceSwagger.class);
        resources.add(org.ejbca.ui.web.rest.api.resource.swagger.CaManagementRestResourceSwagger.class);
        
        if (EjbcaConfiguration.getIsInProductionMode()) {
            log.debug("Swagger is not available in distribution.");
        } else {
            resources.add(io.swagger.jaxrs.listing.ApiListingResource.class);
            resources.add(io.swagger.jaxrs.listing.SwaggerSerializers.class);
        }
        return resources;
    }
}
