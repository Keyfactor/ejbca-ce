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

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.ejbca.ui.web.rest.api.config.SnakeCaseConverter;

import io.swagger.converter.ModelConverters;
import io.swagger.jaxrs.config.BeanConfig;

/**
 * EJBCA rest api application based on RESTEasy
 *  
 * @version $Id$
 *
 */
@ApplicationPath("/")
public class RestApiApplication extends Application {
    // Nothing here for now so RESTEasy takes care of registering end points automatically.
    // Later if manual control over some resources required those could be added here.


    public RestApiApplication() {
        super();
        
        ModelConverters.getInstance().addConverter(new SnakeCaseConverter());
        
        BeanConfig beanConfig = new BeanConfig();
        beanConfig.setVersion("1.0.0");
        beanConfig.setSchemes(new String[]{"https"});
        beanConfig.setBasePath("/ejbca/ejbca-rest-api");
        beanConfig.setResourcePackage("org.ejbca.ui.web.rest.api.resource");
        beanConfig.setScan(true);
    }

}
