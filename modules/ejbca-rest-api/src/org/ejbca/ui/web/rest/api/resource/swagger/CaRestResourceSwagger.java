/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource.swagger;

import io.swagger.annotations.Api;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;
import org.ejbca.ui.web.rest.api.resource.CaRestResource;

import javax.ejb.Stateless;

/**
 * JAX-RS resource handling CA related requests.
 */
@Api(tags = {"v1/ca"}, value = "CA REST API")
@SwaggerDefinition(basePath = "/ejbca/ejbca-rest-api", schemes = {Scheme.HTTPS})
@Stateless
public class CaRestResourceSwagger extends CaRestResource {

}
