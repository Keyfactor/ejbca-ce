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
import org.ejbca.ui.web.rest.api.resource.EndEntityRestResourceV2;

import javax.ejb.Stateless;

/**
 * JAX-RS resource handling End Entity related requests.
 */
@Api(tags = {"v2/endentity"}, value = "End Entity REST Management API V2")
@SwaggerDefinition(basePath="/ejbca/ejbca-rest-api", schemes={Scheme.HTTPS})
@Stateless
public class EndEntityRestResourceSwaggerV2 extends EndEntityRestResourceV2 {

}
