/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import io.swagger.annotations.Api;
import io.swagger.annotations.Info;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;

/**
 * JAX-RS resource handling Crypto Token related requests.
 *
 * @version $Id: CryptoTokenRestResource.java 32447 2019-05-28 12:38:14Z aminkh $
 */
@Api(tags = {"v1/cryptotoken"}, value = "Crypto Token REST Management API")
@SwaggerDefinition(info =
@Info(
    title = "EJBCA Crypto Token REST Interface",
    version = BaseRestResource.RESOURCE_VERSION,
    description = "API reference documentation."
    ),
basePath="/ejbca/ejbca-rest-api",
schemes={Scheme.HTTPS}
)
public class CryptoTokenRestResourceSwagger extends CryptoTokenRestResource {
    
}
