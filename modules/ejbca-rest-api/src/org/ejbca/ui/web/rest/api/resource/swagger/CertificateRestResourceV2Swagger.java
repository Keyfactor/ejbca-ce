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
import io.swagger.annotations.Info;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResourceV2;

import javax.ejb.Stateless;

/**
 * JAX-RS resource handling Certificate related requests.
 */
@Api(tags = {"v2/certificate"}, value = "Certificate REST Management API")
@SwaggerDefinition(
        /* @Info annotation seems to work properly only when it is configured only once. Must not specify it on any other RestResources in this module! */
        info = @Info(
                title = "EJBCA REST Interface",
                version = BaseRestResource.RESOURCE_VERSION,
                description = "API reference documentation."
        ),
        basePath = "/ejbca/ejbca-rest-api",
        schemes = {Scheme.HTTPS}
)
@Stateless
public class CertificateRestResourceV2Swagger extends CertificateRestResourceV2 {

}
