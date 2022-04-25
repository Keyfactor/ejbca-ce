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
package org.ejbca.ui.web.rest.api.resource.swagger;

import io.swagger.annotations.Api;
import io.swagger.annotations.Info;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResource;

import javax.ejb.Stateless;

/**
 * JAX-RS resource handling Certificate related requests.
 */
@Api(tags = {"v1/certificate"}, value = "Certificate REST Management API")
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
public class CertificateRestResourceSwagger extends CertificateRestResource {

}
