/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.controllers;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.apache.log4j.Logger;

/**
 * JAX-RS resource handling certificate-related requests.
 * @version $Id: CertificateResource.java 28867 2018-05-08 09:26:51Z tarmo_r_helmes $
 *
 */
@Path("v1/certificate")
public class CertificateController {
    
    private static final Logger log = Logger.getLogger(CertificateController.class);
    
    /* test it with endpoint:
     * https://localhost:8443/ejbca/ejbca-rest-api/v1/certificate/hello
     */
    @GET
    @Path("/hello")
    @Produces("text/html")
    public String hello() {
        return "hello";
    }
}
