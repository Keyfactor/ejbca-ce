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

package org.ejbca.ui.web.rest.api.resources;

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
public class CertificateResource {
    
    private static final String VERSION = "1";
    
    private static final Logger log = Logger.getLogger(CertificateResource.class);
    
    
    @GET
    @Path("/version")
    @Produces("text/html")
    public String version() {
        return VERSION;
    }
}
