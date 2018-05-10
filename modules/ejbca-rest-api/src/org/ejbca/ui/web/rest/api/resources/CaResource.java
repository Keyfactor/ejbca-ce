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

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.ui.web.rest.api.types.CaType;

/**
 * JAX-RS resource handling CA related requests.
 * 
 * @version $Id$
 *
 */
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
public class CaResource {
    
    private static final Logger log = Logger.getLogger(CaResource.class);
    
    private static final String VERSION = "1";
    
    @EJB
    private CaSessionLocal caSession;
    
    @GET
    public Response getCAs() {
        log.trace(">getCAs");
        
        List<CaType> caList = new ArrayList<CaType>();
        
        for (final Entry<Integer, String> caEntry : caSession.getCAIdToNameMap().entrySet()) {
            caList.add(new CaType(caEntry.getKey(), caEntry.getValue()));
        }

        log.trace("<getCAs");
        return Response.ok(caList).build();
    }

    @GET
    @Path("/version")
    @Produces(MediaType.TEXT_HTML)
    public Response getApiVersion() {
        return Response.ok(VERSION).build();
    }
}
