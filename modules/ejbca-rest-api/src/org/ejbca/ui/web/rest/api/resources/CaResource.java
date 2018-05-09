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

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.rest.api.types.CaType;

/**
 * JAX-RS resource handling CA related requests.
 * 
 * @version $Id$
 *
 */
@Path("/v1/ca")
public class CaResource {
    
    private static final Logger log = Logger.getLogger(CaResource.class);
    
    private CaSessionLocal caSession;     
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCAs() {
        log.trace(">getCAs");
        caSession = new EjbLocalHelper().getCaSession();
        
        List<CaType> result = new ArrayList<CaType>();
        
        for (final Entry<Integer, String> caEntry : caSession.getCAIdToNameMap().entrySet()) {
            result.add(new CaType(caEntry.getKey(), caEntry.getValue()));
        }
        
        log.trace("<getCAs");
        return Response.ok(result).build();
    }
}
