/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resources;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;

/**
 * JAX-RS resource handling CA related requests.
 * 
 * @version $Id$
 *
 */
@Path("/v1/ca")
public class CaResource {
    
    private static final Logger log = Logger.getLogger(CaResource.class);
    
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public List<String> getCAs() {
        log.trace(">getCAs");
        
        ArrayList<String> list = new ArrayList<String>();
        list.add("ItemOne");
        list.add("ItemTwo");
        list.add("ItemThree");
        
        log.trace("<getCAs");

        return new ArrayList<String>(list);

        
    }

}
