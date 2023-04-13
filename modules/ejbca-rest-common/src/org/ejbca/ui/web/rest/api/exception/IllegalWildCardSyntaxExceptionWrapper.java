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
package org.ejbca.ui.web.rest.api.exception;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.ejbca.configdump.ConfigdumpPattern.IllegalWildCardSyntaxException;

/**
 * Mapper that converts include/exclude format errors to HTTP BAD_REQUEST.
 */
@Provider
public class IllegalWildCardSyntaxExceptionWrapper implements ExceptionMapper<IllegalWildCardSyntaxException>{

    @Override
    public Response toResponse(IllegalWildCardSyntaxException arg0) {
        return Response.status(Response.Status.BAD_REQUEST.getStatusCode()).entity(arg0.getLocalizedMessage()).build();
    }

}
