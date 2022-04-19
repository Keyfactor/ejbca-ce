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
