package org.ejbca.ui.web.rest.api.resource;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.services.ServiceDataSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.ui.web.rest.api.exception.RestException;

/**
 * JAX-RS resource handling System related requests.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)

public class SystemRestResource extends BaseRestResource {
    
    @EJB
    private ServiceSessionLocal serviceSession;
    
    @EJB
    private ServiceDataSessionLocal serviceDataSession;
    
    private static final Logger log = Logger.getLogger(SystemRestResource.class);

    public Response runServiceWorker(
            final HttpServletRequest requestContext,
            final String serviceName)throws RestException{
        try {
            getAdmin(requestContext, false);
        } catch (AuthorizationDeniedException e) {
            throw new RestException(Status.UNAUTHORIZED.getStatusCode(), e.getMessage());
        }
        final Integer serviceId = serviceSession.getServiceId(serviceName);
        if (serviceId == 0) {
            String exception = "The following service could not be found: " + serviceName;
            log.info(exception);
            throw new RestException(Status.NOT_FOUND.getStatusCode(),  exception);
        }
        try {
            serviceSession.runServiceNoTimer(serviceId);
        } catch (ServiceExecutionFailedException exception) {
            String message = "The service could not run or was already running: " + serviceName;
            log.info(exception.getMessage());
            throw new RestException(Status.CONFLICT.getStatusCode(), message );            
        }
        return Response.status(Status.OK).build();
    }
}
