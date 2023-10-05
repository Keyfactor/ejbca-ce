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
import org.ejbca.core.model.services.ServiceExecutionResult;
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
            String exceptionMessage = "The following service could not be found: " + serviceName;
            log.info(exceptionMessage);
            throw new RestException(Status.NOT_FOUND.getStatusCode(),  exceptionMessage);
        }
        try {
            serviceSession.runServiceNoTimer(serviceId);
        } catch (ServiceExecutionFailedException exception) {
            String message = null;
            if (exception.getMessage().equals(ServiceExecutionResult.Result.FAILURE.toString())) {
                message = "The service " + serviceName + " failed. See server log.";
            } else if (exception.getMessage().equals(ServiceExecutionResult.Result.NO_ACTION.toString())){
                message = "The service " + serviceName + " did not run because there were no changes to be made or due to the same "
                        + "service already running. See server log.";
            }
            throw new RestException(Status.CONFLICT.getStatusCode(), message);            
        }
        return Response.status(Status.OK).build();
    }
}
