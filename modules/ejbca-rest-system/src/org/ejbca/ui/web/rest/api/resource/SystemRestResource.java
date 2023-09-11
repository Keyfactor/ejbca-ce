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
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RunServiceRestResponse;

/**
 * JAX-RS resource handling System related requests.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)

public class SystemRestResource extends BaseRestResource {
    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;
    @EJB
    private ServiceSessionLocal serviceSession;
    private static final Logger log = Logger.getLogger(SystemRestResource.class);

    public Response runServiceWorker(
            final HttpServletRequest requestContext,
            final String serviceName) throws AuthorizationDeniedException, RestException{
        final Integer id = serviceSession.getServiceId(serviceName);
        if (id == 0) {
            String exception = "The following service could not be found: " + serviceName;
            log.info(exception);
            throw new RestException(Status.NOT_FOUND.getStatusCode(),  exception);
        }
        serviceSession.runService(id);

        return Response.ok(RunServiceRestResponse.builder()
                .message("Running service: " + serviceName)
                .build()
                ).build();
    }
}
