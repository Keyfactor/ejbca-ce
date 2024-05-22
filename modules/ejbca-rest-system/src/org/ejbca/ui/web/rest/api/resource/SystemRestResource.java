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
 
 
package org.ejbca.ui.web.rest.api.resource;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

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
