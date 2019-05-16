/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling CA management related requests.
 *
 * @version $Id$
 */
@Api(tags = {"v1/ca_management"}, value = "CA Management API")
@Path("/v1/ca_management")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CaManagementRestResource extends BaseRestResource {

    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    
    @EJB
    private CAAdminSessionLocal caAdminSession;
    
    @EJB
    private CaSessionLocal caSession;
    
    private static final Logger log = Logger.getLogger(CaManagementRestResource.class);

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", 
                  notes = "Returns status, API version and EJBCA version.",  
                  response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }
    
    @PUT
    @Path("/{ca_name}/activate")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Activate a CA",
        notes = "Activates CA with given name",
        code = 200)
    public Response activate(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the CA to activate")
            @PathParam("ca_name") String caName) throws AuthorizationDeniedException, RestException, ApprovalException, CADoesntExistsException, WaitingForApprovalException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        
        final CAInfo caInfo = caSession.getCAInfo(admin, caName);
        if (caInfo == null) {
            String message = "Unknown CA name";
            log.info(message);
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), message);
        }
        
        try {
            caAdminSession.activateCAService(admin, caInfo.getCAId());
        } catch (Exception e) {
            String message = e.getMessage();
            log.info(message);
            throw new RestException(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, message);
        }
        
        return Response.status(Status.OK).build();
    }
    
    @PUT
    @Path("/{ca_name}/deactivate")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Deactivate a CA",
        notes = "Deactivates CA with given name",
        code = 200)
    public Response deactivate(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the CA to deactivate")
            @PathParam("ca_name") String caName) throws AuthorizationDeniedException, RestException, ApprovalException, CADoesntExistsException, WaitingForApprovalException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        
        final CAInfo caInfo = caSession.getCAInfo(admin, caName);
        if (caInfo == null) {
            String message = "Unknown CA name";
            log.info(message);
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), message);
        }
        
        try {
            caAdminSession.deactivateCAService(admin, caInfo.getCAId());
        } catch (Exception e) {
            String message = e.getMessage();
            log.info(message);
            throw new RestException(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, message);
        }
        
        return Response.status(Status.OK).build();
    }
}
