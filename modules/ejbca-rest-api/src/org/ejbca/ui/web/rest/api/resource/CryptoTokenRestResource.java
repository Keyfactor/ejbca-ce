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
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.CryptoTokenActivationRestRequest;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling Crypto Token related requests.
 *
 * @version $Id$
 */
@Api(tags = {"v1/cryptotoken"}, value = "Crypto Token REST Management API")
@Path("/v1/cryptotoken")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CryptoTokenRestResource extends BaseRestResource {

    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    
    private static final Logger log = Logger.getLogger(CryptoTokenRestResource.class);

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", 
                  notes = "Returns status and version of the resource.", 
                  response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }
    
    @PUT
    @Path("/{cryptotoken_name}/activate")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Activate a Crypto Token",
        notes = "Activates Crypto Token given name and activation code",
        code = 200)
    public Response activate(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the token to activate")
            @PathParam("cryptotoken_name") String cryptoTokenName,
            @ApiParam (value="activation code") CryptoTokenActivationRestRequest request) throws AuthorizationDeniedException, RestException, CryptoTokenOfflineException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        final char[] activationCode = request.getActivationCode().toCharArray();
        final Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (cryptoTokenId == null) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Unknown crypto token");
        }
        try {
            cryptoTokenManagementSession.activate(admin, cryptoTokenId, activationCode);
        } catch (CryptoTokenOfflineException e) {
            log.info("Activation of CryptoToken '" + cryptoTokenName + "' (" + cryptoTokenId +
                    ") by administrator " + admin.toString() + " failed. Device was unavailable.");
            throw e;
        } catch (CryptoTokenAuthenticationFailedException e) {
            log.info("Activation of CryptoToken '" + cryptoTokenName + "' (" + cryptoTokenId +
                    ") by administrator " + admin.toString() + " failed. Authentication code was not correct.");
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Invalid activation code");
        }
        
        return Response.status(Status.OK).build();
    }

}
