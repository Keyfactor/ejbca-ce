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

import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaEndEntitySearchRequest;
import org.ejbca.core.model.era.RaEndEntitySearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.AddEndEntityRestRequest;
import org.ejbca.ui.web.rest.api.io.request.EndEntityRevocationRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchEndEntitiesRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SetEndEntityStatusRestRequest;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchEndEntitiesRestResponse;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling End Entity related requests.
 */
@Path("/v1/endentity")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EndEntityRestResource extends BaseRestResource {

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;
    private static final Logger log = Logger.getLogger(EndEntityRestResource.class);

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", 
                  notes = "Returns status, API version and EJBCA version.",  
                  response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }
    
    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Add new end entity, if it does not exist",
        notes = "Register new end entity based on provided registration data",
        code = 200)
    public Response add(
            @Context HttpServletRequest requestContext,
            @ApiParam (value="request") AddEndEntityRestRequest request) throws AuthorizationDeniedException, RestException, EjbcaException, WaitingForApprovalException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        validateObject(request);

        Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
        Map<Integer, String> availableCertificateProfiles = new HashMap<>();
        Map<Integer, String> availableCAs = new HashMap<>();
        availableEndEntityProfiles = loadAuthorizedEndEntityProfiles(admin, availableEndEntityProfiles);
        availableCertificateProfiles = loadAuthorizedCertificateProfiles(admin, availableCertificateProfiles);
        availableCAs = loadAuthorizedCAs(admin, availableCAs);
        
        final Integer endEntityProfileId = getKeyFromMapByValue(availableEndEntityProfiles, request.getEndEntityProfileName());
        if(endEntityProfileId == null) {
            throw new RestException(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid request, unknown end entity profile."
            );
        }
        final Integer certificateProfileId = getKeyFromMapByValue(availableCertificateProfiles, request.getCertificateProfileName());
        if(certificateProfileId == null) {
            throw new RestException(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid request, unknown certificate profile."
            );
        }
        final Integer caId = getKeyFromMapByValue(availableCAs, request.getCaName());
        if(caId == null) {
            throw new RestException(
                    Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid request, unknown CA."
            );
        }
        
        EndEntityInformation endEntityInformation = AddEndEntityRestRequest.converter().toEntity(request, caId, endEntityProfileId, certificateProfileId);
        
        try {
        	raMasterApiProxy.addUser(admin, endEntityInformation, false);
        } catch (EjbcaException e) {
            int errorStatusCode = Response.Status.BAD_REQUEST.getStatusCode();
        	ErrorCode errorCode = EjbcaException.getErrorCode(e);
            if (errorCode != null) {
                if (errorCode.equals(ErrorCode.USER_ALREADY_EXISTS)) {
                    log.info("Client " + admin + " failed to add end entity since the username " + endEntityInformation.getUsername() + " already exists");
                    errorStatusCode = Response.Status.CONFLICT.getStatusCode();
                } else if (errorCode.equals(ErrorCode.LOGIN_ERROR)) {
                    log.info("End entity " + endEntityInformation.getUsername() + " could not be added: " + e.getMessage() + ", " + errorCode);
                } else {
                    log.info("Exception adding end entity. Error Code: " + errorCode, e);
                }
            } else {
                log.info("End entity " + endEntityInformation.getUsername() + " could not be added: " + e.getMessage());
            }
            // Throw a REST Exception on order to produce a good error for the client
            throw new RestException(
                    errorStatusCode,
                    e.getMessage()
            );
		} catch (WaitingForApprovalException e) {
			log.info(admin + " is not authorized to execute this operation without approval", e);
            // Throw a REST Exception on order to produce a good error for the client
            throw new RestException(
                    Response.Status.ACCEPTED.getStatusCode(),
                    e.getMessage()
            );
		}

        
        return Response.status(Status.OK).build();
    }
    
    @PUT
    @Path("/{endentity_name}/revoke")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Revokes all end entity certificates",
        notes = "Revokes all certificates associated with given end entity name with specified reason code (see RFC 5280 Section 5.3.1), and optionally deletes the end entity",
        code = 200)
    public Response revoke(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the end entity")
            @PathParam("endentity_name") String endEntityName,
            @ApiParam (value="request") EndEntityRevocationRestRequest request) throws AuthorizationDeniedException, RestException, CryptoTokenOfflineException, CADoesntExistsException, ApprovalException, AlreadyRevokedException, WaitingForApprovalException, CouldNotRemoveEndEntityException, EjbcaException, NoSuchEndEntityException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        validateObject(request);
        final int reasonCode = request.getReasonCode();
        final boolean delete = request.isDelete();

        try {
			raMasterApiProxy.revokeUser(admin, endEntityName, reasonCode, delete);
		} catch (NoSuchEndEntityException e) {
			log.info("Revocation of end entity '" + endEntityName + "' by administrator " + admin.toString() +
					" failed. End entity does not exist.");
            throw e;
		}
        
        return Response.status(Status.OK).build();
    }
    
    @POST
    @Path("/{endentity_name}/setstatus")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Edits end entity setting new status",
        notes = "Edit status, password and token type of related end entity",
        code = 200)
    public Response setstatus(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the end entity to edit status for")
            @PathParam("endentity_name") String endEntityName,
            @ApiParam (value="request") SetEndEntityStatusRestRequest request) throws AuthorizationDeniedException, RestException, NoSuchEndEntityException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, CustomFieldException, EndEntityProfileValidationException, WaitingForApprovalException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        validateObject(request);

        EndEntityInformation endEntityInformation = raMasterApiProxy.searchUser(admin, endEntityName);
        if (endEntityInformation == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find end entity for the username '" + endEntityName + "'");
            }
            throw new NoSuchEndEntityException("Could not find  End Entity for the username='" + endEntityName + "'");
        } else {
            final String status = request.getStatus();
            final String token = request.getToken();
            if (log.isDebugEnabled()) {
                log.debug("Setting status for username='" + endEntityName + "', " + status + ", " + token);
            }
        	endEntityInformation.setStatus(SetEndEntityStatusRestRequest.EndEntityStatus.resolveEndEntityStatusByName(status).getStatusValue());
        	endEntityInformation.setTokenType(SetEndEntityStatusRestRequest.TokenType.resolveEndEntityTokenByName(token).getTokenValue());
        	if (request.getPassword() != null) {
        		endEntityInformation.setPassword(request.getPassword());
        	}
        	boolean result = raMasterApiProxy.editUser(admin, endEntityInformation, false, null);
        	if (result) {
        		log.info("End entity '" + endEntityName + "' successfully edited by administrator " + admin.toString());
            } else {
            	log.info("Error during end entity '" + endEntityName + "' edit by administrator " + admin.toString() +
            			" . Edit operation failed");
            	return Response.status(Status.NOT_MODIFIED).build();
            }
        }
        return Response.status(Status.OK).build();
    }
    
    @DELETE
    @Path("/{endentity_name}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Deletes end entity",
        notes = "Deletes specified end entity and keeps certificate information untouched, if end entity does not exist success is still returned",
        code = 200)
    public Response delete(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the end entity")
            @PathParam("endentity_name") String endEntityName) throws AuthorizationDeniedException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        
        raMasterApiProxy.deleteUser(admin, endEntityName);
        
        return Response.status(Status.OK).build();
    }
    
    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Searches for end entity confirming given criteria.",
            notes = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchEndEntityCriteriaRestRequest model.",
            response = SearchEndEntitiesRestResponse.class
    )
    public Response search(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Maximum number of results and collection of search criterias.") final SearchEndEntitiesRestRequest searchEndEntitiesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException {
        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);
        validateObject(searchEndEntitiesRestRequest);
        authorizeSearchEndEntitiesRestRequestReferences(authenticationToken, searchEndEntitiesRestRequest);
        final SearchEndEntitiesRestResponse searchEndEntitiesRestResponse = searchEndEntities(authenticationToken, searchEndEntitiesRestRequest);
        return Response.ok(searchEndEntitiesRestResponse).build();
    }
    
    /*
    **
    * Authorizes the input search request for proper access references (End entity profile ids, Certificate profile ids and CA ids) inside a request.
    *
    * @param authenticationToken authentication token to use.
    * @param searchEndEntitiesRestRequest input search request.
    * @throws RestException In case of inaccessible reference usage.
    */
   private void authorizeSearchEndEntitiesRestRequestReferences(
           final AuthenticationToken authenticationToken,
           final SearchEndEntitiesRestRequest searchEndEntitiesRestRequest
   ) throws RestException {
       Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
       Map<Integer, String> availableCertificateProfiles = new HashMap<>();
       Map<Integer, String> availableCAs = new HashMap<>();
       for(SearchEndEntityCriteriaRestRequest searchEndEntityCriteriaRestRequest : searchEndEntitiesRestRequest.getCriteria()) {
           final SearchEndEntityCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchEndEntityCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchEndEntityCriteriaRestRequest.getProperty());
           if(criteriaProperty == null) {
               throw new RestException(
                       Response.Status.BAD_REQUEST.getStatusCode(),
                       "Invalid search criteria content."
               );
           }
           switch (criteriaProperty) {
               case END_ENTITY_PROFILE:
                   availableEndEntityProfiles = loadAuthorizedEndEntityProfiles(authenticationToken, availableEndEntityProfiles);
                   final String criteriaEndEntityProfileName = searchEndEntityCriteriaRestRequest.getValue();
                   final Integer criteriaEndEntityProfileId = getKeyFromMapByValue(availableEndEntityProfiles, criteriaEndEntityProfileName);
                   if(criteriaEndEntityProfileId == null) {
                       throw new RestException(
                               Response.Status.BAD_REQUEST.getStatusCode(),
                               "Invalid search criteria content, unknown end entity profile."
                       );
                   }
                   searchEndEntityCriteriaRestRequest.setIdentifier(criteriaEndEntityProfileId);
                   break;
               case CERTIFICATE_PROFILE:
                   availableCertificateProfiles = loadAuthorizedCertificateProfiles(authenticationToken, availableCertificateProfiles);
                   final String criteriaCertificateProfileName = searchEndEntityCriteriaRestRequest.getValue();
                   final Integer criteriaCertificateProfileId = getKeyFromMapByValue(availableCertificateProfiles, criteriaCertificateProfileName);
                   if(criteriaCertificateProfileId == null) {
                       throw new RestException(
                               Response.Status.BAD_REQUEST.getStatusCode(),
                               "Invalid search criteria content, unknown certificate profile."
                       );
                   }
                   searchEndEntityCriteriaRestRequest.setIdentifier(criteriaCertificateProfileId);
                   break;
               case CA:
                   availableCAs = loadAuthorizedCAs(authenticationToken, availableCAs);
                   final String criteriaCAName = searchEndEntityCriteriaRestRequest.getValue();
                   final Integer criteriaCAId = getKeyFromMapByValue(availableCAs, criteriaCAName);
                   if(criteriaCAId == null) {
                       throw new RestException(
                               Response.Status.BAD_REQUEST.getStatusCode(),
                               "Invalid search criteria content, unknown CA."
                       );
                   }
                   searchEndEntityCriteriaRestRequest.setIdentifier(criteriaCAId);
                   break;
               default:
                   // Do nothing
           }
       }
   }
   
   /**
    * Searches for end entities within given criteria.
    *
    * @param authenticationToken authentication token to use.
    * @param searchEndEntitiesRestRequest search criteria.
    * @return Search results.
    * @throws RestException In case of malformed criteria.
    */
   private SearchEndEntitiesRestResponse searchEndEntities(
           final AuthenticationToken authenticationToken,
           final SearchEndEntitiesRestRequest searchEndEntitiesRestRequest
   ) throws RestException {
       final RaEndEntitySearchRequest raEndEntitySearchRequest = SearchEndEntitiesRestRequest.converter().toEntity(searchEndEntitiesRestRequest);
       final RaEndEntitySearchResponse raEndEntitySearchResponse = raMasterApiProxy.searchForEndEntities(authenticationToken, raEndEntitySearchRequest);
       return SearchEndEntitiesRestResponse.converter().toRestResponse(raEndEntitySearchResponse);
   }

   private Map<Integer, String> loadAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableEndEntityProfiles) {
       if(availableEndEntityProfiles.isEmpty()) {
           return raMasterApiProxy.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken);
       }
       return availableEndEntityProfiles;
   }

   private Map<Integer, String> loadAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableCertificateProfiles) {
       if(availableCertificateProfiles.isEmpty()) {
           return raMasterApiProxy.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken);
       }
       return availableCertificateProfiles;
   }

   private Map<Integer, String> loadAuthorizedCAs(final AuthenticationToken authenticationToken, final Map<Integer, String> availableCAs) {
       if(availableCAs.isEmpty()) {
           final Map<Integer, String> authorizedCAIds = new HashMap<>();
           final List<CAInfo> caInfosList = raMasterApiProxy.getAuthorizedCas(authenticationToken);
           for(final CAInfo caInfo : caInfosList) {
               authorizedCAIds.put(caInfo.getCAId(), caInfo.getName());
           }
           return authorizedCAIds;
       }
       return availableCAs;
   }

   private Integer getKeyFromMapByValue(final Map<Integer, String> map, final String value) {
       for(Integer key : map.keySet()) {
           if(map.get(key).equals(value)) {
               return key;
           }
       }
       return null;
   }

}
