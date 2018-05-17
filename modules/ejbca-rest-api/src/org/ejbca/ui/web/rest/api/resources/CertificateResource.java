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

package org.ejbca.ui.web.rest.api.resources;

import java.math.BigInteger;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.crl.RevocationReasons;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.ui.web.protocol.DateNotValidException;
import org.ejbca.ui.web.rest.api.types.RevocationResultType;
import org.ejbca.ui.web.rest.common.BaseRestResource;

/**
 * JAX-RS resource handling certificate-related requests.
 * @version $Id$
 *
 */
@Path("v1/certificate")
@Stateless
public class CertificateResource extends BaseRestResource {
    
    private static final String VERSION = "1";
    
    private static final Logger log = Logger.getLogger(CertificateResource.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    
    
    /**
     * Revokes the specified certificate
     * @param requestContext HttpServletRequest
     * @param issuerDN of the certificate to revoke
     * @param serialNumber decimal serial number
     * @param reason revocation reason. 
     * @see org.cesecore.certificates.crl.RevocationReasons
     * @param date revocation date (optional). Must be valid ISO8601 date string
     * @return JSON representation of serialNr, revocation status, date and optional message
     */
    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @PathParam("issuer_dn") String issuerDN,
            @PathParam("certificate_serial_number") String serialNumber,
            @QueryParam("reason") String reason,
            @QueryParam("date") String date) {
        Date revocationDate = null;
        final BigInteger serianNr = new BigInteger(serialNumber);
        RevocationResultType result = new RevocationResultType(serianNr, RevocationResultType.STATUS_REVOKED);
        RevocationReasons reasons = RevocationReasons.getFromCliValue(reason);
        if (reasons == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid revocation reason").build();
        }
        final int revocationReason = reasons.getDatabaseValue();
        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            if (date != null) {
                revocationDate = getValidatedRevocationDate(date);
                result.setDate(revocationDate);
            } else {
                result.setDate(new Date());
            }
            raMasterApiProxyBean.revokeCert(admin, serianNr, revocationDate, issuerDN, revocationReason, false);
            result.setMessage("Successfully revoked");
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (AlreadyRevokedException e) {
            result.setStatus(RevocationResultType.STATUS_ALREADYREVOKED);
            result.setMessage("Certificate has already been revoked");
        } catch (WaitingForApprovalException e) {
            result.setStatus(RevocationResultType.STATUS_WAITINGFORAPPROVAL);
            result.setMessage("Operation is awaiting approval by another administrator");
        } catch (NoSuchEndEntityException | ApprovalException | RevokeBackDateNotAllowedForProfileException | CADoesntExistsException | DateNotValidException e) {
            result.setStatus(RevocationResultType.STATUS_ERROR);
            result.setMessage(e.getMessage());
        } 
        // TODO Response codes will be handled properly with ECA-6937, ECA-6938.
        return Response.ok(result).build();
    }
    
    private Date getValidatedRevocationDate(String sDate) throws DateNotValidException {
        Date date = null;
        if (sDate != null) {
            try {
                date = DatatypeConverter.parseDateTime(sDate).getTime();
            } catch (IllegalArgumentException e) {
                throw new DateNotValidException(intres.getLocalizedMessage("ra.bad.date", sDate));
            }
            if (date.after(new Date())) {
                throw new DateNotValidException("Revocation date in the future: '" + sDate + "'.");
            }
        }
        return date;
    }
    
    @GET
    @Path("/version")
    @Produces("text/html")
    public String version() {
        return VERSION;
    }
}

