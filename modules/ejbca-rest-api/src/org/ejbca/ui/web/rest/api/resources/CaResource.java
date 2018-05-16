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

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.RaAuthorizationResult;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.converters.CaInfoConverter;
import org.ejbca.ui.web.rest.api.types.CaInfoTypes;
import org.ejbca.ui.web.rest.api.types.EndpointStatusType;
import org.ejbca.ui.web.rest.common.BaseRestResource;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

// TODO Javadoc
/**
 * JAX-RS resource handling CA related requests.
 *
 * @version $Id$
 */
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
public class CaResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(CaResource.class);
    private final CaInfoConverter caInfoConverter;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    public CaResource() {
        caInfoConverter = new CaInfoConverter();
    }

    @GET
    @Path("/status")
    public Response status() {
        return Response.ok(EndpointStatusType.builder()
                .status("OK")
                .version("1.0")
                .revision("ALPHA")
                .build()
        ).build();
    }

    /**
     * @param subjectDn CA subjectDn
     * @return PEM file with CA certifictes
     */
    @GET
    @Path("/{subject_dn}/certificate/download")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getCertificateAsPem(@PathParam("subject_dn") String subjectDn) {
        subjectDn = CertTools.stringToBCDNString(subjectDn);
        try {
            Collection<Certificate> certificateChain = raMasterApiProxyBean.getCertificateChain(subjectDn.hashCode());
            try {
                byte[] bytes = CertTools.getPemFromCertificateChain(certificateChain);
                return Response.ok(bytes)
                        .header("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(subjectDn + ".cacert.pem") + "\"")
                        .build();
            } catch (CertificateEncodingException e) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
            }
        } catch (Exception e) {
            log.error("Error getting CA certificates: ", e);
            return Response.status(Response.Status.NOT_FOUND).entity("Error getting CA certificates.").build();
        }
    }

    @GET
    public Response listCas() {
        final CaInfoTypes caInfoTypes = CaInfoTypes.builder()
                .certificateAuthorities(caInfoConverter.toTypes(caSession.findAll()))
                .build();
        return Response.ok(caInfoTypes).build();
    }

    /**
     * TODO Mainly used for auth testing. Keep this anyway (under some other base url)?
     *
     * @param requestContext Context
     * @return granted access for the requesting administrator
     */
    @GET
    @Path("/get-authorization")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorization(@Context HttpServletRequest requestContext) {
        if (requestContext == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing request context").build();
        }
        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            final RaAuthorizationResult authResult = raMasterApiProxyBean.getAuthorization(admin);
            final Map<String, Boolean> authResultSorted = new TreeMap<String, Boolean>(authResult.getAccessRules());
            return Response.ok(authResultSorted).build();
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (AuthenticationFailedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        }
    }
}
