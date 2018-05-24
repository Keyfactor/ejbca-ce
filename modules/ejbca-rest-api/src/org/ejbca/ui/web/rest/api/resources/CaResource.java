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

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;

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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.types.response.CaInfoTypes;
import org.ejbca.ui.web.rest.common.BaseRestResource;

/**
 * JAX-RS resource handling CA related requests.
 *
 * @version $Id$
 */
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
public class CaResource extends BaseRestResource {
    //private static final Logger log = Logger.getLogger(CaResource.class);

    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    public CaResource() {
    }

    @GET
    @Path("/status")
    @Override
    public Response status() {
        return super.status();
    }

    /**
     * @param subjectDn CA subjectDn
     * @return PEM file with CA certificates
     */
    @GET
    @Path("/{subject_dn}/certificate/download")
    @Produces(MediaType.WILDCARD)
    public Response getCertificateAsPem(@Context HttpServletRequest requestContext,
                                        @PathParam("subject_dn") String subjectDn) throws AuthorizationDeniedException, CertificateEncodingException {
        if (requestContext == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing request context").build();
        }
        final AuthenticationToken admin = getAdmin(requestContext, false);
        subjectDn = CertTools.stringToBCDNString(subjectDn);
        Collection<Certificate> certificateChain = raMasterApiProxy.getCertificateChain(admin, subjectDn.hashCode());

        byte[] bytes = CertTools.getPemFromCertificateChain(certificateChain);
        return Response.ok(bytes)
                .header("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(subjectDn + ".cacert.pem") + "\"")
                .header("Content-Length", bytes.length)
                .build();
    }

    /**
     * Returns the Response containing the list of CAs with general information per CA as Json.
     *
     * @param httpServletRequest HttpServletRequest of a request.
     *
     * @return The response containing the list of CAs and its general information.
     */
    @GET
    public Response listCas(@Context final HttpServletRequest httpServletRequest) throws Exception {
        final AuthenticationToken adminToken = getAdmin(httpServletRequest, false);
        final CaInfoTypes caInfoTypes = CaInfoTypes.builder()
                .certificateAuthorities(CaInfoTypes.converter().toTypes(raMasterApiProxy.getAuthorizedCAInfos(adminToken)))
                .build();
        return Response.ok(caInfoTypes).build();
    }

}
