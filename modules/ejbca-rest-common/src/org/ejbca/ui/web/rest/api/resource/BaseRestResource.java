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

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.util.HttpTools;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Validator;
import javax.ws.rs.core.Response;
import java.security.cert.X509Certificate;

/**
 * Base class for common methods used across all REST resources.
 */
public abstract class BaseRestResource {

    private static volatile Validator validator = null;
    private static Object mutex = new Object();

    private static final String RESOURCE_STATUS = "OK";
    public static final String RESOURCE_VERSION = "1.0";
    private static final String CONFIG_DUMP = "v1/configdump";
    private static final String CRYPTO_TOKEN = "v1/cryptotoken";

    // Some status codes (including 422) are missing from the JAX-RS Response.Status enum
    protected static final int HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY = 422;

    /**
     * Returns the status information of this resource as JSON.
     *
     * @return response as JSON.
     */
    public Response status() {
        return Response.ok(RestResourceStatusRestResponse.builder()
                .status(RESOURCE_STATUS)
                .version(RESOURCE_VERSION)
                .revision(GlobalConfiguration.EJBCA_VERSION)
                .build()
        ).build();
    }

    /**
     * Returns an AuthenticationToken for the requesting administrator based on the SSL client certificate
     *
     * @param requestContext HTTP context
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @return AuthenticationToken for the requesting administrator
     * @throws AuthorizationDeniedException
     */
    protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) throws AuthorizationDeniedException, RestException {
        if (requestContext == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Missing request context");
        }

        final X509Certificate[] certificates = (X509Certificate[]) requestContext.getAttribute("javax.servlet.request.X509Certificate");
        final X509Certificate certificate = certificates != null ? certificates[0] : null;
        final String oauthBearerToken = HttpTools.extractBearerAuthorization(requestContext.getHeader(HttpTools.AUTHORIZATION_HEADER));

        if (certificate == null && StringUtils.isEmpty(oauthBearerToken)) {
            throw new AuthorizationDeniedException("Error no client certificate or OAuth token received for authentication.");
        }
        if (requestContext.getRequestURI().toLowerCase().contains(CONFIG_DUMP) || requestContext.getRequestURI().toLowerCase().contains(CRYPTO_TOKEN)) {
            return new EjbLocalHelper().getEjbcaRestHelperSession().getAdmin(allowNonAdmins, certificate, oauthBearerToken, true);
        }

        return new EjbLocalHelper().getEjbcaRestHelperSession().getAdmin(allowNonAdmins, certificate, oauthBearerToken, false);
    }

}
