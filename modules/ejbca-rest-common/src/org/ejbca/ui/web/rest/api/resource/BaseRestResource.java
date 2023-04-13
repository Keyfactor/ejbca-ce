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

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.util.HttpTools;

/**
 * Base class for common methods used across all REST resources.
 */
public abstract class BaseRestResource {

    private static volatile Validator validator = null;
    private static Object mutex = new Object();

    private static final String RESOURCE_STATUS = "OK";
    public static final String RESOURCE_VERSION = "1.0";
    
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

        return new EjbLocalHelper().getEjbcaRestHelperSession().getAdmin(allowNonAdmins, certificate, oauthBearerToken);
    }

    // TODO ECA-7119 Due to limited validation exception handling support in JAX-RS 1.1, we validate the object programmatically to handle the response properly.
    // TODO ECA-7119 Within JAX-RS 2.0, configure the error handler to support a ValidationException and use @Valid annotation for input parameters
    /**
     * This method triggers the validation over input object and throws RestException in case of validation violation.
     *
     * @param object the object for validation.
     * @throws RestException in case of constraint violation.
     */
    protected void validateObject(final Object object) throws RestException {
        
        final Set<ConstraintViolation<Object>> constraintViolations = getValidator().validate(object);
        if(!constraintViolations.isEmpty()) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), constraintViolations.iterator().next().getMessage());
        }
    }
    
    private static Validator getValidator() {
        if (validator == null) {
            synchronized (mutex) {
                if (validator == null) { // check again inside synchronized block to avoid race condition
                    validator = Validation.buildDefaultValidatorFactory().getValidator();
                }
            }
        }
        return validator;
    }

}
