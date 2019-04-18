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

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.ws.rs.core.Response;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

/**
 * Base class for common methods used across all REST resources.
 *
 * @version $Id$
 */
public abstract class BaseRestResource {

    private static volatile Validator validator = null;
    private static Object mutex = new Object();

    private static final String RESOURCE_STATUS = "OK";
    private static final String RESOURCE_VERSION = "1.0";
    private static final String RESOURCE_REVISION = "ALPHA";

    /**
     * Returns the status information of this resource as Json.
     *
     * @return response as Json.
     */
    public Response status() {
        return Response.ok(RestResourceStatusRestResponse.builder()
                .status(RESOURCE_STATUS)
                .version(RESOURCE_VERSION)
                .revision(RESOURCE_REVISION)
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
        X509Certificate[] certs = (X509Certificate[]) requestContext.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null || certs[0] == null) {
            throw new AuthorizationDeniedException("Error no client certificate received for authentication.");
        }
        return new EjbLocalHelper().getEjbcaRestHelperSession().getAdmin(allowNonAdmins, certs[0]);
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
