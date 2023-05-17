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

package org.ejbca.core.ejb.rest;

import java.security.cert.X509Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;

@Local
public interface EjbcaRestHelperSessionLocal extends EjbcaRestHelperSession {

    /**
     * Gets an AuthenticationToken object authenticated with the given X509 certificate or OAuth token. If both provided,
     * X509 certificate will be used.
     *
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @param cert X509 certificate
     * @param oauthBearerToken OAuth token for JWT authentication
     * @param allowNoActiveCA true if having a an active (local) CA should not be a requirement. Useful for allowing some requests to be performed before a local CA is set up.
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins = false and the certificate does not belong to an administrator
     */
    AuthenticationToken getAdmin(boolean allowNonAdmins, X509Certificate cert, String oauthBearerToken, boolean allowNoActiveCa) throws AuthorizationDeniedException;

    /**
     * Compose EndEntityInformation object based on EnrollPkcs10CertificateRequest input
     * @param authenticationToken of the requesting administrator
     * @param enrollcertificateRequest input data object for enrolling a certificate
     */
    public EndEntityInformation convertToEndEntityInformation(AuthenticationToken authenticationToken, EnrollPkcs10CertificateRequest enrollcertificateRequest)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException, EjbcaException, CertificateProfileDoesNotExistException, CADoesntExistsException;
}
