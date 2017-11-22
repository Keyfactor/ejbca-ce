/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Functional domain service interface (should be implemented by separate domain service class, 
 * but is used temporarily to solve cyclic package dependency at compile time).
 * 
 * @version $Id: CertificateValidationDomainService.java 26390 2017-11-14 15:20:58Z anjakobs $
 *
 */
public interface CertificateValidationDomainService {

    /**
     * Validates a generated certificate during issuance.
     * 
     * @param authenticationToken the authentication token of the administrator performing the action.
     * @param ca the issuing CA
     * @param endEntityInformation the end entity object
     * @param certificate the certificate to validate
     * @throws ValidationException if the validation failed. If the validation failed action is set to abort certificate issuance {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE} and validation fails, message is NOT null. Exception of any technical errors are stored in the cause, and message is null.
     */
    void validateCertificate(final AuthenticationToken authenticationToken, final CA ca, final EndEntityInformation endEntityInformation,
            final X509Certificate certificate) throws ValidationException, IllegalValidityException;
}
