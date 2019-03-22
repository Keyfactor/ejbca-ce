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
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Functional domain service interface (should be implemented by separate domain service class, 
 * but is used temporarily to solve cyclic package dependency at compile time).
 * 
 * @version $Id$
 *
 */
public interface CertificateValidationDomainService {

    /**
     * Validates a generated certificate during issuance.
     * 
     * @param authenticationToken the authentication token of the administrator performing the action.
     * @param phase the certificate issuance life cycle phase ({@link IssuancePhase}.
     * @param ca the issuing CA
     * @param endEntityInformation the end entity object
     * @param certificate the certificate to validate
     * @throws ValidationException if the validation failed. If the validation failed action is set to abort certificate issuance 
     * {@link KeyValidationFailedActions#ABORT_CERTIFICATE_ISSUANCE} and validation fails, message is NOT null. Exception of any technical errors are
     *  stored in the cause, and message is null.
     */
    void validateCertificate(final AuthenticationToken authenticationToken, final IssuancePhase phase, final CA ca,
            final EndEntityInformation endEntityInformation, final X509Certificate certificate) throws ValidationException;

    /** Method that checks if validation will be performed in the specified phase. Can be used to exclude operations 
     * (such as signing a certificate) if we know no validation will happen in this phase
     * @param phase the certificate issuance life cycle phase ({@link IssuancePhase}.
     * @param ca the issuing CA, which is configured with validators
     * @return true if some validator will run in the phase
     */
    boolean willValidateInPhase(IssuancePhase phase, CA ca);
}
