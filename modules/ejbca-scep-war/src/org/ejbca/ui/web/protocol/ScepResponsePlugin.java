/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.protocol;

import java.security.SignatureException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.protocol.scep.ScepRequestMessage;

/**
 * Plugin class for SCEP plugins which expect a ResponseMessage in reply
 * 
 * @version $Id$
 *
 */

public interface ScepResponsePlugin {

    /**
     * 
     * TODO: Generalize exception handling for this interface method when the need arises.
     * 
     * @param authenticationToken an authentication token with access to the relevant CA, end entities and to create certificates
     * @param reqmsg the SCEP request message
     * @param scepConfig a copy of the SCEP configuration 
     * @param alias the particular SCEP configuration alias to check out
     * @return
     * @throws NoSuchEndEntityException if the username specified in the request doesn't exist for any end entity
     * @throws CADoesntExistsException if the CA specified in the request doesn't exist
     * @throws AuthorizationDeniedException if the authentication token lacks access
     * @throws CryptoTokenOfflineException if the CA's crypto token is unavailable
     * @throws IllegalKeyException if reuse of old keys is prohibited in the configuration, and this request was found to be doing so
     * @throws SignatureException if the PKCS#10 was not signed using the previous certificate
     * @throws CustomCertificateSerialNumberException if a custom serial number was requested for the certificate, but it was invalid
     * @throws SignRequestException if the request message lacks username and/or password
     * @throws SignRequestSignatureException  if the PKCS#7 request was badly signed
     * @throws AuthStatusException if the status of the end entity was not valid for this operation
     * @throws AuthLoginException if the password in the request was incorrect
     * @throws IllegalNameException if the requested username was invalid
     * @throws CertificateCreateException if certificate creation failed
     * @throws CertificateRevokeException if the certificate was menant to be issued revoked but could not be set so
     * @throws CertificateSerialNumberException if a certificate with the same SubjectDN and key already exist, and a limitation is set that prohibits this
     * @throws IllegalValidityException if the validity defined in the request wasn't valid
     * @throws CAOfflineException if the CA was offline
     * @throws InvalidAlgorithmException f the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CertificateExtensionException if there was an error with the extensions specified in the request message
     * @throws ClientCertificateRenewalException if the last issued certificate hasn't passed half its validity date, or if it wasn't possible to change status for the end entity
     */
    public abstract ResponseMessage performOperation(AuthenticationToken authenticationToken, ScepRequestMessage reqmsg,
            ScepConfiguration scepConfig, String alias) throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException,
            CryptoTokenOfflineException, IllegalKeyException, SignatureException, CustomCertificateSerialNumberException, SignRequestException,
            SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException,
            CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CertificateExtensionException, ClientCertificateRenewalException;

}