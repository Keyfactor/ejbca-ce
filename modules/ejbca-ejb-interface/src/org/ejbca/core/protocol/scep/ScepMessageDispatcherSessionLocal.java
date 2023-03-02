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

package org.ejbca.core.protocol.scep;

import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.ejb.Local;

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
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.ScepResponseInfo;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

@Local
public interface ScepMessageDispatcherSessionLocal extends ScepMessageDispatcherSession {

    /**
     * Handles received SCEP message. 
     * 
     * @param authenticationToken the origin of the request
     * @param operation desired SCEP operation to perform
     * @param message to dispatch
     * @param scepConfigurationAlias name of alias containing SCEP configuration
     * @return byte array containing dispatch response. Content depends on operation
     * @throws NoSuchAliasException 
     * @throws CertificateEncodingException 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws CertificateRenewalException 
     * @throws CertificateExtensionException 
     * @throws CertificateException 
     * @throws SignatureException 
     * @throws InvalidAlgorithmException 
     * @throws CAOfflineException 
     * @throws IllegalValidityException 
     * @throws CertificateSerialNumberException 
     * @throws CertificateRevokeException 
     * @throws CertificateCreateException 
     * @throws IllegalNameException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws IllegalKeyException 
     * @throws CryptoTokenOfflineException 
     * @throws CustomCertificateSerialNumberException 
     * @throws NoSuchEndEntityException 
     */
    byte[] dispatchRequest(AuthenticationToken authenticationToken, String operation, String message, String scepConfigurationAlias) throws NoSuchAliasException, 
        CertificateEncodingException, CADoesntExistsException, AuthorizationDeniedException, NoSuchEndEntityException, CustomCertificateSerialNumberException, 
        CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, 
        CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, 
        SignatureException, CertificateException, CertificateExtensionException, CertificateRenewalException;
    
    
    /**
     * Verifies the MS Intune challenge token in the CSR.
     *  
     * @param authenticationToken the origin of the request
     * @param alias name of alias containing SCEP configuration
     * @param message to dispatch
     * @return true if the CSR verification was successful.
     * @throws CertificateCreateException if the CSR verification fails.
     */
    boolean doMsIntuneCsrVerification(final AuthenticationToken authenticationToken, final String alias, final byte[] message) throws CertificateCreateException;
    
    /**
     * Updates MS Intune with the results of a SCEP issuance
     * 
     * @param administrator the origin of the request
     * @param transactionId ID of the original request
     * @param dispatchResponse the SCEP response.  Null if an error occurred
     * @throws CertificateCreateException An error occurred when updating Intune
     */
    void doMsIntuneCompleteRequest(AuthenticationToken administrator, String transactionId, String alias, ScepResponseInfo dispatchResponse) throws CertificateCreateException;
    
    /**
     * Verifies and decrypts the SCEP PKCS10 message CSR with the crypto token of the 
     * CA defined in the SCEP alias.
     * 
     * @param authenticationToken the origin of the request
     * @param alias name of alias containing SCEP configuration
     * @param message to parse
     * @return the DER encoded CSR or null.
     * @throws CertificateCreateException if the message could not be parsed or verified. 
     */
    public byte[] verifyRequestMessage(final AuthenticationToken authenticationToken, final String alias, final byte[] message) throws CertificateCreateException;

    /**
     * Handles received SCEP message initiated by an Intune client.
     * 
     * @param authenticationToken the origin of the request
     * @param operation desired SCEP operation to perform
     * @param message to dispatch
     * @param scepConfigurationAlias name of alias containing SCEP configuration
     * @return byte array containing dispatch response. Content depends on operation
     * @throws NoSuchAliasException 
     * @throws CertificateEncodingException 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws CertificateRenewalException 
     * @throws CertificateExtensionException 
     * @throws CertificateException 
     * @throws SignatureException 
     * @throws InvalidAlgorithmException 
     * @throws CAOfflineException 
     * @throws IllegalValidityException 
     * @throws CertificateSerialNumberException 
     * @throws CertificateRevokeException 
     * @throws CertificateCreateException 
     * @throws IllegalNameException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws IllegalKeyException 
     * @throws CryptoTokenOfflineException 
     * @throws CustomCertificateSerialNumberException 
     * @throws NoSuchEndEntityException 
     */
    ScepResponseInfo dispatchRequestIntune(AuthenticationToken authenticationToken, String operation, String message, String scepConfigurationAlias) throws NoSuchAliasException, 
        CertificateEncodingException, CADoesntExistsException, AuthorizationDeniedException, NoSuchEndEntityException, CustomCertificateSerialNumberException, 
        CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, 
        CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, 
        SignatureException, CertificateException, CertificateExtensionException, CertificateRenewalException;
}
