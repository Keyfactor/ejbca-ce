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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.protocol.CertificateRenewalException;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;

import com.keyfactor.util.EJBTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 A plug-in to provide SCEP renewal capabilities using client certificate authentication (as per the SCEP RFC (and earlier drafts).
 
 To enable SCEP renewal, the following are required:
   1. The SCEP configuration must allow 'Allow Client Certificate Renewal'
   2. The End-Entity must be associated with an End Entity Profile that enables 'Allow renewal before expiration'. Also, ensure the
      'Days before expiration' is set to an appropriate number (the SCEP RFC suggests 50% of certificate validity).
      
 Upon an incoming SCEP renewal, the plug-in will perform a validation of the Signer's certificate before allowing the request. 
 This validation must meet all these criteria:
   1. Certificate is provided in the request.
   2. Certificate is not expired or pending.
   3. Certificate was previously issued to the end-entity identified in the request. By inference, this suggests that the certificate 
      was issued by a trusted authority as the certificate was found in the EJBCA's database. Please note that the Signer's certificate
      could have been issued by a different CA to that which will perform the renewal.
   4. Certificate is not revoked.
      
 SCEP renewals using a previously issued key may be permitted by the SCEP configuration with the parameter 'Allow Client Certificate Renewal 
 using old key'. However, be aware that if the CA setting 'Enforce key renewal' is enabled, then this will prevent the certificate being
 issued.
  
 During SCEP processing (for initial certificate or for renewals), the User's password will be reset to a random value. This will invalidate
 the Challenge Password previously known to the Client. This is the recommendation in the RFC (and earlier drafts).  
          
**/

public class ClientCertificateRenewalExtension implements ScepResponsePlugin, ScepMessageDispatcherSession {

    private static final Logger log = Logger.getLogger(ClientCertificateRenewalExtension.class);
    
    /**
     * Internal localization of logs and errors
     */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    
    

    @Override
    public ResponseMessage performOperation(AuthenticationToken authenticationToken, ScepRequestMessage reqmsg, ScepConfiguration scepConfig,
            String alias)
            throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, IllegalKeyException,
            SignatureException, CustomCertificateSerialNumberException, SignRequestException, SignRequestSignatureException, AuthStatusException,
            AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException, CertificateRenewalException {
        
        if (log.isDebugEnabled()) {
            log.debug("SCEP plug-in activated for alias="+alias+" with MessageType="+reqmsg.getMessageType());
        }
        
        // Get EJBs dynamically as this plug-in is loaded at run-time. need a helper for this.
        final EjbLocalHelper localHelper = new EjbLocalHelper();
        final SignSessionLocal signSession = localHelper.getSignSession();
        
        // The SCEP plug-in will be invoked for the initial certificate enrolment, or for automatic renewals. Different processing is 
        // required for these.
 
        try {

            // Ensure SCEP requests are decrypted and verified. This verification is just the PKCS10 data, not the PKCSS7 outer envelope.
            signSession.decryptAndVerifyRequest(authenticationToken, reqmsg);
            
            log.info("Processing SCEP request. Username provided in request:"+reqmsg.getUsername());
            
            // Check the PKCS7 signature, just to make sure it hasn't been tampered.
            final java.security.cert.X509Certificate certSigner = (X509Certificate)reqmsg.getSignerCert();
            if (certSigner == null) {
                throw new SignRequestException("Aborting SCEP request. The PKCS7 Signer's certificate was not provided.");
            }

            try {
                if ( !(reqmsg).verifySignature( certSigner.getPublicKey() ) ) {
                    throw new SignRequestException( "Aborting SCEP request. The PKCS7 signature does not verify." );
                }
            } catch (CMSException | OperatorCreationException e) {
                log.error("Caught exception while verifing the PKCS7 in the SCEP request: ", e);
               throw new SignRequestException( "Aborting SCEP request. The PKCS7 signature does not verify." );
            }

            // Check if SCEP request is an initial enrolment or a renewal. The test for this is to check if the PKCS10 signer certificate is 
            //  self-signed or not. 
            if ( isSelfSigned(certSigner)) {
                
                // Looks like an initial enrolment request.
                // Lets pass back to the SignSessionBean to process the initial certificate request
                final ResponseMessage response = signSession.createCertificate(authenticationToken, reqmsg, ScepResponseMessage.class, null);
                
                // If successful, reset the User's password to ensure one-time use.
                if (response.getStatus().equals( ResponseStatus.SUCCESS)) {
                    
                    // Create a random password
                    final String newPassword = new AllPrintableCharPasswordGenerator().getNewPassword(15, 20);
                    
                    // Update the EE information via the Management Session.
                    final EndEntityManagementSessionLocal endEntityManagementSession = localHelper.getEndEntityManagementSession();
                    try {
                        endEntityManagementSession.setPassword(authenticationToken, reqmsg.getUsername(), newPassword);
                    } catch ( AuthorizationDeniedException | EndEntityProfileValidationException e) {
                        // Can't really do much about this as the certificate has been issued. Just leave a warning in the log.
                        log.warn("Caught exception while resetting password of the EE: "+reqmsg.getUsername()+" Details: "+ e.getMessage());
                    }
                }
                return response;
                
            } else {

                // Looks like a renewal with certificate authentication...
                if (log.isDebugEnabled()) {
                    log.debug("SCEP renewal request. PKCS10 Signing certificate:"+certSigner.toString() );   
                }

                // Check the request has a Username.  
                if (reqmsg.getUsername() == null) {
                    String msg = intres.getLocalizedMessage("signsession.nouserinrequest", reqmsg.getRequestDN());
                    throw new NoSuchEndEntityException(msg);
                }
                
                //
                // SCEP renewal requests need to pass a bunch of authentication, certificate and configuration checks  
                //

                if (log.isDebugEnabled()) {
                    log.debug("Checking if Signing cert within the SCEP renewal request belongs to the User and meets other validity criteria.");  
                }

                // Get the EE details
                final EndEntityAccessSessionLocal endEntityAccessSession = localHelper.getEndEntityAccessSession();  
                final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser( reqmsg.getUsername());
                if ( endEntityInformation == null) {
                    // Couldn't find the User referenced in the request.
                    throw new NoSuchEndEntityException("Aborting SCEP renewal: The Username in the request is not known: "+ reqmsg.getUsername());
                }

                // The EE should have status of "GENERATED" in order to perform a SCEP renewal. Any other status will cause an abort (ie., NEW, REVOKED, etc)).
                if ( endEntityInformation.getStatus() != EndEntityConstants.STATUS_GENERATED ) {
                    throw new CertificateRenewalException("Aborting SCEP renewal: The current User status is preventing renewals.");
                }
 

                // Get CA that will be used to fulfil the certificate request. Check some settings that affect SCEP renewals.
                final CA ca = signSession.getCAFromRequest(authenticationToken, reqmsg, false);
                if (!ca.isUseCertificateStorage()) {
                    log.error("Aborting SCEP renewal. CA does not support 'Use Certificate Storage'. CA="+ca.getName());;
                    throw new CertificateRenewalException("Aborting SCEP renewal: Not supported by CA.");
                }

                // SCEP can only work if we have CA configured for 'Use User Storage'
                if ( !ca.isUseUserStorage()) {
                    log.error("Aborting SCEP request as the CA does not support 'Use User Storage'. CA="+ca.getName());;
                    throw new CertificateRenewalException("Aborting SCEP renewal: Not supported by CA.");
                }
               
                
                // Check the validity of the signer's certificate. Will perform revocation check later.
                try {
                    certSigner.checkValidity();
                } catch (java.security.cert.CertificateExpiredException | java.security.cert.CertificateNotYetValidException e) {
                    throw new SignRequestException("Aborting SCEP renewal: Signer's certificate is not valid at this time.");
                } 

                // Check the User is associated with the Signer's certificate. This can be done by retrieving all the User's certs
                // and then confirming the Signer's cert is one of these. There is an inference here that any existing cert for
                // the User is acceptable, even if that cert was issued by a different CA or difference certificate policy.
                
                // Need to get all the User's certificates.
                final CertificateStoreSessionLocal certificateStoreSession = localHelper.getCertificateStoreSession();
                final java.util.Collection<Certificate> userCertificates = EJBTools
                        .unwrapCertCollection(certificateStoreSession.findCertificatesByUsername( reqmsg.getUsername() ));

                // Loop through to find any matches within the collection of User certificates.
                // While performing this check, we can also identify if the public key in the PKCS10 has been used previously by this User.
                boolean isSignerCertIssuedToUser = false;
                boolean isRequestPublicKeyInUse = false;
                
                if (userCertificates != null) {
                    for (Certificate certificate : userCertificates) {
                        if (  certificate.equals( certSigner) ) {
                            isSignerCertIssuedToUser = true;
                            if (log.isDebugEnabled()) {
                                log.debug("SCEP signer's certificate is associated with the User: "+reqmsg.getUsername() );
                            }
                        }
                        if ( certificate.getPublicKey().equals( reqmsg.getRequestPublicKey())) {
                            isRequestPublicKeyInUse = true;
                            if (log.isDebugEnabled()) {
                                log.debug("Public key in SCEP request has been used previously by the User: "+reqmsg.getUsername() );
                            }
                       }
                   }
                }
                
                // Abort if the signing certificate is not associated with the User.
                if (!isSignerCertIssuedToUser) {
                    throw new SignRequestException("Aborting SCEP renewal: Signer's certificate is not associated with the User: "+reqmsg.getUsername());
                }
                         

                // Check if the request is supplying an old public key.  
                // This may not be permitted by the SCEP configuration or the CA configuration.
                if ( isRequestPublicKeyInUse ) {
                    // Check the SCEP configuration
                    if ( !scepConfig.getAllowClientCertificateRenewalWithOldKey(alias)) {
                        log.error("Aborting SCEP renewal as SCEP configuration does not support reuse of old keys. SCEP Alias="+alias);;
                        throw new CertificateRenewalException("Aborting SCEP renewal: Not supported by CA.");
                    }
                    // If the CA setting 'Enforce key renewals' is going to reject the request, we can catch the problem now and fail-out.
                    if ( ca.isDoEnforceKeyRenewal()) {
                        log.error("Aborting SCEP renewal as CA configuration has enabled 'Enforce Key Renewal'. CA="+ca.getName());
                        throw new CertificateRenewalException("Aborting SCEP renewal: Not supported by CA.");
                    }
               }

                
                // Is the Signing cert revoked?
                // This will throw an exception if cert is revoked ,but also if the IssuerDN is unknown by EJBCA.
                if ( certificateStoreSession.getStatus( certSigner.getIssuerDN().toString(), certSigner.getSerialNumber()).isRevoked() ) {
                    throw new SignRequestException( "Aborting SCEP renewal: Signer's certificate is revoked. Serial (hex)="+certSigner.getSerialNumber().toString(16) 
                                                  + " IssuerDN="+certSigner.getIssuerDN().toString());
                }
                
                
                //
                // Our checks are now complete, and now we can start the issuance for the requested certificate.
                // Will set End-entity with a new random password and will need to set this password in the SCEP request.
                // We can then pass to SignSessionBean for further processing.

               // Create a random password
                final String newPassword = new AllPrintableCharPasswordGenerator().getNewPassword(15, 20);

                // Set the password in the request
                reqmsg.setPassword( newPassword);
                
                // Update the EE information via the Management Session.
                final EndEntityManagementSessionLocal endEntityManagementSession = localHelper.getEndEntityManagementSession();
                try {
                    endEntityManagementSession.setPassword(authenticationToken, reqmsg.getUsername(), newPassword);
                } catch ( AuthorizationDeniedException | EndEntityProfileValidationException e) {
                    log.error("Caught exception while resetting password of the EE: "+reqmsg.getUsername()+" Details: "+ e.getMessage());
                    throw new CertificateRenewalException("Aborting SCEP renewal: Internal error.");
                }


                // Pass the SCEP renewal request for normal processing which could identify other issues, or be successful.
                final ResponseMessage response = signSession.createCertificate(authenticationToken, reqmsg, ScepResponseMessage.class, null);

                // Return the response message as nothing further to do.
                return response;
            }
            
        // Catch our exceptions to ensure an appropriate FAIL response is given to SCEP client. The ScepServlet handles most exceptions with a
        // FAIL response or a HTML error code.
        // Note: The failure text is not actually sent, but if this is to change, then ensure only minimal non-sensitive information is returned to clients.
        
        // The SCEP standard has limited error codes; BadAlg(0), BadMessageCheck(1), BadRequest(2), BadTime(3), badCertID(4) 
        // Will only use two of these error codes.
        } catch ( CertificateRenewalException  e) {
            log.error("Catching "+e.getClass().getSimpleName() +": "+ e.getMessage());
           return signSession.createRequestFailedResponse(authenticationToken, reqmsg, ScepResponseMessage.class, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (SignRequestException  e) {
            log.error("Catching "+e.getClass().getSimpleName() +": "+ e.getMessage());
            return signSession.createRequestFailedResponse(authenticationToken, reqmsg, ScepResponseMessage.class, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
        }              
    }



    
    // Additional support functions for SCEP renewals

    // Check if a certificate is self-signed. This check is performed cryptographically
    // rather than simply checking the Subject DN and the Issuer DN.
   public static boolean isSelfSigned(X509Certificate cert) throws SignRequestException { 
       try {
           // Try to verify certificate signature with its own public key
           PublicKey key = cert.getPublicKey();
           cert.verify(key);
           return true;
       } catch (SignatureException sigEx) {
           // Invalid signature --> not self-signed
           return false;
       } catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException ex) {
           // Fail out...
           log.error("Could not complete the self-sign check on the certificate. Details: "+ex.getMessage()); 
           throw new SignRequestException("Aborting SCEP renewal: Could not verify the signing certificate.");
       }
   }

   
   
}
