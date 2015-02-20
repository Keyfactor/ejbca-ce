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
package org.ejbca.core.ejb.ca.sign;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.Local;
import javax.ejb.ObjectNotFoundException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

/**
 * Local interface for RSASignSession.
 */
@Local
public interface SignSessionLocal extends SignSession {
    /**
     * Returns a CA that a request is targeted for. Uses different methods in priority order to try to find it.
     * 
     * @param admin an authenticating token
     * @param req the request
     * @param doLog if this operation should log in the audit log.
     * @return CA object
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    CA getCAFromRequest(AuthenticationToken admin, RequestMessage req, boolean doLog) throws CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Requests for a certificate to be created for the passed public key with default key usage
     * The method queries the user database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     */
    Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk) throws ObjectNotFoundException,
            CADoesntExistsException, AuthorizationDeniedException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException;
    
    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *                 CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                 from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                 keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                 digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                 | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @return The newly created certificate or null.
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     *             
     */
    Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore,
            Date notAfter) throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException,
            AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException;
    
    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage and using the given certificate profile. This method is primarily intended to be used when
     * issuing hardtokens having multiple certificates per user.
     * The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin                Information about the administrator or admin performing the event.
     * @param username             unique username within the instance.
     * @param password             password for the user.
     * @param pk                   the public key to be put in the created certificate.
     * @param keyusage             integer with bit mask describing desired keys usage, overrides keyUsage from
     *                             CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                             from org.bouncycastle.jce.X509KeyUsage. -1 means use default keyUsage from CertificateProfile. ex. int
     *                             keyusage = X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation; gives
     *                             digitalSignature and nonRepudiation. ex. int keyusage = X509KeyUsage.keyCertSign
     *                             | X509KeyUsage.cRLSign; gives keyCertSign and cRLSign
     * @param notBefore an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @param certificateprofileid used to override the one set in userdata.
     *                             Should be set to CertificateProfileConstants.CERTPROFILE_NO_PROFILE if the usedata certificateprofileid should be used
     * @param caid                 used to override the one set in userdata.
     *                             Should be set to SecConst.CAID_USEUSERDEFINED if the regular certificateprofileid should be used
     * 
     * 
     * @return The newly created certificate or null.
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * 
     */
     Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore,
            Date notAfter, int certificateprofileid, int caid) throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException,
            AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException;


}
