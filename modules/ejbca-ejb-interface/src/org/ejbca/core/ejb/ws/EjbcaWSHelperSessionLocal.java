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
package org.ejbca.core.ejb.ws;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.TreeMap;

import javax.ejb.Local;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.query.Query;

/**
 * Local interface for EjbcaWSHelperSession. These methods are used from EjbcaWS only
 * @version $Id$
 */
@Local
public interface EjbcaWSHelperSessionLocal extends EjbcaWSHelperSession {

    /**
     * Gets an AuthenticationToken object for a WS-API administrator authenticated with the given client certificate.
     * - Checks (through authenticationSession.authenticate) that the certificate is valid
     * - If (WebConfiguration.getRequireAdminCertificateInDatabase) checks (through authenticationSession.authenticate) that the admin certificate is not revoked.
     * - If (allowNonAdmin == false), checks that the admin have access to /administrator, i.e. really is an administrator with the certificate mapped in an admin role. 
     *   Does not check any other authorization though, other than that it is an administrator.
     * 
     * @param cert The X.509 client certificate.
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins == false and the cert does not belong to an admin
     */
    AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert) throws AuthorizationDeniedException;
    
    /**
     * Method that converts profile names etc to corresponding ID's
     * @param admin
     * @param usermatch a usermatch containing names of profiles
     * @return a query containing id's of profiles.
     * @throws NumberFormatException
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws EndEntityProfileNotFoundException if usermatch was for and end entity profile, and that profile didn't exist
     */
    Query convertUserMatch(AuthenticationToken admin, UserMatch usermatch) throws CADoesntExistsException,
        AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /**
     * Checks authorization for each certificate and optionally check that it's valid. Does not check revocation status. 
     * @param admin is the admin used for authorization
     * @param certs is the collection of certs to verify
     * @param validate set to true to perform validation of each certificate
     * @param nowMillis current time
     * @return a List of valid and authorized certificates
     */
    List<Certificate> returnAuthorizedCertificates(final AuthenticationToken admin, Collection<java.security.cert.Certificate> certs, boolean validate, long nowMillis);

    boolean checkValidityAndSetUserPassword(AuthenticationToken admin, java.security.cert.Certificate cert, String username, String password) 
            throws ServiceLocatorException, CertificateNotYetValidException, CertificateExpiredException, EndEntityProfileValidationException,
            AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException;

    void resetUserPasswordAndStatus(AuthenticationToken admin, String username, int status);
    
    /**
     * @throws CryptoTokenAuthenticationFailedException 
     * @throws CryptoTokenOfflineException 
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
     */
    byte[] caRenewCertRequest(AuthenticationToken admin, String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) 
        throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * @throws AuthorizationDeniedException
     * @throws CAExistsException
     * @throws CertificateImportException
     * @throws EjbcaException
     * @throws CertificateParsingException
     * @throws IllegalCryptoTokenException
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#importCaCert
     */
    void importCaCert(AuthenticationToken admin, String caname, byte[] certbytes) throws AuthorizationDeniedException, 
        CAExistsException, IllegalCryptoTokenException, CertificateImportException, EjbcaException, CertificateParsingException;
    
    /**
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws CertificateImportException
     * @throws EjbcaException
     * @throws CertificateParsingException
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#updateCaCert
     */
     void updateCaCert(AuthenticationToken admin, String caname, byte[] certbytes) throws AuthorizationDeniedException, 
         CADoesntExistsException, CertificateImportException, EjbcaException, CertificateParsingException; 

     /** Makes a CA certificate that has been created prior to its "not before" date active (CA rollover) */
     void rolloverCACert(AuthenticationToken admin, String caname) throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException;
     
     /**
      * @throws AuthorizationDeniedException
      * @throws EjbcaException
      * @throws ApprovalException
      * @throws WaitingForApprovalException
      * @throws CertPathValidatorException
      * @throws CesecoreException
      * @throws CertificateParsingException 
      * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
      */
     void caCertResponse(AuthenticationToken admin, String caname, byte[] cert, List<byte[]> cachain, String keystorepwd, boolean futureRollover) 
         throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException, CesecoreException, CertificateParsingException;

     void isAuthorizedToHardTokenData(AuthenticationToken admin, String username, boolean viewPUKData) throws AuthorizationDeniedException, EjbcaException;

     /**
      * Help method returning a subset of certificates containing only valid certificates
      * expiredate and revocation status is checked.
      * @throws ClassCastException 
      */
     Collection<java.security.cert.Certificate> returnOnlyValidCertificates(AuthenticationToken admin, Collection<java.security.cert.Certificate> certs);
     
     /**
      * Method used to convert a HardToken data to a WS version
      * @param data
      * @throws EjbcaException 
      */
     HardTokenDataWS convertHardTokenToWS(HardTokenInformation data, Collection<java.security.cert.Certificate> certificates, boolean includePUK) throws EjbcaException;
     
     void isAuthorizedToRepublish(AuthenticationToken admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException;
     
     /**
      * Web services does not support Collection type so convert it to array.
      * 
      * @param mytree TreeMap of name and id pairs to convert to an array
      * @return array of NameAndId objects
      */
     NameAndId[] convertTreeMapToArray(TreeMap<String, Integer> mytree);
}
