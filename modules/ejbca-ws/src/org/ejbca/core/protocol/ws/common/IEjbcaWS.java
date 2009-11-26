/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ws.common;

import java.rmi.RemoteException;
import java.security.cert.CertificateExpiredException;
import java.util.List;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.query.IllegalQueryException;

/**
 * Interface the the EJBCA RA WebService. Contains the following methods:
 * 
 * editUser    : Edits/adds  userdata
 * findUser    : Retrieves the userdata for a given user.
 * findCerts   : Retrieves the certificates generated for a user.
 * getLastCertChain : retrieves the latest full certificate chain issued for the user
 * pkcs10Req   : Generates a certificate using the given userdata and the public key from the PKCS10
 * pkcs12Req   : Generates a PKCS12 keystore (with the private key) using the given userdata
 * crmfRequest : Generates a certificate using the given userdata and the public key from the CRMF
 * spkacRequest : Generates a certificate using the given userdata and the public key from the SPKAC (netscape)
 * cvcRequest : Generates a certificate using the given userdata and the public key from the CVC (EAC ePassports)
 * revokeCert  : Revokes the given certificate.
 * revokeUser  : Revokes all certificates for a given user, it's also possible to delete the user.
 * revokeToken : Revokes all certificates placed on a given hard token
 * checkRevokationStatus : Checks the revocation status of a certificate.
 * isAuthorized : Checks if an admin is authorized to an resource
 * fetchUserData : Method used to fetch userdata from an existing UserDataSource
 * genTokenCertificates : Method used to add information about a generated hardtoken
 * existsHardToken : Looks up if a serial number already have been generated
 * getHardTokenData : Method fetching information about a hard token given it's hard token serial number.
 * getHardTokenDatas: Method fetching all hard token informations for a given user.
 * republishCertificate : Method performing a republication of a selected certificate
 * isApproved : Looks up if a requested action have been approved by an authorized administrator or not
 * customLog  : Logs a CUSTOM_LOG event to the logging system
 * deleteUserDataFromSource : Method used to remove user data from a user data source
 * getCertificate : Returns a certificate given its issuer and serial number
 * getAvailableCAs() : 
 * getAuthorizedEndEntityProfiles() : 
 * getAvailableCertificateProfiles : 
 * getAvailableCAsInProfile : 
 * 
 * 
 * Observe: All methods have to be called using client authenticated https
 * otherwise will a AuthorizationDenied Exception be thrown.
 * 
 * @author Philip Vendil
 * $Id$
 */
public interface IEjbcaWS {
	
	public static final int CUSTOMLOG_LEVEL_INFO  = 1;
	public static final int CUSTOMLOG_LEVEL_ERROR = 2;

	/**
	 * Method that should be used to edit/add a user to the EJBCA database,
	 * if the user doesn't already exists it will be added otherwise it will be
	 * overwritten.
	 * 
	 * Observe: if the user doesn't already exists, it's status will always be set to 'New'.
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/<end entity profile of user>/create_end_entity and/or edit_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param userdata contains all the information about the user about to be added.
	 * @param clearPwd indicates it the password should be stored in cleartext, required
	 * when creating server generated keystores.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws EjbcaException
	 */
	public abstract void editUser(UserDataVOWS userdata)
			throws CADoesntExistsException, AuthorizationDeniedException,
			UserDoesntFullfillEndEntityProfile, EjbcaException,
			ApprovalException, WaitingForApprovalException;

	/**
	 * Retrieves information about a user in the database.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of matching users>/view_end_entity
	 * - /ca/<ca of matching users>
	 * 
	 * @param username, the unique username to search for
	 * @return a array of UserDataVOWS objects (Max 100) containing the information about the user or null if user doesn't exists.
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws IllegalQueryException if query isn't valid
	 * @throws EjbcaException 
	 */

	public abstract List<UserDataVOWS> findUser(UserMatch usermatch)
			throws AuthorizationDeniedException, IllegalQueryException,
			EjbcaException;

	/**
	 * Retrieves a collection of certificates generated for a user.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param username a unique username 
	 * @param onlyValid only return valid certs not revoked or expired ones.
	 * @return a collection of X509Certificates or null if no certificates could be found
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws EjbcaException 
	 */

	public abstract List<Certificate> findCerts(String username,
			boolean onlyValid) throws AuthorizationDeniedException,
			NotFoundException, EjbcaException;

	/**
	 * Retrieves a the latest certificate issued to the user, together woth the CA certificates so the whole certificate chain is returned.
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param username a unique username 
	 * @return a collection of X509Certificates or null if no certificates could be found with user certificate in pos 0, SubCA in 1, RootCA in 2 etc
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws EjbcaException 
	 */

	public abstract List<Certificate> getLastCertChain(String username) 
	throws AuthorizationDeniedException, NotFoundException, EjbcaException;
	
	/** Generate a certificate for a user, works the same as pkcs10Request
	 * 
	 * @see #pkcs10Request(String, String, String, String, String)
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param crmf the CRMF request message (only the public key is used.)
	 * @param responseType indicating which type of answer that should be returned, on of the CertificateHelper.RESPONSETYPE_ parameters.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 */
	public abstract CertificateResponse crmfRequest(String username, String password,
			String crmf, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException;

	/** Generate a certificate for a user, works the same as pkcs10Request
	 * 
	 * @see #pkcs10Request(String, String, String, String, String)
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param spkac the SPKAC (netscape) request message (only the public key is used.)
	 * @param responseType indicating which type of answer that should be returned, on of the CertificateHelper.RESPONSETYPE_ parameters.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 */
	public abstract CertificateResponse spkacRequest(String username, String password,
			String spkac, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException;

	/** Generate a CV certificate for a user, uses the same authorizations as editUser and pkcs10Request
	 * responseType is always CertificateHelper.RESPONSETYPE_CERTIFICATE.
	 * 
	 * @see #editUser
	 * @see #pkcs10Request
	 * @param username the user name of the user requesting the certificate.
	 * @param password the password for initial enrollment, not used for renewal requests that can be authenticated using signatures with keys with valid certificates.
	 * @param cvcreq Base64 encoded CVC request message.
	 * @return the full certificate chain for the IS, with IS certificate in pos 0, DV in 1, CVCA in 2.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if administrator is not authorized to edit end entity or if an authenticated request can not be verified
	 * @throws SignRequestException if the provided request is invalid, for example not containing a username or password 
	 */
	public List<Certificate> cvcRequest(String username, String password, String cvcreq)
	throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException,
	EjbcaException, ApprovalException, WaitingForApprovalException, SignRequestException, CertificateExpiredException;
	
	/**
	 * Method to use to generate a certificate for a user. The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add non-existing users.
	 * 
	 * Observe, the user must first have added/set the status to new with edituser command
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/view_end_entity
	 * - /ca_functionality/create_certificate
	 * - /ca/<ca of user>
	 * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param pkcs10 the PKCS10 (only the public key is used.)
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a tokens
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param responseType indicating which type of answer that should be returned, on of the CertificateHelper.RESPONSETYPE_ parameters.
	 * @return the generated certificate, in either just X509Certificate or PKCS7 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 */
	public abstract CertificateResponse pkcs10Request(String username, String password,
			String pkcs10, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException;

	/**
	 * Method to use to generate a server generated keystore. The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add non-existing users and
	 * the users token should be set to SecConst.TOKEN_SOFT_P12.
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/view_end_entity
	 * - /ca_functionality/create_certificate
	 * - /ca/<ca of user>
	 * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a tokens
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param keyspec that the generated key should have, examples are 1024 for RSA or prime192v1 for ECDSA.
	 * @param keyalg that the generated key should have, RSA, ECDSA. Use one of the constants in CATokenConstants.org.ejbca.core.model.ca.catoken.KEYALGORITHM_XX.
	 * @return the generated keystore
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 */

	public abstract KeyStore pkcs12Req(String username, String password,
			String hardTokenSN, String keyspec, String keyalg)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException;

	/**
	 * Method used to revoke a certificate.
	 * 
	 * * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user owning the cert>/revoke_end_entity
	 * - /ca/<ca of certificate>
	 * 
	 * @param issuerDN of the certificate to revoke
	 * @param certificateSN of the certificate to revoke
	 * @param reason for revocation, one of RevokedCertInfo.REVOKATION_REASON_ constants, 
	 * or use RevokedCertInfo.NOT_REVOKED to un-revoke a certificate on hold.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if certificate doesn't exist
	 * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved
	 * @throws ApprovalException There already exists an approval request for this task
	 * @throws AlreadyRevokedException The certificate was already revoked
	 */

	public abstract void revokeCert(String issuerDN, String certificateSN,
			int reason) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException, ApprovalException, WaitingForApprovalException,
			AlreadyRevokedException;

	/**
	 * Method used to revoke all a users certificates. It is also possible to delete
	 * a user after all certificates have been revoked.
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/revoke_end_entity
	 * - /ca/<ca of users certificate>
	 * 
	 * @param username unique username i EJBCA
	 * @param reasonfor revokation, one of RevokedCertInfo.REVOKATION_REASON_ constants
	 * or use RevokedCertInfo.NOT_REVOKED to un-revoke a certificate on hold.
	 * @param deleteUser deletes the users after all the certificates have been revoked.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if user doesn't exist
	 * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved
	 * @throws ApprovalException if there already exists an approval request for this task
	 * @throws AlreadyRevokedException if the user already was revoked
	 */
	public abstract void revokeUser(String username, int reason,
			boolean deleteUser) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException, AlreadyRevokedException;

	/**
	 * Method used to mark the users latest certificate for key recovery
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/keyrecovery
	 * - /endentityprofilesrules/<end entity profile of the user>/keyrecovery
	 * - /ca/<ca of users certificate>
	 * 
	 * @param username unique username i EJBCA
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if user doesn't exist
	 * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved
	 * @throws ApprovalException if there already exists an approval request for this task
	 * @throws EjbcaException if there is a configuration or other error
	 */
	public abstract void keyRecoverNewest(String username) throws
			CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException;
	
	/**
	 * Method used to revoke all certificates mapped to one hardtoken.
	 *
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user owning the token>/revoke_end_entity
	 * - /ca/<ca of certificates on token>
	 * 
	 * @param hardTokenSN of the hardTokenSN
	 * @param reasonfor revocation, one of RevokedCertInfo.REVOKATION_REASON_ constants
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if token doesn't exist
	 * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved
	 * @throws ApprovalException There already exists an approval request for this task
	 * @throws AlreadyRevokedException The token was already revoked.
	 */

	public abstract void revokeToken(String hardTokenSN, int reason)
			throws CADoesntExistsException, RemoteException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException, AlreadyRevokedException;

	/**
	 * Method returning the revocation status for given user
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ca/<ca of certificate>
	 * 
	 * @param issuerDN 
	 * @param certificateSN a hexa decimal string
	 * @return the revocation status or null i certificate doesn't exists.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @see org.ejbca.core.protocol.ws.RevokeStatus
	 */

	public abstract RevokeStatus checkRevokationStatus(String issuerDN,
			String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException,
			EjbcaException;

	/**
	 * Method checking if a user is authorized to a given resource
	 * 
	 * Authorization requirements: a valid client certificate
	 * 
	 * @param resource the access rule to test
	 * @return true if the user is authorized to the resource otherwise false.
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @see org.ejbca.core.protocol.ws.RevokeStatus
	 */
	public abstract boolean isAuthorized(String resource) throws EjbcaException;

	/**
	 * Method used to fetch userdata from an existing UserDataSource.
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /userdatasourcesrules/<user data source>/fetch_userdata (for all the given user data sources)
	 * - /ca/<all cas defined in all the user data sources>
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * 
	 * @param userDataSourceNames a List of User Data Source Names
	 * @param searchString to identify the userdata.
	 * @return a List of UserDataSourceVOWS of the data in the specified UserDataSources, if no user data is found will an empty list be returned. 
	 * @throws UserDataSourceException if an error occurred connecting to one of 
	 * UserDataSources.
	 */
	public abstract List<UserDataSourceVOWS> fetchUserData(
			List<String> userDataSourceNames, String searchString)
			throws UserDataSourceException, EjbcaException, AuthorizationDeniedException;

	/**
	 * Method used to add information about a generated hardtoken
	 * 
	 * Authorization requirements:
	 * If the caller is an administrator
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/<end entity profile of user>/create_end_entity and/or edit_end_entity
     * - /ra_functionality/revoke_end_entity (if overwrite flag is set)
     * - /endentityprofilesrules/<end entity profile of user>/revoke_end_entity (if overwrite flag is set)
	 * - /ca_functionality/create_certificate
	 * - /ca/<ca of all requested certificates>
	 * - /hardtoken_functionality/issue_hardtokens
	 * 
	 * If the user isn't an administrator will it be added to the queue for approval.
	 * 
	 * @param userData of the user that should be generated
	 * @param tokenRequests a list of certificate requests
	 * @param hardTokenData data containing PIN/PUK info
	 * @param hardTokenSN Serial number of the generated hard token.
	 * @param overwriteExistingSN if the the current hardtoken should be overwritten instead of throwing HardTokenExists exception.
	 * If a card is overwritten, all previous certificates on the card is revoked.
	 * @param revocePreviousCards tells the service to revoke old cards issued to this user. If the present card have the label TEMPORARY_CARD
	 * old cards is set to CERTIFICATE_ONHOLD otherwise UNSPECIFIED.
	 * @return a List of the generated certificates. 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the administrator isn't authorized.
	 * @throws WaitingForApprovalException if the caller is a non-admin a must be approved before it is executed.
	 * @throws HardTokenExistsException if the given hardtoken serial number already exists.
	 * @throws ApprovalRequestExpiredException if the request for approval have expired.
	 * @throws ApprovalException  if error happened with the approval mechanisms
	 * @throws WaitingForApprovalException if the request haven't been processed yet. 
	 * @throws ApprovalRequestExecutionException if the approval request was rejected 
	 */

	public abstract List<TokenCertificateResponseWS> genTokenCertificates(
			UserDataVOWS userData,
			List<TokenCertificateRequestWS> tokenRequests,
			HardTokenDataWS hardTokenData,
			boolean overwriteExistingSN,
			boolean revocePreviousCards) throws CADoesntExistsException, AuthorizationDeniedException,
			WaitingForApprovalException, HardTokenExistsException,
			UserDoesntFullfillEndEntityProfile, ApprovalException,
			EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException;

	/**
	 * Looks up if a serial number already have been generated
	 * 
	 * Authorization requirements: A valid certificate
	 * 
	 * @param hardTokenSN the serial number of the token to look for.
	 * @return true if hard token exists
	 * @throws EjbcaException if error occurred server side
	 */
	public abstract boolean existsHardToken(String hardTokenSN)
			throws EjbcaException;

	/**
	 * Method fetching information about a hard token given it's hard token serial number.
	 * 
	 * If the caller is an administrator
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_hardtoken
	 * - /endentityprofilesrules/<end entity profile of user>/view_hardtoken
	 * - /endentityprofilesrules/<end entity profile of user>/view_hardtoken/puk_data (if viewPUKData = true)
	 * - /ca/<ca of user>
	 * 
	 * If the user isn't an administrator will it be added to the queue for approval.
	 * 
	 * @param hardTokenSN of the token to look for.
	 * @param viewPUKData if PUK data of the hard token should be returned.
	 * @param boolean onlyValidCertificates of all revoked and expired certificates should be filtered.
	 * @return the HardTokenData
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws HardTokenDoesntExistsException if the hardtokensn don't exist in database.
	 * @throws EjbcaException if an exception occurred on server side.
	 * @throws ApprovalRequestExpiredException if the request for approval have expired.
	 * @throws ApprovalException  if error happened with the approval mechanisms
	 * @throws WaitingForApprovalException if the request haven't been processed yet. 
	 * @throws ApprovalRequestExecutionException if the approval request was rejected 
	 */
	public abstract HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
			throws CADoesntExistsException, AuthorizationDeniedException,
			HardTokenDoesntExistsException, EjbcaException, ApprovalException, ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException;

	/**
	 * Method fetching all hard token informations for a given user.
	 * 
	 * If the caller is an administrator
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_hardtoken
	 * - /endentityprofilesrules/<end entity profile of user>/view_hardtoken
	 * - /endentityprofilesrules/<end entity profile of user>/view_hardtoken/puk_data (if viewPUKData = true)
	 * 
	 * 
	 * @param username to look for.
	 * @param viewPUKData if PUK data of the hard token should be returned.
	 * @param boolean onlyValidCertificates of all revoked and expired certificates should be filtered.
	 * @return a list of the HardTokenData generated for the user never null.
	 * @throws EjbcaException if an exception occurred on server side.
	 */
	public abstract List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
			throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException;

	/**
	 * Method performing a republication of a selected certificate
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param serialNumberInHex of the certificate to republish
	 * @param issuerDN of the certificate to republish
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the administratior isn't authorized to republish
	 * @throws PublisherException if something went wrong during publication
	 * @throws EjbcaException if other error occured on the server side.
	 */
	public abstract void republishCertificate(String serialNumberInHex,
			String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException,
			PublisherException, EjbcaException;

	/**
	 * Looks up if a requested action have been approved by an authorized administrator or not
	 * 
	 * Authorization requirements: A valid certificate
	 * 
	 * @param approvalId unique id for the action
	 * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
	 * @throws ApprovalException if approvalId doesn't exists
	 * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it wount throw it anymore.
	 * @throws EjbcaException if error occured server side
	 */
	public abstract int isApproved(int approvalId) throws ApprovalException,
			EjbcaException, ApprovalRequestExpiredException;
	
	/**
	 * Generates a Custom Log event in the database.
	 * 
	 * Authorization requirements: 
	 * - Administrator flag set
	 * - /administrator
	 * - /log_functionality/log_custom_events
	 * 
	 * @param level of the event, one of IEjbcaWS.CUSTOMLOG_LEVEL_ constants
	 * @param type userdefined string used as a prefix in the log comment
	 * @param caname of the ca related to the event, use null if no specific CA is related.
	 * Then will the ca of the administrator be used.
	 * @param username of the related user, use null if no related user exists.
	 * @param certificate that relates to the log event, use null if no certificate is related
	 * @param msg message data used in the log comment. The log comment will have
	 * a syntax of '<type> : <msg'
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the administrators isn't authorized to log.
	 * @throws EjbcaException if error occured server side
	 */		
	public abstract void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg) throws
		CADoesntExistsException, AuthorizationDeniedException, EjbcaException;

	/**
	 * Special method used to remove existing used data from a user data source.
	 * 
	 * Important removal functionality of a user data source is optional to
	 * implement so it isn't certain that this method works with the given
	 * user data source.
	 * 
	 * Authorization requirements
	 * - Administrator flag set
	 * - /administrator
	 * - /userdatasourcesrules/<user data source>/remove_userdata (for all the given user data sources)
	 * - /ca/<all cas defined in all the user data sources>
	 * 
	 * 
	 * @param userDataSourceName the names of the userdata source to remove from
	 * @param searchString the search string to search for
	 * @param removeMultipleMatch if multiple matches of a search string should be removed othervise is none removed.
	 * @return true if the user was remove successfully from at least one of the user data sources.
	 * @throws AuthorizationDeniedException if the user isn't authorized to remove userdata from any of the specified user data sources
	 * @throws MultipleMatchException if the searchstring resulted in a multiple match and the removeMultipleMatch was set to false.
	 * @throws UserDataSourceException if an error occured during the communication with the user data source. 
	 * @throws EjbcaException if error occured server side
	 */
	public abstract boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException;  
	
	/**
	 * Method to fetch a issued certificate. 
	 *
	 * Authorization requirements
	 * - A valid certificate
	 * - /ca_functionality/view_certificate
	 * - /ca/<of the issing CA>
	 * 
	 * @param certSNinHex the certificate serial number in hexadecimal representation
	 * @param issuerDN the issuer of the certificate
	 * @return the certificate (in WS representation) or null if certificate couldn't be found.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the calling administrator isn't authorized to view the certificate
	 * @throws EjbcaException if error occured server side
	 */
	public abstract Certificate getCertificate(String certSNinHex, String issuerDN) throws
		CADoesntExistsException, AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Method used to fetch a list of the ids and names of available CAs, i.e. not having status "external" or "waiting for certificate response".
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * 
	 * @return array of NameAndId of available CAs, if no CAs are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @see ICAAdminSessionLocal#getAvailableCAs()
	 * @author Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 */
	public abstract NameAndId[] getAvailableCAs()
			throws EjbcaException, AuthorizationDeniedException;

	/**
	 * Method that fetches a list of end entity profiles that the administrator is authorized to use.
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /endentityprofilesrules/<end entity profile>
	 * 
	 * @return array of NameAndId of available end entity profiles, if no profiles are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @see IRaAdminSessionLocal#getAuthorizedEndEntityProfileIds()
	 * @author Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 */
	public abstract NameAndId[] getAuthorizedEndEntityProfiles()
			throws EjbcaException, AuthorizationDeniedException;

	/**
	 * Method that fetches a list of available certificate profiles in an end entity profile.
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /endentityprofilesrules/<end entity profile>
	 * 
	 * @param entityProfileId id of an end entity profile where we want to find which certificate profiles are available
	 * @return array of NameAndId of available certificate profiles, if no profiles are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @author Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 */
	public abstract NameAndId[] getAvailableCertificateProfiles(int entityProfileId) 
			throws AuthorizationDeniedException, EjbcaException;

	/**
	 * Method used to fetch a list of the ids and names of available CAs in an end entity profile.
	 * 
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /endentityprofilesrules/<end entity profile>
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * @param entityProfileId id of an end entity profile where we want to find which CAs are available
	 * @return array of NameAndId of available CAs in the specified end entity profile, if no CAs are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @author Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 */
	public abstract NameAndId[] getAvailableCAsInProfile(int entityProfileId) 
			throws AuthorizationDeniedException, EjbcaException;

	/** Generates a CRL for the given CA.
	 * Authorization requirements:
	 * - Administrator flag set
	 * - /administrator
	 * - /ca/<caid>
     *
	 * @param caname the name in EJBCA of the CA that should have a new CRL generated
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws ApprovalException
	 * @throws EjbcaException if an error occured
	 * @throws ApprovalRequestExpiredException
	 */
	public abstract void createCRL(String caname) 
			throws CADoesntExistsException, ApprovalException, EjbcaException, ApprovalRequestExpiredException;
	
	/** Returns the version of the EJBCA server.
	 * Authorization requirements:
	 *  - none
     *
	 * @returns String with the version of EJBCA, i.e. "EJBCA 3.6.2"
	 * @throws EjbcaException if an error occured
	 */
	public abstract String getEjbcaVersion();

    /**
     * Ask for the length of a publisher queue
     * @param name of the queue
     * @return the length or -4 if the publisher does not exist
     * @throws EjbcaException
     */
    int getPublisherQueueLength(String name) throws EjbcaException;
}