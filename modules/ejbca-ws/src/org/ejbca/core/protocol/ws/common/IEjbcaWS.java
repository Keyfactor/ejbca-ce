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
package org.ejbca.core.protocol.ws.common;

import java.security.cert.CertificateExpiredException;
import java.util.List;

import org.cesecore.CesecoreException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.protocol.ws.DateNotValidException;
import org.ejbca.core.protocol.ws.UnknownProfileTypeException;
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
import org.ejbca.util.KeyValuePair;
import org.ejbca.util.query.IllegalQueryException;

/**
 * Primary interface to the EJBCA RA WebService.
 * 
 * 
 * Observe: All methods have to be called using client authenticated https
 * otherwise an AuthorizationDenied exception will be thrown.
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public interface IEjbcaWS {
	
	public static final int CUSTOMLOG_LEVEL_INFO  = 1;
	public static final int CUSTOMLOG_LEVEL_ERROR = 2;

	/**
	 * Edits/adds a user to the EJBCA database.
	 * 
	 * If the user doesn't already exists it will be added otherwise it will be
	 * overwritten.
	 * 
	 * Observe: if the user doesn't already exists, it's status will always be set to 'New'.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * @param userdata contains all the information about the user about to be added.
	 * clearPwd indicates it the password should be stored in clear text, required
	 * when creating server generated keystores.
	 * @throws CADoesntExistsException if a referenced CA does not exist
	 * @throws ApprovalException
	 * @throws AuthorizationDeniedException
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws WaitingForApprovalException
	 * @throws EjbcaException
	 */
    void editUser(UserDataVOWS userdata) throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            EjbcaException, ApprovalException, WaitingForApprovalException;

	/**
	 * Retrieves information about users in the database.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile of matching users&gt;/view_end_entity
	 * - /ca/&lt;ca of usermatch&gt; - when matching on CA
	 * </pre>
	 * 
	 * @param usermatch the unique user pattern to search for
	 * @return a array of {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS} objects (Max 100) containing the information about the user or null if there are no matches.
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws IllegalQueryException if query isn't valid
	 * @throws EjbcaException 
	 * @throws EndEntityProfileNotFoundException 
	 */
	List<UserDataVOWS> findUser(UserMatch usermatch)
			throws AuthorizationDeniedException, IllegalQueryException, EjbcaException, EndEntityProfileNotFoundException;

	/**
	 * Retrieves a collection of certificates generated for a user.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * @param username a unique username 
	 * @param onlyValid only return valid certs not revoked or expired ones.
	 * @return a collection of Certificates or an empty list if no certificates, or no user, could be found
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws EjbcaException 
	 */
	List<Certificate> findCerts(String username,
			boolean onlyValid) throws AuthorizationDeniedException, EjbcaException;

	/**
	 * Retrieves the latest CA path
	 * 
	 *  Note: the whole certificate chain is returned.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ca/&lt;ca in question&gt;
	 * </pre>
	 * 
	 * @param caname a unique caname 
	 * @return a collection of X509Certificates or CVCCertificates with CA certificate in pos 0, and possible higer-level CA in pos 1 and upwards.
	 * <i>If CA status is CA_WAITING_CERTIFICATE_RESPONSE the list will be of zero length</i>
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws CADoesntExistsException 
	 * @throws EjbcaException
	 */
	List<Certificate> getLastCAChain(String caname) 
	throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;

	/**
	 * Retrieves the latest certificate issued to the user.
	 * 
	 *  Note the whole certificate chain is returned.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * If the user is not found on the local system, then the query will be forwarded to upstream peer systems (if any).
	 * 
	 * @param username a unique username 
	 * @return a collection of X509Certificates or an empty list if no certificates could be found with user certificate in pos 0, SubCA in 1, RootCA in 2 etc, or if user does not exist.
	 *         Prior to EJBCA 6.8.0, the documentation incorrectly stated that this method could return null when it actually returns an empty list.
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws EjbcaException on internal errors, such as badly encoded certificate.
	 */
	List<Certificate> getLastCertChain(String username)
	throws AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Creates a new cryptotoken
	 * 
	 * @param tokenName The name of the cryptotoken
	 * @param tokenType The type of the cryptotoken. Available types: SoftCryptoToken, PKCS11CryptoToken
	 * @param activationPin Pin code for the cryptotoken
	 * @param autoActivate Set to true|false to allow|disallow whether cryptotoken should be autoactivated or not
	 * @param cryptotokenProperties as a List of KeyValuePair objects. See {@link org.ejbca.core.protocol.ws.objects.CryptoTokenConstantsWS}
	 * @throws EjbcaException
	 * @throws AuthorizationDeniedException
	 * @see org.ejbca.core.protocol.ws.objects.CryptoTokenConstantsWS
	 */
	 void createCryptoToken(String tokenName, String tokenType, String activationPin, boolean autoActivate, 
	        List<KeyValuePair> cryptotokenProperties) throws AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Generates a key pair in the specified cryptotoken
	 *  
	 * @param cryptoTokenName The name of the cryptotoken
	 * @param keyPairAlias Key pair alias
	 * @param keySpecification Key specification, for example RSA2048, secp256r1, DSA1024, gost3410, dstu4145
	 * @throws AuthorizationDeniedException
	 * @throws EjbcaException
	 */
	 void generateCryptoTokenKeys(String cryptoTokenName, String keyPairAlias, String keySpecification) 
	        throws AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Creates a new CA using the specified cryptotoken
	 * 
     * @param caname The CA name
     * @param cadn The CA subjectDN
     * @param catype The CA type. It could be either 'x509' or 'cvc'
     * @param validityInDays Validity of the CA in days.
     * @param certprofile Makes the CA use the certificate profile 'certprofile' instead of the default ROOTCA or SUBCA.
     * @param signAlg Signing Algorithm may be one of the following: SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA
     * SHA256WithRSAAndMGF1, SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, SHA1WithDSA, 
     * GOST3411withECGOST3410, GOST3411withDSTU4145
     * @param signedByCAId The ID of a CA that will sign this CA. Use '1' for self signed CA (i.e. a root CA).
     * CAs created using the WS cannot be signed by external CAs.
     * @param cryptoTokenName The name of the cryptotoken associated with the CA
     * @param purposeKeyMapping The mapping the the cryptotoken keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
	 * @throws EjbcaException
	 * @throws AuthorizationDeniedException
     * @see org.ejbca.core.protocol.ws.objects.CAConstantsWS
	 */
	 void createCA(String caname, String cadn, String catype, long validityInDays, String certprofile, 
	        String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping, 
	        List<KeyValuePair> caProperties) throws EjbcaException, AuthorizationDeniedException;
	
	/**
	 * Adds an administrator to the specified role
	 * 
	 * @param roleName The role to add the admin to
	 * @param caName Name of the CA that issued the new administrator's certificate
	 * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
	 * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
	 * @param matchValue That value to match against
	 * @throws EjbcaException
	 * @throws AuthorizationDeniedException
	 */
	 void addSubjectToRole(String roleName, String caName, String matchWith, String matchType, String matchValue) 
	        throws EjbcaException, AuthorizationDeniedException;
	
	/**
	 * Removes an administrator from the specified role
	 * 
	 * @param roleName The role to remove the admin from
	 * @param caName Name of the CA that issued the administrator's certificate
	 * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
	 * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
	 * @param matchValue The value to match against
	 * @throws EjbcaException
	 * @throws AuthorizationDeniedException
	 */
	void removeSubjectFromRole(String roleName, String caName, String matchWith, String matchType, String matchValue) 
	        throws EjbcaException, AuthorizationDeniedException;
	
	/**
	 *  Generates a certificate for a user.
	 * 
	 *  Works the same as pkcs10Request.
	 * 
	 * @see #pkcs10Request(String, String, String, String, String)
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param crmf the CRMF request message (only the public key is used.)
	 * @param responseType indicating which type of answer that should be returned, on of the 
	 *                     {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
	 * @throws CADoesntExistsException if a referenced CA does not exist
	 * @throws AuthorizationDeniedException
	 * @throws NotFoundException
	 * @throws EjbcaException
	 * @throws CesecoreException 
	 */
	CertificateResponse crmfRequest(String username, String password,
			String crmf, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException, CesecoreException;

	/**
	 *  Generates a certificate for a user.
	 *  
	 *  Works the same as pkcs10Request.
	 * 
	 * @see #pkcs10Request(String, String, String, String, String)
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param spkac the SPKAC (netscape) request message (only the public key is used.)
	 * @param responseType indicating which type of answer that should be returned, on of the
	 *                     {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException
	 * @throws NotFoundException
	 * @throws EjbcaException
	 * @throws CesecoreException 
	 */
	CertificateResponse spkacRequest(String username, String password,
			String spkac, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException, CesecoreException;

	/** 
	 * Generates a CV certificate for a user.
	 * 
	 * Uses the same authorizations as editUser and pkcs10Request
	 * responseType is always {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_CERTIFICATE.
	 * 
	 * @see #editUser(UserDataVOWS)
	 * @see #pkcs10Request(String, String, String, String, String)
	 * @param username the user name of the user requesting the certificate.
	 * @param password the password for initial enrollment, not used for renewal requests that can be authenticated using signatures with keys with valid certificates.
	 * @param cvcreq Base64 encoded CVC request message.
	 * @return the full certificate chain for the IS, with IS certificate in pos 0, DV in 1, CVCA in 2.
	 * 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if administrator is not authorized to edit end entity or if an authenticated request can not be verified
	 * @throws SignRequestException if the provided request is invalid, for example not containing a username or password
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws NotFoundException
	 * @throws EjbcaException for other errors, an error code like ErrorCode.SIGNATURE_ERROR (popo/inner signature verification failed) is set.
	 * @throws ApprovalException
	 * @throws WaitingForApprovalException
	 * @throws CertificateExpiredException
	 * @throws CesecoreException 
	 * @see org.cesecore.ErrorCode 
	 */
    List<Certificate> cvcRequest(String username, String password, String cvcreq)
	throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException,
	EjbcaException, ApprovalException, WaitingForApprovalException, SignRequestException, CertificateExpiredException, CesecoreException;
	

	/** Generates a certificate request (CSP) from a CA. The CSR can be sent to another CA to be signed, thus making the CA a sub CA of the signing CA.
	 * Can also be used for cross-certification. The method can use an existing key pair of the CA or generate a new key pair. The new key pair does not have to be
	 * activated and used as the CAs operational signature keys.
	 * 
	 * Authorization requirements: the client certificate must have the following privileges set<pre>
	 * - /administrator
	 * - /ca_functionality/renew_ca
	 * - /ca/&lt;ca to renew&gt;
	 * </pre>
	 * @param caname The name in EJBCA for the CA that will create the CSR
	 * @param cachain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
	 * For DV renewals the cachain may be an empty list if there is a matching imported CVCA.
	 * Matching means having the same mnemonic,country and sequence as well as being external.   
     * @param regenerateKeys if renewing a CA this is used to also generate a new KeyPair, if this is true and activatekey is false, the new key will not be activated immediately, but added as "next" signingkey.
     * @param usenextkey if regenerateKey is true this should be false. Otherwise it makes a request using an already existing "next" signing key, perhaps from a previous call with regenerateKeys true.
     * @param activatekey if regenerateKey is true or usenextkey is true, setting this flag to true makes the new or "next" key be activated when the request is created.
     * @param keystorepwd password used when regenerating keys or activating keys, can be null if regenerateKeys and activatekey is false.
	 * 
     * @return byte array with binary encoded certificate request to be sent to signing CA.
     * 
	 * @throws CADoesntExistsException if caname does not exist
	 * @throws AuthorizationDeniedException if administrator is not authorized to create request, renew keys etc.
	 * @throws ApprovalException if a non-expired approval for this action already exists, i.e. the same action has already been requested.
	 * @throws WaitingForApprovalException if the operation requires approval from another CA administrator, in this case an approval request is created for another administrator to approve
	 * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCade is set in the EjbcaException
	 */
	byte[] caRenewCertRequest(String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException; 

	/** Receives a certificate as a response to a CSR from the CA. The CSR might have been generated using the caRenewCertRequest. 
	 * When the certificate is imported it is verified that the CA keys match the received certificate. 
	 * This can be used to activate a new key pair on the CA. If the certificate does not match the existing key pair, but another key pair on the CAs token, this key pair can be activated and used as the CAs operational signature key pair.
	 *   
	 * Authorization requirements: the client certificate must have the following privileges set<pre>
	 * - /administrator
	 * - /ca_functionality/renew_ca
	 * - /ca/&lt;ca to import certificate&gt;
	 * </pre>
	 * This method auto-senses if there is a new CA key that needs to be activated, it does this by comparing the public key in cert with public keys in the CAs token
	 * @param caname The name in EJBCA for the CA that will create the CSR
	 * @param cert the CA certificate to import. Certificate format is the binary certificate bytes.
	 * @param cachain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
	 * @param keystorepwd If there is a new CA key that must be activates the keystore password is needed. Set to null if the request was generated using the existing CA keys.
	 * 
	 * @throws CADoesntExistsException if caname does not exist
	 * @throws AuthorizationDeniedException if administrator is not authorized to import certificate.
	 * @throws ApprovalException if the operation requires approval from another CA administrator, in this case an approval request is created for another administrator to approve 
	 * @throws WaitingForApprovalException if there is already a request waiting for approval
	 * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCade is set in the EjbcaException
	 * @throws CesecoreException 
	 */
	void caCertResponse(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException;
	
	/**
	 * Receives a certificate as a response to a CSR from the CA, but does not activate the certificate yet.
	 * To activate the certificate at a later point, use the rolloverCACert method.
	 * It is also possible to configure a Rollover Service for automatic activation once the new certificate becomes valid.
	 * 
	 * @param caname The name in EJBCA for the CA that will create the CSR
     * @param cert the CA certificate to import. Certificate format is the binary certificate bytes.
     * @param cachain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
     * @param keystorepwd If there is a new CA key that must be activates the keystore password is needed. Set to null if the request was generated using the existing CA keys.
     * 
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws EjbcaException
     * @throws ApprovalException
     * @throws WaitingForApprovalException
     * @throws CesecoreException
	 */
	void caCertResponseForRollover(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException;

	/**
	 * Imports a root or sub CA certificate of an external X.509 CA or CVC CA.
	 * 
	 * @param caname the logical name of the CA in EJBCA.
	 * @param certbytes a byte array containing the CA certificate, and optional it's CA certificate chain.
	 * 
	 * @throws AuthorizationDeniedException
	 * @throws CAExistsException if a CA with that logical name or CA certificate subject DN already exists.
	 * @throws EjbcaException if an other exception occurs.
	 */
	void importCaCert(String caname, byte[] certbytes) throws AuthorizationDeniedException, CAExistsException, EjbcaException;
	
	/**
	 * Updates a root or sub CA certificate of an external X.509 CA or CVC CA.
	 * 
	 * @param caname the logical name of the CA in EJBCA
	 * @param certbytes a byte array containing the CA certificate, and optional it's CA certificate chain.
	 * 
	 * @throws AuthorizationDeniedException
	 * @throws CADoesntExistsException if a CA with that logical name does not exists in EJBCA.
	 * @throws EjbcaException if an other exception occurs.
	 */
	void updateCaCert(String caname, byte[] certbytes) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;
	
	/**
	 * Performs a certificate rollover for a CA with a rollover certificate previously added with caCertResponseForRollover.
     * @throws AuthorizationDeniedException if administrator is not authorized to import certificate.
     * @throws CADoesntExistsException if caname does not exist
     * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCode is set in the EjbcaException
     */
    void rolloverCACert(String caname) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;
	
	/**
	 * Generates a certificate for a user.
	 * 
	 * The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add non-existing users.
	 * 
	 * Observe, the user must first have added/set the status to new with edituser command
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
	 * - /ca_functionality/create_certificate
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param pkcs10 the base64 encoded PKCS10 (only the public key is used.)
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a tokens
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param responseType indicating which type of answer that should be returned, on of the
	 * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
	 * @return the generated certificate, in either just X509Certificate or PKCS7 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws EjbcaException
	 * @throws CesecoreException 
	 */
	CertificateResponse pkcs10Request(String username, String password,
			String pkcs10, String hardTokenSN, String responseType)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException, CesecoreException;

	/**
	 * Creates a server-generated keystore.
	 * 
	 * The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add non-existing users and
	 * the user's token must be set to {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS}.TOKEN_TYPE_P12.<br>
	 * 
	 * Authorization requirements: <pre>
	 * - /administrator
     * - /ca/&lt;ca of user&gt;
     * - /ca_functionality/create_certificate
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
	 * - /ra_functionality/view_end_entity
	 * </pre>
	 * 
     * Additional authorization requirements for (non key recovery) clearing of password: <pre>
     * - /endentityprofilesrules/&lt;end entity profile&gt;/edit_end_entity
     * - /ra_functionality/edit_end_entity
     * </pre>
     * 
     * Additional authorization requirements for key recovery: <pre>
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /ra_functionality/keyrecovery
     * </pre>
     * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a tokens
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param keyspec that the generated key should have, examples are 2048 for RSA or secp256r1 for ECDSA.
	 * @param keyalg that the generated key should have, RSA, ECDSA. Use one of the constants in
	 * {@link org.cesecore.certificates.util.AlgorithmConstants}.KEYALGORITHM_...
	 * @return the generated keystore
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws EjbcaException
	 */
	KeyStore pkcs12Req(String username, String password,
			String hardTokenSN, String keyspec, String keyalg)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException;

	/**
	 * Revokes a user certificate.
	 * 
	 * Authorization requirements:<pre>
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user owning the cert>/revoke_end_entity
	 * - /ca/&lt;ca of certificate&gt;
	 * </pre>
	 * <p>
	 * To use this call the certificate to be used must be from a certificate profile that has 'Allow back dated revocation' enabled.
	 * </p><p>
	 * If {@link RevokeBackDateNotAllowedForProfileException} is throwed then the CA is not
	 * allowing back date and you could then revoke with {@link #revokeCert(String, String, int)}.
	 * {@link DateNotValidException} means that the date parameter can't be parsed and in this case it might also
	 * be better with a fall back to {@link #revokeCert(String, String, int)}.
	 * </p>
	 * @param issuerDN of the certificate to revoke
	 * @param certificateSN Certificate serial number in hex format of the certificate to revoke (without any "0x", "h" or similar) 
	 * @param reason for revocation, one of {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.REVOKATION_REASON_ constants, 
	 * or use {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.NOT_REVOKED to un-revoke a certificate on hold.
	 * @param sDate The revocation date. If null then the current date is used. If specified then the profile of the certificate must allow
	 * "back dating" and the date must be i the past. The parameter is specified as an
	 * <a href="http://en.wikipedia.org/wiki/ISO8601">ISO 8601 string</a>.
	 * An example: 2012-06-07T23:55:59+02:00
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if certificate doesn't exist
	 * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved
	 * @throws ApprovalException There already exists an approval request for this task
	 * @throws AlreadyRevokedException The certificate was already revoked, or you tried to unrevoke a permanently revoked certificate
	 * @throws EjbcaException internal error
	 * @throws RevokeBackDateNotAllowedForProfileException if back date is not allowed in the certificate profile
	 * @throws DateNotValidException if the date is not a valid ISO 8601 string or if it is in the future.
	 */
	void revokeCertBackdated(String issuerDN, String certificateSN, int reason,
			String sDate) throws CADoesntExistsException,
			AuthorizationDeniedException, NotFoundException, EjbcaException,
			ApprovalException, WaitingForApprovalException,
			AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException, DateNotValidException;

	/**
	 * Same as {@link #revokeCertBackdated(String, String, int, String)} but revocation date is current time.
	 * 
	 * @param issuerDN
	 * @param certificateSN
	 * @param reason
	 * @throws CADoesntExistsException
	 * @throws AuthorizationDeniedException
	 * @throws NotFoundException
	 * @throws EjbcaException
	 * @throws ApprovalException
	 * @throws WaitingForApprovalException
	 * @throws AlreadyRevokedException
	 */
	void revokeCert(String issuerDN, String certificateSN,
			int reason) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
			EjbcaException, ApprovalException, WaitingForApprovalException,
			AlreadyRevokedException;

	/**
	 * Revokes all of a user's certificates.
	 * 
	 * It is also possible to delete
	 * a user after all certificates have been revoked.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/revoke_end_entity
	 * - /ca/<ca of users certificate>
	 * </pre>
	 * 
	 * @param username unique username i EJBCA
	 * @param reason for revocation, one of {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.REVOKATION_REASON_ constants
	 * or use {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.NOT_REVOKED to un-revoke a certificate on hold.
	 * @param deleteUser deletes the users after all the certificates have been revoked.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if user doesn't exist
	 * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved
	 * @throws ApprovalException if there already exists an approval request for this task
	 * @throws AlreadyRevokedException if the user already was revoked
	 * @throws EjbcaException
	 */
	void revokeUser(String username, int reason,
			boolean deleteUser) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException, AlreadyRevokedException;

	/**
	 * Marks the user's latest certificate for key recovery.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/keyrecovery
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
	 * - /ca/<ca of users certificate>
	 * </pre>
	 * 
	 * @param username unique username i EJBCA
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if user doesn't exist
	 * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved
	 * @throws ApprovalException if there already exists an approval request for this task
	 * @throws EjbcaException if there is a configuration or other error
	 */
	void keyRecoverNewest(String username) throws
			CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException;

	/**
     * Marks a user's certificate for key recovery.
     * 
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of users certificate&gt;
     * - /ca_functionality/view_certificate
     * - /ra_functionality/keyrecovery
     * - /ra_functionality/view_end_entity
     * </pre>
     * 
     * @param username unique username i EJBCA
     * @param certSNinHex unique certificate serialnumber i EJBCA, hex encoded 
     * @param issuerDN DN of CA, i EJBCA, that issued the certificate 
     * @throws CADoesntExistsException if a referenced CA does not exist 
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws NotFoundException if user doesn't exist
     * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved
     * @throws ApprovalException if there already exists an approval request for this task
     * @throws EjbcaException if there is a configuration or other error
     */
    void keyRecover(String username, String certSNinHex, String issuerDN) throws
            CADoesntExistsException, AuthorizationDeniedException,
            NotFoundException, EjbcaException, ApprovalException,
            WaitingForApprovalException;
	
	/**
	 * Revokes all certificates mapped to a hardtoken.
	 *
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /endentityprofilesrules/<end entity profile of the user owning the token>/revoke_end_entity
	 * - /ca/&lt;ca of certificates on token&gt;
	 * </pre>
	 * 
	 * @param hardTokenSN of the hardTokenSN
	 * @param reason for revocation, one of {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.REVOKATION_REASON_ constants
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if token doesn't exist
	 * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved
	 * @throws ApprovalException There already exists an approval request for this task
	 * @throws AlreadyRevokedException The token was already revoked.
	 * @throws EjbcaException
	 */
	void revokeToken(String hardTokenSN, int reason)
			throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException,
			WaitingForApprovalException, AlreadyRevokedException;

	/**
	 * Returns revocation status for given user.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ca/&lt;ca of certificate&gt;
	 * </pre>
	 * 
	 * @param issuerDN 
	 * @param certificateSN a hexa decimal string
	 * @return the revocation status or null if certificate does not exist.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws EjbcaException
	 * @see RevokeStatus
	 */
	RevokeStatus checkRevokationStatus(String issuerDN,
			String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException,
			EjbcaException;

	/**
	 * Checks if a user is authorized to a given resource.
	 * 
	 * Authorization requirements: a valid client certificate
	 * 
	 * @param resource the access rule to test
	 * @return true if the user is authorized to the resource otherwise false.
	 * @throws EjbcaException
	 * @see RevokeStatus
	 */
	boolean isAuthorized(String resource) throws EjbcaException;

	/**
	 * Fetches userdata from an existing UserDataSource.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /userdatasourcesrules/&lt;user data source&gt;/fetch_userdata (for all the given user data sources)
	 * - /ca/&lt;all cas defined in all the user data sources&gt;
	 * </pre>
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * 
	 * @param userDataSourceNames a List of User Data Source Names
	 * @param searchString to identify the userdata.
	 * @return a List of UserDataSourceVOWS of the data in the specified UserDataSources, if no user data is found will an empty list be returned. 
	 * @throws UserDataSourceException if an error occurred connecting to one of UserDataSources
	 * @throws AuthorizationDeniedException
	 * @throws EjbcaException
	 */
	List<UserDataSourceVOWS> fetchUserData(
			List<String> userDataSourceNames, String searchString)
			throws UserDataSourceException, EjbcaException, AuthorizationDeniedException;

	/**
	 * Adds certificates and/or data to a hardtoken.
	 * 
	 * Authorization requirements:<pre>
	 * If the caller is an administrator
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/create_end_entity and/or edit_end_entity
	 * - /ra_functionality/revoke_end_entity (if overwrite flag is set)
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/revoke_end_entity (if overwrite flag is set)
	 * - /ca_functionality/create_certificate
	 * - /ca/&lt;ca of all requested certificates&gt;
	 * - /hardtoken_functionality/issue_hardtokens
	 * </pre>
	 * 
	 * If the user isn't an administrator the request will be added to a queue for approval.
	 * 
	 * @param userData of the user that should be generated
	 * @param tokenRequests a list of certificate requests
	 * @param hardTokenData data containing PIN/PUK info
	 * @param overwriteExistingSN if the the current hardtoken should be overwritten instead of throwing HardTokenExists exception.
	 * If a card is overwritten, all previous certificates on the card is revoked.
	 * @param revokePreviousCards tells the service to revoke old cards issued to this user. If the present card have the label TEMPORARY_CARD
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
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws EjbcaException
	 */
    List<TokenCertificateResponseWS> genTokenCertificates(
			UserDataVOWS userData,
			List<TokenCertificateRequestWS> tokenRequests,
			HardTokenDataWS hardTokenData,
			boolean overwriteExistingSN,
			boolean revokePreviousCards) throws CADoesntExistsException, AuthorizationDeniedException,
			WaitingForApprovalException, HardTokenExistsException,
			UserDoesntFullfillEndEntityProfile, ApprovalException,
			EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException;

	/**
	 * Looks up if a serial number already have been generated.
	 * 
	 * Authorization requirements: A valid certificate
	 * 
	 * @param hardTokenSN the serial number of the token to look for.
	 * @return true if hard token exists
	 * @throws EjbcaException if error occurred server side
	 */
	boolean existsHardToken(String hardTokenSN)
			throws EjbcaException;

	/**
	 * Fetches information about a hard token.
	 * 
	 * If the caller is an administrator<pre>
	 * - /administrator
	 * - /ra_functionality/view_hardtoken
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_hardtoken
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_hardtoken/puk_data (if viewPUKData = true)
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * If the user isn't an administrator the request will be added to a queue for approval.
	 * 
	 * @param hardTokenSN of the token to look for.
	 * @param viewPUKData if PUK data of the hard token should be returned.
	 * @param onlyValidCertificates of all revoked and expired certificates should be filtered.
	 * @return the HardTokenData
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws HardTokenDoesntExistsException if the hardtokensn don't exist in database.
	 * @throws NotFoundException if user for wich the hard token is registered does not exist
	 * @throws ApprovalRequestExpiredException if the request for approval have expired.
	 * @throws ApprovalException  if error happened with the approval mechanisms
	 * @throws WaitingForApprovalException if the request haven't been processed yet. 
	 * @throws ApprovalRequestExecutionException if the approval request was rejected
	 * @throws AuthorizationDeniedException 
	 * @throws EjbcaException if an exception occurred on server side.
	 */
	HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
			throws CADoesntExistsException, AuthorizationDeniedException,
			HardTokenDoesntExistsException, NotFoundException, ApprovalException, ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException, EjbcaException;

	/**
	 * Fetches all hard tokens for a given user.
	 * 
	 * If the caller is an administrator<pre>
	 * - /administrator
	 * - /ra_functionality/view_hardtoken
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_hardtoken
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_hardtoken/puk_data (if viewPUKData = true)
	 * </pre>
	 * 
	 * @param username to look for.
	 * @param viewPUKData if PUK data of the hard token should be returned.
	 * @param onlyValidCertificates of all revoked and expired certificates should be filtered.
	 * @return a list of the HardTokenData generated for the user never null.
	 * @throws EjbcaException if an exception occurred on server side.
	 * @throws CADoesntExistsException
	 * @throws AuthorizationDeniedException
	 */
	List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
			throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException;

	/**
	 * Republishes a selected certificate.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * 
	 * @param serialNumberInHex of the certificate to republish
	 * @param issuerDN of the certificate to republish
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the administratior isn't authorized to republish
	 * @throws PublisherException if something went wrong during publication
	 * @throws EjbcaException if other error occured on the server side.
	 */
	void republishCertificate(String serialNumberInHex,
			String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException,
			PublisherException, EjbcaException;

	/**
	 * Looks up if a requested action has been approved.
	 * 
	 * Authorization requirements: A valid certificate
	 * 
	 * @param approvalId unique id for the action
	 * @return the number of approvals left, 0 if approved otherwise is the ApprovalDataVO.STATUS constants returned indicating the status.
	 * @throws ApprovalException if approvalId does not exist
	 * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it won't throw it anymore.
	 * @throws EjbcaException if error occurred server side
	 */
	int isApproved(int approvalId) throws ApprovalException,
			EjbcaException, ApprovalRequestExpiredException;
	
	/**
	 * 
	 * @param requestId the ID of an approval request
	 * @return the number of remaining approvals required, or STATUS_REJECTED (-1) if request was rejected
	 * @throws ApprovalException if a request of the given ID didn't exist
	 * @throws AuthorizationDeniedException if the current requester wasn't authorized. 
	 * @throws ApprovalRequestExpiredException if sought approval request has expired
	 * 
	 */
	int getRemainingNumberOfApprovals(int requestId) throws ApprovalException, AuthorizationDeniedException, ApprovalRequestExpiredException;
	
	/**
	 * Generates a Custom Log event in the database.
	 * 
	 * Authorization requirements: <pre>
	 * - /administrator
	 * - /secureaudit/log_custom_events (must be configured in advanced mode when editing access rules)
	 * </pre>
	 * 
	 * @param level of the event, one of IEjbcaWS.CUSTOMLOG_LEVEL_ constants
	 * @param type userdefined string used as a prefix in the log comment
	 * @param caName of the ca related to the event, use null if no specific CA is related.
	 * Then will the ca of the administrator be used.
	 * @param username of the related user, use null if no related user exists.
	 * @param certificate that relates to the log event, use null if no certificate is related
	 * @param msg message data used in the log comment. The log comment will have
	 * a syntax of 'type : msg'
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the administrators isn't authorized to log.
	 * @throws EjbcaException if error occured server side
	 */		
	void customLog(int level, String type, String caName, String username, Certificate certificate, String msg) throws
		CADoesntExistsException, AuthorizationDeniedException, EjbcaException;

	/**
	 * Removes user data from a user data source.
	 * 
	 * Important removal functionality of a user data source is optional to
	 * implement so it isn't certain that this method works with the given
	 * user data source.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /userdatasourcesrules/&lt;user data source&gt;/remove_userdata (for all the given user data sources)
	 * - /ca/&lt;all cas defined in all the user data sources&gt;
	 * </pre>
	 * 
	 * @param userDataSourceNames the names of the userdata source to remove from
	 * @param searchString the search string to search for
	 * @param removeMultipleMatch if multiple matches of a search string should be removed othervise is none removed.
	 * @return true if the user was remove successfully from at least one of the user data sources.
	 * @throws AuthorizationDeniedException if the user isn't authorized to remove userdata from any of the specified user data sources
	 * @throws MultipleMatchException if the searchstring resulted in a multiple match and the removeMultipleMatch was set to false.
	 * @throws UserDataSourceException if an error occured during the communication with the user data source. 
	 * @throws EjbcaException if error occured server side
	 */
	boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException;  
	
	/**
	 * Fetches issued certificate. 
	 *
	 * Authorization requirements:<pre>
	 * - A valid certificate
	 * - /ca_functionality/view_certificate
	 * - /ca/&lt;of the issing CA&gt;
	 * </pre>
	 * 
	 * @param certSNinHex the certificate serial number in hexadecimal representation
	 * @param issuerDN the issuer of the certificate
	 * @return the certificate (in WS representation) or null if certificate couldn't be found.
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if the calling administrator isn't authorized to view the certificate
	 * @throws EjbcaException if error occured server side
	 */
	Certificate getCertificate(String certSNinHex, String issuerDN) throws
		CADoesntExistsException, AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Fetch a list of the ids and names of available CAs.
	 * 
	 * Note: available means not having status "external" or "waiting for certificate response".
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * </pre>
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * Authored by Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 * 
	 * @return array of NameAndId of available CAs, if no CAs are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @throws AuthorizationDeniedException
	 * @see "ICAAdminSessionLocal#getAvailableCAs()"
	 */
	NameAndId[] getAvailableCAs()
			throws EjbcaException, AuthorizationDeniedException;

	/**
	 * Fetches the end-entity profiles that the administrator is authorized to use.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /endentityprofilesrules/&lt;end entity profile&gt;
	 * </pre>
	 * 
	 * Authored by Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson

	 * @return array of NameAndId of available end entity profiles, if no profiles are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @throws AuthorizationDeniedException
	 * @see "IRaAdminSessionLocal#getAuthorizedEndEntityProfileIds()"
	 */
	NameAndId[] getAuthorizedEndEntityProfiles()
			throws EjbcaException, AuthorizationDeniedException;

	/**
	 * Fetches available certificate profiles in an end entity profile.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /endentityprofilesrules/&lt;end entity profile&gt;
	 * </pre>
	 * 
	 * Authored by Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 *
	 * @param entityProfileId id of an end entity profile where we want to find which certificate profiles are available
	 * @return array of NameAndId of available certificate profiles, if no profiles are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @throws AuthorizationDeniedException
	 */
	NameAndId[] getAvailableCertificateProfiles(int entityProfileId) 
			throws AuthorizationDeniedException, EjbcaException;

	/**
	 * Fetches the ids and names of available CAs in an end entity profile.
	 * 
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /endentityprofilesrules/&lt;end entity profile&gt;
	 * </pre>
	 * 
	 * If not turned of in jaxws.properties then only a valid certificate required
	 * 
	 * Authorws by Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
	 * 
	 * @param entityProfileId id of an end entity profile where we want to find which CAs are available
	 * @return array of NameAndId of available CAs in the specified end entity profile, if no CAs are found will an empty array be returned of size 0, never null. 
	 * @throws EjbcaException if an error occured
	 * @throws AuthorizationDeniedException
	 */
	NameAndId[] getAvailableCAsInProfile(int entityProfileId) 
			throws AuthorizationDeniedException, EjbcaException;
	
	/**
	 * Fetches the profile specified by profileId and profileType in XML format.
	 *
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /endentityprofilesrules/&lt;end entity profile&gt;
	 * </pre>
	 *
	 * For detailed documentation for how to parse an End Entity Profile XML, see the org.ejbca.core.model.ra.raadmin.EndEntity class.
	 * 
	 * @param profileId ID of the profile we want to retrieve.
	 * @param profileType The type of the profile we want to retrieve. 'eep' for End Entity Profiles and 'cp' for Certificate Profiles
	 * @return a byte array containing the specified profile in XML format
	 * @throws EjbcaException if an error occured
	 * @throws AuthorizationDeniedException
	 * @throws UnknownProfileTypeException
	 */
	 byte[] getProfile(int profileId, String profileType)
                 throws EjbcaException, AuthorizationDeniedException, UnknownProfileTypeException;
	
	/**
	 * Generates a CRL for the given CA.
	 * 
	 * Authorization requirements:<pre>
	 * - /ca/&lt;caid&gt;
	 * </pre>
	 *
	 * @param caname the name in EJBCA of the CA that should have a new CRL generated
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws ApprovalException
	 * @throws EjbcaException if an error occured, for example authorization denied
	 * @throws ApprovalRequestExpiredException
	 * @throws CAOfflineException 
	 * @throws CryptoTokenOfflineException 
	 */
	void createCRL(String caname) 
			throws CADoesntExistsException, ApprovalException, EjbcaException, ApprovalRequestExpiredException, CryptoTokenOfflineException, CAOfflineException;
	
    /**
     * Retrieves the latest CRL issued by the given CA.
     * 
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * @param caname the name in EJBCA of the CA that issued the desired CRL
     * @param deltaCRL false to fetch a full CRL, true to fetch a deltaCRL (if issued)
     * @return the latest CRL issued for the CA as a DER encoded byte array
     * @throws CADoesntExistsException if a referenced CA does not exist 
     * @throws EjbcaException if an error occured, for example authorization denied
     */
    byte[] getLatestCRL(String caname, boolean deltaCRL) throws CADoesntExistsException, EjbcaException;

	/**
	 * Returns the version of the EJBCA server.
	 * 
	 * Authorization requirements:
	 *  - none
     *
	 * @return String with the version of EJBCA, i.e. "EJBCA 3.6.2"
	 */
	String getEjbcaVersion();

	/**
	 * Generates a soft token certificate for a user. 
	 * If the user is not already present in the database, the user is added.<br>
	 * Status is automatically set to STATUS_NEW.<br>
	 * The user's token type must be set to {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS}.TOKEN_TYPE_ (JKS or P12).
	 * A token password must also be defined.<p>
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
	 * - /ca_functionality/create_certificate
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * @param userData the user
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a token
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param keyspec that the generated key should have, examples are 2048 for RSA or secp256r1 for ECDSA.
	 * @param keyalg that the generated key should have, RSA, ECDSA. Use one of the constants in 
	 * {@link org.cesecore.certificates.util.AlgorithmConstants}.KEYALGORITHM_...
	 * @return the generated token data 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws ApprovalException
	 * @throws WaitingForApprovalException
	 * @throws EjbcaException
	 * @see #editUser(UserDataVOWS)
	 */
	KeyStore softTokenRequest(UserDataVOWS userData, String hardTokenSN, String keyspec, String keyalg)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException;
	/**
	 * Generates a certificate for a user.
	 * If the user is not already present in the database it will be added otherwise it will be overwritten.<br>
	 * Status is automatically set to STATUS_NEW.<p>
	 * Authorization requirements:<pre>
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
	 * - /ca_functionality/create_certificate
	 * - /ca/&lt;ca of user&gt;
	 * </pre>
	 * When the requestType is PUBLICKEY the requestData should be an 
	 * SubjectPublicKeyInfo structure either base64 encoded or in PEM format.
	 * 
	 * <p>If the CA does not exist on the local system, then the request will be forwarded to upstream peer systems (if any).
	 * 
	 * @param userData the user
	 * @param requestData the PKCS10/CRMF/SPKAC/PUBLICKEY request in base64
	 * @param requestType PKCS10, CRMF, SPKAC or PUBLICKEY request as specified by
	 * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.CERT_REQ_TYPE_ parameters.
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplify revocation of a token
	 * certificates. Use null if no hardtokenSN should be associated with the certificate.
	 * @param responseType indicating which type of answer that should be returned, on of the 
	 * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
	 * @return the generated certificate, in either just X509Certificate or PKCS7 
	 * @throws CADoesntExistsException if a referenced CA does not exist 
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws ApprovalException
	 * @throws WaitingForApprovalException
	 * @throws EjbcaException
	 * @see #editUser(UserDataVOWS)
	 */
	CertificateResponse certificateRequest(UserDataVOWS userData, String requestData, int requestType, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException;


    /**
     * Returns the length of a publisher queue.
     * 
     * @param name of the queue
     * @return the length or -4 if the publisher does not exist
     * @throws EjbcaException
     */
    int getPublisherQueueLength(String name) throws EjbcaException;
    
    /**
     * Retrieves the certificates whose expiration date is before the specified number of days.
     * 
     *  Note the whole certificate chain is returned.
     * 
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     * 
     * @param days the number of days before the certificates will expire
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
    List<Certificate> getCertificatesByExpirationTime(long days, int maxNumberOfResults) throws EjbcaException;
    
        
    /**
     * List certificates that will expire within the given number of days and issued by the given issuer
     * 
     * @param days Expire time in days
     * @param issuerDN The issuerDN of the certificates
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
    List<Certificate> getCertificatesByExpirationTimeAndIssuer(long days, String issuerDN, int maxNumberOfResults) throws EjbcaException;
        
    /**
     * List certificates that will expire within the given number of days and of the given type
     * 
     * @param days Expire time in days
     * @param certificateType The type of the certificates. Use 0=Unknown  1=EndEntity  2=SUBCA  8=ROOTCA  16=HardToken
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
    List<Certificate> getCertificatesByExpirationTimeAndType(long days, int certificateType, int maxNumberOfResults) throws EjbcaException;

}
