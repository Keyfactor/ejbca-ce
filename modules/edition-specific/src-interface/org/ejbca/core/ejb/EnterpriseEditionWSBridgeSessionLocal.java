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
package org.ejbca.core.ejb;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CertPathValidatorException;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignedByExternalCANotSupportedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.roles.RoleNotFoundException;
import org.ejbca.util.KeyValuePair;

/**
 * JEE5 Lookup helper implementation for optional (enterprise edition) WS methods.
 * 
 * @version $Id$
 */
@Local
public interface EnterpriseEditionWSBridgeSessionLocal {

    /**
     * Creates a new cryptotoken
     * 
     * @param admin An authentication token
     * @param tokenName The name of the crypto token
     * @param tokenType The type of the crypto token. Available types: SoftCryptoToken, PKCS11CryptoToken
     * @param activationPin Pin code for the crypto token
     * @param autoActivate Set to true|false to allow|disallow whether crypto token should be autoactivated or not
     * @param cryptoTokenProperties The properties of the cryptotoken. See {@link org.ejbca.core.protocol.ws.objects.CryptoTokenConstantsWS}
     * 
     * @throws UnsupportedMethodException if trying to access this method in the community version
     * @throws AuthorizationDeniedException if admin lacks access to resource /cryptotoken/modify
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws CryptoTokenAuthenticationFailedException if the password specified in activationPin was incorrect
     * @throws CryptoTokenNameInUseException if a crypto token with the given name already exists
     * @throws NoSuchSlotException if the slot as defined in cryptoTokenProperties doesn't exist
     */
    void createCryptoToken(AuthenticationToken admin, String tokenName, String tokenType, String activationPin, boolean autoActivate, 
            List<KeyValuePair> cryptoTokenProperties) throws UnsupportedMethodException, AuthorizationDeniedException, 
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException;
    
    /**
     * Generates a keys pair in the specified cryptotoken
     * 
     * @param admin An authentication token
     * @param cryptoTokenName The name of the cryptotoken
     * @param keyPairAlias Key pair alias
     * @param keySpecification Key specification, for example RSA2048, secp256r1, DSA1024, gost3410, dstu4145
     * 
     * @throws UnsupportedMethodException When trying to access this method in the community version
     * @throws InvalidKeyException if key generation failed
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws InvalidAlgorithmParameterException if the keySpecification is not available for this CryptoToken.
     * @throws AuthorizationDeniedException if admin lacks access to resource /cryptotoken/modify
     */
    void generateCryptoTokenKeys(AuthenticationToken admin, String cryptoTokenName, String keyPairAlias, String keySpecification) 
            throws UnsupportedMethodException, InvalidKeyException, CryptoTokenOfflineException, InvalidAlgorithmParameterException, 
            AuthorizationDeniedException;
    
    /**
     * Creates a new CA
     * 
     * @param admin An authentication token
     * @param caname The CA name
     * @param cadn The CA subjectDN
     * @param catype The CA type. It could be either 'x509' or 'cvc'
     * @param encodedValidity Validity of the CA  encoded for example as "3650d".
     * @param certprofile Makes the CA use the certificate profile 'certprofile' instead of the default ROOTCA or SUBCA.
     * @param signAlg Signing Algorithm may be one of the following: SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA
     *        SHA256WithRSAAndMGF1, SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, SHA1WithDSA, 
     *        GOST3411withECGOST3410, GOST3411withDSTU4145
     * @param signedByCAId The ID of a CA that will sign this CA. Use '1' for self signed CA (i.e. a root CA). Externally signed CA's should be created with 
     *          the createExternallySignedCa call. 
     * @param cryptoTokenName The name of the cryptotoken associated with the CA
     * @param purposeKeyMapping The mapping the the cryptotoken keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * 
     * @throws UnsupportedMethodException When trying to access this method in the community version
     * @throws SignedByExternalCANotSupportedException if the given CA was set to be signed by external
     * @throws CAExistsException if a CA with the given name already exists
     * @throws AuthorizationDeniedException if admin is not authorized to create CAs
     * @throws CertificateProfileDoesNotExistException if the certificate profile specified by certprofile doesn't exist
     * @throws CertificateProfileTypeNotAcceptedException if the certificate profile was not of type ROOTCA or SUBCA
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws InvalidAlgorithmException if the CA signature algorithm was invalid
     */
    void createCA(AuthenticationToken admin, String caname, String cadn, String catype, String encodedValidity, String certprofile, 
            String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping, List<KeyValuePair> caProperties) 
            throws UnsupportedMethodException, SignedByExternalCANotSupportedException, CAExistsException, AuthorizationDeniedException, 
            CertificateProfileDoesNotExistException, CertificateProfileTypeNotAcceptedException, CryptoTokenOfflineException, InvalidAlgorithmException;
    
    /**
     * Create an externally signed CA. Will return a CSR as a byte array.
     * 
     * @param authenticationToken An authentication token
     * @param caname The CA name
     * @param cadn The CA subjectDN
     * @param catype The CA type. It could be either 'x509' or 'cvc'
     * @param encodedValidity Validity of the CA  encoded for example as "3650d".
     * @param certprofile Makes the CA use the certificate profile 'certprofile' instead of the default ROOTCA or SUBCA.
     * @param signAlg Signing Algorithm may be one of the following: SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA
     *        SHA256WithRSAAndMGF1, SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, SHA1WithDSA, 
     *        GOST3411withECGOST3410, GOST3411withDSTU4145
     * @param cryptoTokenName The name of the cryptotoken associated with the CA
     * @param purposeKeyMapping The mapping the the cryptotoken keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * 
     * @return a CSR for this CA
     * 
     * @throws UnsupportedMethodException  When trying to access this method in the community version
     * @throws CAExistsException if a CA with the given name already exists
     * @throws AuthorizationDeniedException if admin is not authorized to create CAs
     * @throws CertificateProfileDoesNotExistException if the certificate profile specified by certificate profile doesn't exist
     * @throws CertificateProfileTypeNotAcceptedException if the certificate profile was not of type ROOTCA or SUBCA
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws InvalidAlgorithmException if the CA signature algorithm was invalid
     * @throws CertPathValidatorException An exception indicating one of a variety of problems encountered when validating a certification path.
     */
    byte[] createExternallySignedCa(AuthenticationToken authenticationToken, String caname, String cadn, String catype, String encodedValidity, String certprofile, 
            String signAlg, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping, List<KeyValuePair> caProperties) throws UnsupportedMethodException, CAExistsException, CertificateProfileDoesNotExistException, CertificateProfileTypeNotAcceptedException, CryptoTokenOfflineException, InvalidAlgorithmException, AuthorizationDeniedException, CertPathValidatorException;
    
    /**
     * Adds an administrator to the specified role
     * 
     * @param admin An authentication token
     * @param roleName The role to add the admin to
     * @param caName Name of the CA that issued the new administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue the value to match against
     * 
     * @throws UnsupportedMethodException if trying to access this method in the community version
     * @throws RoleNotFoundException if the role specified by rolename doesn't exist
     * @throws CADoesntExistsException if the CA specified by caName doesn't exist
     * @throws AuthorizationDeniedException if admin doesn't have access to CA or rights to manage roles.
     */
    void addSubjectToRole(AuthenticationToken admin, String roleName, String caName, String matchWith, String matchType, 
            String matchValue) throws UnsupportedMethodException, RoleNotFoundException, CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Removes an administrator to the specified role
     * 
     * @param admin An authentication token
     * @param roleName The role to add the admin to
     * @param caName Name of the CA that issued the new administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue if admin doesn't have access to CA or rights to manage roles.
     * 
     * @throws UnsupportedMethodException if trying to access this method in the community version
     * @throws RoleNotFoundException if the role specified by rolename doesn't exist
     * @throws CADoesntExistsException if the CA specified by caName doesn't exist
     * @throws AuthorizationDeniedException if admin doesn't have access to CA or rights to manage roles.
     */
    void removeSubjectFromRole(AuthenticationToken admin, String roleName, String caName, String matchWith, String matchType, 
            String matchValue) throws UnsupportedMethodException, RoleNotFoundException, CADoesntExistsException, AuthorizationDeniedException;
}