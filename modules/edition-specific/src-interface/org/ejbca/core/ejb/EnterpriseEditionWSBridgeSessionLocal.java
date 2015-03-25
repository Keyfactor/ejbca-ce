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
     * @param admin
     * @param tokenName The name of the crypto token
     * @param tokenType The type of the crypto token. Available types: SoftCryptoToken, PKCS11CryptoToken
     * @param activationPin Pin code for the crypto token
     * @param autoActivate Set to true|false to allow|disallow whether crypto token should be autoactivated or not
     * @param cryptoTokenProperties The properties of the cryptotoken. See {@link org.ejbca.core.protocol.ws.objects.CryptoTokenConstants}
     * @throws UnsupportedMethodException When trying to access this method in the community version
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenNameInUseException
     * @throws NoSuchSlotException
     */
    void createCryptoToken(AuthenticationToken admin, String tokenName, String tokenType, String activationPin, boolean autoActivate, 
            List<KeyValuePair> cryptoTokenProperties) throws UnsupportedMethodException, AuthorizationDeniedException, 
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException;
    
    /**
     * Generates a keys pair in the specified cryptotoken
     * 
     * @param admin
     * @param cryptoTokenName The name of the cryptotoken
     * @param keyPairAlias Key pair alias
     * @param keySpecification Key specification, for example RSA2048, secp256r1, DSA1024, gost3410, dstu4145
     * @throws UnsupportedMethodException When trying to access this method in the community version
     * @throws InvalidKeyException
     * @throws CryptoTokenOfflineException
     * @throws InvalidAlgorithmParameterException
     * @throws AuthorizationDeniedException
     */
    void generateCryptoTokenKeys(AuthenticationToken admin, String cryptoTokenName, String keyPairAlias, String keySpecification) 
            throws UnsupportedMethodException, InvalidKeyException, CryptoTokenOfflineException, InvalidAlgorithmParameterException, 
            AuthorizationDeniedException;
    
    /**
     * Creates a new CA
     * 
     * @param admin
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
     * @param purposeKeyMapping The mapping the the cryptotoken keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CaConstants}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CaConstants}
     * @throws UnsupportedMethodException When trying to access this method in the community version
     * @throws SignedByExternalCANotSupportedException
     * @throws CAExistsException
     * @throws AuthorizationDeniedException
     * @throws CertificateProfileDoesNotExistException
     * @throws CertificateProfileTypeNotAcceptedException
     * @throws CryptoTokenOfflineException
     * @throws InvalidAlgorithmException
     */
    void createCA(AuthenticationToken admin, String caname, String cadn, String catype, long validityInDays, String certprofile, 
            String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping, List<KeyValuePair> caProperties) 
            throws UnsupportedMethodException, SignedByExternalCANotSupportedException, CAExistsException, AuthorizationDeniedException, 
            CertificateProfileDoesNotExistException, CertificateProfileTypeNotAcceptedException, CryptoTokenOfflineException, InvalidAlgorithmException;
    
    /**
     * Adds an administrator to the specified role
     * 
     * @param admin
     * @param roleName The role to add the admin to
     * @param caName Name of the CA that issued the new administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue
     * @throws UnsupportedMethodException
     * @throws RoleNotFoundException
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    void addSubjectToRole(AuthenticationToken admin, String roleName, String caName, String matchWith, String matchType, 
            String matchValue) throws UnsupportedMethodException, RoleNotFoundException, CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Removes an administrator to the specified role
     * 
     * @param admin
     * @param roleName The role to add the admin to
     * @param caName Name of the CA that issued the new administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue
     * @throws UnsupportedMethodException
     * @throws RoleNotFoundException
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    void removeSubjectFromRole(AuthenticationToken admin, String roleName, String caName, String matchWith, String matchType, 
            String matchValue) throws UnsupportedMethodException, RoleNotFoundException, CADoesntExistsException, AuthorizationDeniedException;
}