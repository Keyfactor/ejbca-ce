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
import java.util.HashMap;
import java.util.Properties;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.token.p11.exception.PKCS11LibraryFileNotFoundException;
import org.ejbca.core.EjbcaException;

/**
 * JEE5 Lookup helper implementation for optional (enterprise edition) WS methods.
 * 
 * @version $Id$
 */
@Local
public interface EnterpriseEditionWSBridgeSessionLocal {

    void createCryptoToken(AuthenticationToken admin, String tokenName, String tokenType, String activationPin, boolean autoActivate, 
            boolean exportKey, String pkcs11LibFilename, String pkcs11SlotLabelType, String pkcs11SlotPropertyValue,
            HashMap<String, String> PKCS11AttributeData) throws UnsupportedMethodException, AuthorizationDeniedException, 
            EjbcaException, UnsupportedMethodException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, 
            CryptoTokenNameInUseException, NoSuchSlotException, PKCS11LibraryFileNotFoundException;
    
    void generateCryptoTokenKeys(AuthenticationToken admin, String cryptoTokenName, String keyPairAlias, String keySpecification) 
            throws UnsupportedMethodException, InvalidKeyException, CryptoTokenOfflineException, InvalidAlgorithmParameterException, 
            AuthorizationDeniedException;
    
    void createCA(AuthenticationToken admin, String caname, String cadn, String catype, String catokentype, String catokenpassword, 
            Properties catokenProperties, String cryptoTokenName, String cryptotokenKeyAlias, long validityInDays, String certprofile, 
            String signAlg, String policyId, int signedByCAId) throws UnsupportedMethodException, 
            SignedByExternalCANotSupportedException, CAExistsException, AuthorizationDeniedException, 
            CertificateProfileDoesNotExistException, ProfileTypeNotAcceptedException, CryptoTokenOfflineException, InvalidAlgorithmException;
}