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
package org.cesecore.junit.util;

import java.security.InvalidKeyException;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.runners.model.InitializationError;

/**
 * @version $Id$
 *
 */
public class PKCS11TestRunner extends CryptoTokenTestRunner {

    private static final String TOKEN_PIN = "userpin1";
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            PKCS11TestRunner.class.getSimpleName()));

    public PKCS11TestRunner(Class<?> klass) throws InitializationError {
        super(klass);

    }

    @Override
    protected void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        cryptoTokenId = CryptoTokenTestUtils.createPKCS11Token(alwaysAllowToken, super.getName(), true);
        x509ca = CaTestUtils.createTestX509CAOptionalGenKeys("CN=" + super.getName(), TOKEN_PIN.toCharArray(), false, true);
        CAToken caToken = x509ca.getCAToken();
        caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signKeyAlias");
        caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signKeyAlias");
        x509ca.setCAToken(caToken);
        caSession.addCA(alwaysAllowToken, x509ca);
        final int cryptoTokenId = caToken.getCryptoTokenId();
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, "signKeyAlias", "1024");
    };

    @Override
    protected void afterClass() {
        try {
            try {
                cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, "signKeyAlias");
            } catch (InvalidKeyException e) {
                throw new IllegalStateException(e);
            } catch (CryptoTokenOfflineException e) {
                throw new IllegalStateException(e);
            }
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
            if (x509ca != null) {
                CAInfo caInfo;
                try {
                    caInfo = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId());
                    final int caCryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
                    cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
                    caSession.removeCA(alwaysAllowToken, x509ca.getCAId());
                } catch (CADoesntExistsException e) {
                    // NOPMD Ignore
                }      
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        } 
    }

    @Override
    public String getSubtype() {
        return "PKCS#11";
    };

    

}
