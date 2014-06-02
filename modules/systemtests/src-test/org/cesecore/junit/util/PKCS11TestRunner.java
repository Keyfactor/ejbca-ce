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

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
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
        CaTestUtils.addCAUseSessionBeanToGenerateKeys2(x509ca, "CN=" + super.getName(), TOKEN_PIN);
    };

    @Override
    protected void afterClass() {
        try {
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
            if (x509ca != null) {
                final int caCryptoTokenId = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
                cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
                caSession.removeCA(alwaysAllowToken, x509ca.getCAId());
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getSubtype() {
        return "PKCS#11";
    };

    

}
