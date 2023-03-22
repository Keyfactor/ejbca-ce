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

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 *
 */
public abstract class HardtokenTestRunnerBase extends CryptoTokenRunner {

    protected static final String DEFAULT_TOKEN_PIN = "userpin1";
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            HardtokenTestRunnerBase.class.getSimpleName()));
    
    @Override
    public Integer createCryptoToken(final String tokenName)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException {
        int cryptoTokenId = createCryptoToken(SystemTestsConfiguration.getPkcs11SlotPin(DEFAULT_TOKEN_PIN), getTokenImplementation(),
                tokenName);
        setCryptoTokenForRemoval(cryptoTokenId);
        return cryptoTokenId;

    }

    @Override
    public X509CAInfo createX509Ca(String subjectDn, String caName) throws Exception {
        caSession.removeCA(alwaysAllowToken, CertTools.stringToBCDNString(subjectDn).hashCode());
        X509CAInfo x509ca = createTestX509Ca(caName, subjectDn, SystemTestsConfiguration.getPkcs11SlotPin(DEFAULT_TOKEN_PIN), true,
                getTokenImplementation(), CAInfo.SELFSIGNED, "1024", X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);

        setCaForRemoval(x509ca.getCAId(), x509ca);
        
        return x509ca;
    }
    

}
