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
package org.cesecore.junit.util;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;

import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 *
 */
public class PKCS12TestRunner extends CryptoTokenRunner {
    
  
    protected static final String DEFAULT_TOKEN_PIN = "userpin1";
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            PKCS12TestRunner.class.getSimpleName()));

    public PKCS12TestRunner() {
    
    }
    
    @Override
    public X509CAInfo createX509Ca(String subjectDn, String caName) throws Exception {
        caSession.removeCA(alwaysAllowToken, DnComponents.stringToBCDNString(subjectDn).hashCode());
        X509CAInfo x509ca = createTestX509Ca(caName, subjectDn, DEFAULT_TOKEN_PIN.toCharArray(), true,
                getTokenImplementation(), CAInfo.SELFSIGNED, "1024", X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, "3650d");

        setCaForRemoval(x509ca.getCAId(), x509ca);
        return x509ca;
    }
    
    @Override
    public X509CAInfo createX509Ca(String subjectDn, String issuerDn, String caName, String validity) throws Exception {
        return createX509Ca(subjectDn, issuerDn, caName, validity, "1024", AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
    }
    
    @Override
    public X509CAInfo createX509Ca(String subjectDn, String issuerDn, String caName, String validity, 
            String keySpec, String signingAlgorithm) throws Exception {
        caSession.removeCA(alwaysAllowToken, DnComponents.stringToBCDNString(subjectDn).hashCode());
        X509CAInfo x509ca = createTestX509Ca(caName, subjectDn, DEFAULT_TOKEN_PIN.toCharArray(), true,
                getTokenImplementation(), subjectDn.equalsIgnoreCase(issuerDn) ? CAInfo.SELFSIGNED: issuerDn.hashCode(), 
                keySpec, X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign, validity, signingAlgorithm);

        setCaForRemoval(x509ca.getCAId(), x509ca);
        return x509ca;
    }

    @Override
    public String getNamingSuffix() {       
        return "pkcs12";
    }

    @Override
    public Integer createCryptoToken(final String tokenName) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException,
             NoSuchSlotException {
        try {
            int cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowToken, tokenName);
            setCryptoTokenForRemoval(cryptoTokenId);
            return cryptoTokenId;
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always Allow token was denied access.", e);
        }
       
    }

    @Override
    public boolean canRun() {
        //Can always run
        return true;
    }

    @Override
    public String getSimpleName() {
        return "PKCS12TestRunner";
    }
    
    @Override
    public String toString() {
        return getSimpleName();
    }

    @Override
    protected String getTokenImplementation() {
        return SoftCryptoToken.class.getName();
    }

}
