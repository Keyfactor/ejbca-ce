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
package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertTrue;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;

/**
 * @version $Id$
 *
 */
@RunWith(CryptoTokenTestRunner.class)
public class SignSessionSigningTest {

    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();
    
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("SignSessionSigningTest");

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private X509CA x509ca;
    
    @Before
    public void setUp() throws Exception {
        x509ca = cryptoTokenRule.createX509Ca(); 
    }
    
    @After
    public void tearDown() throws Exception {
        cryptoTokenRule.cleanUp();
    }
    
    /**
     * This test attempts to sign a payload (as a byte array) using the CA cert 
     */
    @Test
    public void testSignPayload() throws CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException, CertificateException, CMSException, OperatorCreationException {
        byte[] payload = new byte[]{1, 2, 3, 4};
        X509Certificate cacert =  (X509Certificate) x509ca.getCACertificate();
        //Have the data signed using the CA's signing keys
        CMSSignedData signedData = new CMSSignedData(signSession.signPayload(internalAdmin, payload, x509ca.getCAId()));
        //Construct a signer in order to verify the change
        SignerInformation signer = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME); 
        assertTrue("Payload signature couldnt be verified.", signer.verify(jcaSignerInfoVerifierBuilder.build(cacert.getPublicKey())));
        
    }

}
