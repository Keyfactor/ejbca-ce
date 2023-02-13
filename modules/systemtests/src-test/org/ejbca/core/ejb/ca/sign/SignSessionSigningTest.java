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
import static org.junit.Assume.assumeTrue;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 *
 */
@RunWith(Parameterized.class)
public class SignSessionSigningTest {
    
    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
       return CryptoTokenRunner.defaultRunners;
    }
    
    private final SignProxySessionRemote signProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private X509CAInfo x509ca;
    
    private CryptoTokenRunner cryptoTokenRunner;
    
    public SignSessionSigningTest(CryptoTokenRunner cryptoTokenRule) {
        this.cryptoTokenRunner = cryptoTokenRule;
    }
    
    @Before
    public void setUp() throws Exception {
        assumeTrue("Test with runner " + cryptoTokenRunner.getSimpleName() + " cannot run on this platform.", cryptoTokenRunner.canRun());
        x509ca = cryptoTokenRunner.createX509Ca(); 
    }
    
    @After
    public void tearDown() throws Exception {
        cryptoTokenRunner.cleanUp();
    }
    
    /**
     * This test attempts to sign a payload (as a byte array) using the CA cert 
     */
    @Test
    public void testSignPayload() throws CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException, CertificateException, CMSException, OperatorCreationException {
        byte[] payload = new byte[]{1, 2, 3, 4};
        X509Certificate cacert =  (X509Certificate) x509ca.getCertificateChain().get(0);
        //Have the data signed using the CA's signing keys
        CMSSignedData signedData = new CMSSignedData(signProxySession.signPayload(payload, x509ca.getCAId()));
        //Construct a signer in order to verify the change
        SignerInformation signer = (SignerInformation) signedData.getSignerInfos().getSigners().iterator().next();
        JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME); 
        assertTrue("Payload signature couldnt be verified.", signer.verify(jcaSignerInfoVerifierBuilder.build(cacert.getPublicKey())));
        
    }

}
