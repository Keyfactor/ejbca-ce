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
package org.cesecore.certificates.crl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Test class for testing CRL related extensions.
 */
public class CrlExtensionSystemTest {
    
    private final String EXPIRED_CERT_ON_CRL_OID = "2.5.29.60";
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(CrlExtensionSystemTest.class.getSimpleName());

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    
    @Rule
    public TestName testName = new TestName();
    
    @BeforeClass
    public static void setUpProvider() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setup() throws InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException, IllegalStateException,
            OperatorCreationException, CAExistsException, CertIOException, AuthorizationDeniedException {
        CaTestUtils.createActiveX509Ca(alwaysAllowToken, testName.getMethodName(), testName.getMethodName(), "CN="+testName.getMethodName());
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException {
        CaTestUtils.removeCa(alwaysAllowToken, testName.getMethodName(), testName.getMethodName());
    }
    
    
    /**
     * The ExpiredCertsOnCRL extension adds an extension (OID 2.5.29.60) which states the first date for which
     * the CRL will have an expired certificate declared on it. 
     * 
     * Default behavior in EJBCA is to use the CA's notBefore date
     */
    @Test
    public void testKeepExpiredCertificatesOnCrlCaDate()
            throws AuthorizationDeniedException, CADoesntExistsException, InternalKeyBindingNonceConflictException,
            CaMsCompatibilityIrreversibleException, CryptoTokenOfflineException, CAOfflineException, CRLException, IOException {
        //Retrieve the CA and activate the extension.
        X509CAInfo x509caInfo = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, testName.getMethodName());
        x509caInfo.setKeepExpiredCertsOnCRL(true);
        // date = 0 means to use the CA's notBefore date
        x509caInfo.setKeepExpiredCertsOnCRLDate(0);
        caSession.editCA(alwaysAllowToken, x509caInfo);
        try {
        //Force a CRL 
        publishingCrlSession.forceCRL(alwaysAllowToken, x509caInfo.getCAId());
        //Let's check it out
        byte[] crlBytes = crlStoreSession.getLastCRL(x509caInfo.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crlBytes);
        byte[] extensionValue = x509crl.getExtensionValue(EXPIRED_CERT_ON_CRL_OID);                
        System.err.println(new String(extensionValue));        
        
        } finally {
            crlStoreSession.removeByIssuerDN(x509caInfo.getSubjectDN());
        }
    }
    


    


}
