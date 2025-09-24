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

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.junit.util.PKCS12TestRunner;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Tests the PKCS7-related methods in SignSessionBen
 */
@RunWith(Parameterized.class)
public class SignSessionPkcs7SystemTest {
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @Rule
    public TestName testName = new TestName();
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignSessionPkcs7SystemTest"));
    
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    
    private CryptoTokenRunner cryptoTokenRunner;
    private X509CAInfo x509ca;
    
    
    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
       return Arrays.asList(new PKCS12TestRunner());
    }
    
    public SignSessionPkcs7SystemTest(CryptoTokenRunner cryptoTokenRule) {
        this.cryptoTokenRunner = cryptoTokenRule;
    }
    
    @Before
    public void setUp() throws Exception {
        x509ca = cryptoTokenRunner.createX509Ca("CN="+testName.getMethodName(), testName.getMethodName()); 
    }
    
    @After
    public void tearDown() throws Exception {
        cryptoTokenRunner.cleanUp();
    }
    
    /**
     * Test requesting the CA's chain as a PKCS#7
     * 
     */
    @Test
    public void testPkcs7OfCa() throws CADoesntExistsException, AuthorizationDeniedException, CMSException, CertificateException, StoreException {
        byte[] pkcs7 = signSession.createPKCS7(internalAdmin, x509ca.getCAId(), true);
        CMSSignedData cmsSignedData = new CMSSignedData(pkcs7);
        Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
        List<X509Certificate> certificates = CertTools.convertToX509CertificateList(store.getMatches(null));
        assertEquals("Wrong certificate was returned.", CertTools.getSerialNumber(x509ca.getCertificateChain().get(0)),
                CertTools.getSerialNumber(certificates.get(0)));
    }

    @Test(expected = CADoesntExistsException.class)
    public void testPkcs7MissingCa() throws CADoesntExistsException, AuthorizationDeniedException {
        signSession.createPKCS7(internalAdmin, 1234, true);
    }
    
    @Test
    public void testPkcs7FromCertificate()
            throws EndEntityExistsException, CADoesntExistsException, IllegalNameException, CustomFieldException, ApprovalException,
            CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            InvalidAlgorithmParameterException, IllegalKeyException, CertificateCreateException, CertificateRevokeException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException, NoSuchEndEntityException, SignRequestSignatureException, CMSException, CertificateException, StoreException {
        final String username = "testPkcs7FromCertificateEndEntity";
        final String password = "foo123";
        final EndEntityInformation endEntity = new EndEntityInformation(username,  "CN="+username, x509ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, null);
        endEntity.setPassword("foo123");
        endEntityManagementSession.addUser(internalAdmin, endEntity, false);
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate eeCertificate = (X509Certificate) signSession.createCertificate(internalAdmin, username, password, new PublicKeyWrapper(keys.getPublic()));

        try {
            byte[] pkcs7 = signSession.createPKCS7(internalAdmin, eeCertificate, true);
            CMSSignedData cmsSignedData = new CMSSignedData(pkcs7);
            Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
            List<X509Certificate> certificates = CertTools.convertToX509CertificateList(store.getMatches(null));
            assertEquals("Wrong certificate was returned.", CertTools.getSerialNumber(eeCertificate),
                    CertTools.getSerialNumber(certificates.get(0)));
        } finally {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (NoSuchEndEntityException | AuthorizationDeniedException | CouldNotRemoveEndEntityException e) {
                //Ignore
            }
            internalCertificateStoreSessionRemote.removeCertificate(eeCertificate);
        }
    }
    
    /**
     * getPkcs7 is supposed to throw a signature exception if the certificate being asked for wasn't issued by the CA specified
     */
    @Test(expected = CADoesntExistsException.class)
    public void testPkcs7SignatureException() throws InvalidAlgorithmParameterException, CertificateParsingException, OperatorCreationException,
            CertIOException, AuthorizationDeniedException, CADoesntExistsException {
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final X509Certificate fakeCertificate = SimpleCertGenerator.forTESTLeafCert()
                .setSelfSignKeyPair(keys)
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                .generateCertificate();
        signSession.createPKCS7(internalAdmin, fakeCertificate, true);
    }
    
}
