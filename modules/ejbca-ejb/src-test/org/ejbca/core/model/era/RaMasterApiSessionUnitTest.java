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
package org.ejbca.core.model.era;

import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.isNull;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.KeyStoreGeneralRaException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.test.EjbMocker;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 * Unit tests of {@link RaMasterApiSessionBean}
 */
public class RaMasterApiSessionUnitTest {

    private static final Integer MOCKED_EEP_ID = 111;
    private static final String MOCKED_USERNAME = "TestUser";
    private static final String MOCKED_PASSWORD = "foo123";
    private static final char[] MOCKED_PASSWORD_CHARS = MOCKED_PASSWORD.toCharArray();
    private static final int MOCKED_CAID = 222;

    private RaMasterApiSessionBean raMasterApi;
    private AuthenticationToken adminMock = EasyMock.createStrictMock(AuthenticationToken.class);
    private EndEntityInformation endEntityMock = EasyMock.createStrictMock(EndEntityInformation.class);
    private EndEntityManagementSessionLocal endEntityManagementSessionMock = EasyMock.createStrictMock(EndEntityManagementSessionLocal.class);
    private EndEntityProfileSessionLocal endEntityProfileSessionMock = EasyMock.createStrictMock(EndEntityProfileSessionLocal.class);
    private GlobalConfigurationSessionLocal globalConfigurationSessionMock = EasyMock.createStrictMock(GlobalConfigurationSessionLocal.class);
    private EndEntityAccessSessionLocal endEntityAccessSessionMock = EasyMock.createStrictMock(EndEntityAccessSessionLocal.class);
    private KeyStoreCreateSessionLocal keyStoreCreateSessionMock = EasyMock.createStrictMock(KeyStoreCreateSessionLocal.class);
    private SignSessionLocal signSessionMock = EasyMock.createStrictMock(SignSessionLocal.class);
    private GlobalConfiguration globalConfigurationMock = EasyMock.createStrictMock(GlobalConfiguration.class);
    private EndEntityProfile endEntityProfileMock = EasyMock.createStrictMock(EndEntityProfile.class);
    private ExtendedInformation extendedInfoMock = EasyMock.createStrictMock(ExtendedInformation.class);
    private Object[] allMocks = { adminMock, endEntityMock, endEntityManagementSessionMock, endEntityProfileSessionMock,
            globalConfigurationSessionMock, endEntityAccessSessionMock, keyStoreCreateSessionMock, signSessionMock,
            globalConfigurationMock, endEntityProfileMock, extendedInfoMock };
    private static final byte[] TEST_P12 = Base64.decode(
            ("MIIGQgIBAzCCBfsGCSqGSIb3DQEHAaCCBewEggXoMIIF5DCCATgGCSqGSIb3DQEHAaCCASkEggEl\n" +
            "MIIBITCCAR0GCyqGSIb3DQEMCgECoIHBMIG+MCkGCiqGSIb3DQEMAQMwGwQULpr2UN/t+2L1CGtZ\n" +
            "I/0wJ83PW0ICAwDIAASBkHpSwEa5wTF9Vv/E7ZNzF0+ydi0yw9Ew+R0RKb4SyEtVGtgAEEjpbQgu\n" +
            "9/yfHjWsgSOvXg5932Rit79IUQhOo6/4cgihnRVCTfvQKCj28bawznenzN7TplH1U2wRRAY/Ieeq\n" +
            "qwRfHMbdaztgoh4d91hB/1OuWdFwO/8WXF5N+IsnKICQQSGVq6P/ji2UCQRAvjFKMCMGCSqGSIb3\n" +
            "DQEJFDEWHhQAdABlAHMAdAAyADAAMAAzADIANzAjBgkqhkiG9w0BCRUxFgQU2+su6Zyz4d9fAmpW\n" +
            "JEFwGWfqD6cwggSkBgkqhkiG9w0BBwagggSVMIIEkQIBADCCBIoGCSqGSIb3DQEHATApBgoqhkiG\n" +
            "9w0BDAEGMBsEFAUPv8QiCkhONWQpFNMrEgrQjgy7AgMAyACAggRQbO6mk+K+0cpjYboUL1FeLK5Y\n" +
            "FPttzQELOlPw/jUnOVtpI0nk9DC37GvLJ1R0Rb2FLKwPGS8VQpRfmxPri5/UzJlFp+TLF8ior9P2\n" +
            "Tyiokmh4eZA7MD74oPLIVjFWmDeY8eG5V5EDbSqgkmqQeB8/eH3Z11g1ZWbWKDKeWdV+Rvia/viM\n" +
            "6LOlbuTpWcpcpZI+e+hNW7DKPkr7JRt+DlDaCQwD0bB5tGYX83M3Fc103NEIXUloqDqDKS+uvNbd\n" +
            "4AgeeHnhAd1QN/mzpfsybmHnWF/DgtEzwZ81RdoBz7L/I6szf4WKwD+RHbzIJlvSo2urjNBNhp1o\n" +
            "E6I3buUGT9uVo+8x5gVhm0PihVHBStd14WSs3+9Sgdm2KbUeJfIjgfsp7D3a1jFIIrPYZ2jcw1UC\n" +
            "jcwgegm7SJsixZKFZpLftoRw7CQo+XBTIkTeXLl6oCo5NHQgWil+fp8HgQNHlxQJwIOjaoCStiih\n" +
            "TZlA/x6772pl7IlJ1UeNVKcpicl2+FDw31hA/YEU/LPL+R4zxHssDBLE7/TUMGDaxqOZJd8HhW5b\n" +
            "USsLOLCtTcl7E5m+lvWHen7Yuic0KVdl8Pyzmg84+h+WU34GW0dkURBLP2rXxb+01PcdtMYeLcrE\n" +
            "22m6INvzRKCnuApM4k0uXRRzymKDUkm3YRoWUA2d+cwIAkRgv3iY9XmvL9mCHCfvKTEiazE+2V58\n" +
            "Nth5Lg11nntA3fimezcsjVMiqn9FU0Z/Mb8XAhHpLBUw0oi33yos9sRxB0QUVegTAI4hd63PNpnh\n" +
            "Fqji7c/IwiYD5VzPxPtt23jPRwnJ6RS8baZiMnC7vZTVD6H8SU6WSv2ZTA7ugbbWhadv5T/DIrMq\n" +
            "8CtLfzwcNKxw5Kk5+zzNVLENyNJAYYlEX2a9pYDAPExK4Boj5fMx83A6RyTms3kO9AIM1ASadffv\n" +
            "RMkjqEI6/EHiZjXSeBv02irAiNDgRaZIAnJk6mUXRU21AFZu/gp+CIWcR0659Iff8GM/oxgBoqL1\n" +
            "bHXWGmQY/PBsiLB8M+946ZqJ5vBLTObveklaPuDMmBs2UJbx87jypRiMtIcQ/KFrBDuaVEyKBKFa\n" +
            "lSJ6SnnmUYXXp/AwfQtvihfbpn9W5yVCT0SP+skId/BVpW6vdtAo8AzQulTL/YR5aNTwsSGfSHbc\n" +
            "nZhOfmtJOnJQOsnGlo8AxM/ESt+XffE6s/J9mlR4WTjOd6SEI3fGowREJmLniN2Ev8x6peMok+LD\n" +
            "6GEOCYqNfbgAAgijbAuvKUr+vbmfMske/+B0DwD+KdcNReof3hXDJ65WN8JlR0cP0hMNqI7KnzTI\n" +
            "SbYM0p2dOcFPv2wjjqVwuATMcMgrbMSysvSMoqJnu4Z6tdb6pLFwO6U8uLOjU1lxpwNj4+CRPt3O\n" +
            "fpa0dJPhy84gmsJxsLZ7jFcIW5gh+LwaU1JEksr5XEXw6i8663mX9cbepCE+BZgPxblYBsy/Od5a\n" +
            "ZLf4MD4wITAJBgUrDgMCGgUABBQYQu81WoE7iaMkZil93MWZuJ1OaQQUkPdFkaza0I7/Pr4Di48W\n" +
            "6oBLaXMCAwGQAA==").getBytes(StandardCharsets.US_ASCII));

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void before() {
        final EjbMocker<RaMasterApiSessionBean> mocker = new EjbMocker<>(RaMasterApiSessionBean.class);
        mocker.addMockedInjections(endEntityManagementSessionMock, endEntityProfileSessionMock, globalConfigurationSessionMock,
                endEntityAccessSessionMock, keyStoreCreateSessionMock, signSessionMock);
        raMasterApi = mocker.construct();
    }

    /** {@link EasyMock#expect} calls for addUserAndGenerateKeyStore, up until generateOrKeyRecoverToken */
    private void expectAddUserAndGenerateKeystorePreparations()
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, IllegalNameException, CustomFieldException, ApprovalException, CertificateSerialNumberException {
        expect(endEntityManagementSessionMock.addUser(same(adminMock), same(endEntityMock), eq(false))).andReturn(endEntityMock);
        expect(endEntityMock.getEndEntityProfileId()).andReturn(MOCKED_EEP_ID);
        expect(endEntityProfileSessionMock.getEndEntityProfile(MOCKED_EEP_ID)).andReturn(endEntityProfileMock);
        expect(globalConfigurationSessionMock.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).andReturn(globalConfigurationMock);
        expect(globalConfigurationMock.getEnableKeyRecovery()).andReturn(false);
        expect(endEntityMock.getUsername()).andReturn(MOCKED_USERNAME);
        expect(endEntityAccessSessionMock.findUser(MOCKED_USERNAME)).andReturn(endEntityMock); // this call could possibly be optimized away
        expect(endEntityMock.getKeyRecoverable()).andReturn(false);
        expect(endEntityProfileMock.getReUseKeyRecoveredCertificate()).andReturn(false);
        expect(endEntityMock.getStatus()).andReturn(EndEntityConstants.STATUS_NEW);
        expect(endEntityMock.getExtendedInformation()).andReturn(extendedInfoMock);
        expect(extendedInfoMock.getCertificateEndTime()).andReturn(null);
        // Parameters to invocation of generateOrKeyRecoverToken
        expect(endEntityMock.getUsername()).andReturn(MOCKED_USERNAME);
        expect(endEntityMock.getPassword()).andReturn(MOCKED_PASSWORD);
        expect(endEntityMock.getCAId()).andReturn(MOCKED_CAID);
        expect(endEntityMock.getExtendedInformation()).andReturn(extendedInfoMock);
        expect(extendedInfoMock.getKeyStoreAlgorithmSubType()).andReturn(AlgorithmConstants.KEYALGORITHM_ED25519);
        expect(endEntityMock.getExtendedInformation()).andReturn(extendedInfoMock);
        expect(extendedInfoMock.getKeyStoreAlgorithmType()).andReturn(AlgorithmConstants.SIGALG_ED25519);
        expect(endEntityMock.getTokenType()).andReturn(EndEntityConstants.TOKEN_SOFT_P12);
        expect(endEntityMock.getEndEntityProfileId()).andReturn(MOCKED_EEP_ID);
    }

    /** Test of successful call to addUserAndGenerateKeyStore, without any special features/parameters */
    @Test
    public void addUserAndGenerateKeyStoreNormal() throws Exception {
        expectAddUserAndGenerateKeystorePreparations();
        expect(keyStoreCreateSessionMock.generateOrKeyRecoverTokenWithoutViewEndEntityAccessRule(same(adminMock),
                    eq(MOCKED_USERNAME), // Username
                    eq(MOCKED_PASSWORD),
                    eq(MOCKED_CAID),
                    eq(AlgorithmConstants.KEYALGORITHM_ED25519),
                    eq(AlgorithmConstants.SIGALG_ED25519),
                    isNull(), // No notAfter
                    isNull(), // No notBefore
                    eq(EndEntityConstants.TOKEN_SOFT_P12), // Type of token
                    eq(false), // Perform key recovery?
                    eq(false), // Save private keys?
                    eq(false), // Reuse recovered cert?
                    eq(MOCKED_EEP_ID))).andReturn(getDummyKeyStore());
        // Encoding of keystore
        expect(endEntityMock.getTokenType()).andReturn(EndEntityConstants.TOKEN_SOFT_P12);
        expect(endEntityMock.getPassword()).andReturn(MOCKED_PASSWORD);
        replay(allMocks);
        assertNotNull("Returned byte array was null", raMasterApi.addUserAndGenerateKeyStore(adminMock, endEntityMock, false));
        verify(allMocks);
    }

    /** Test of error cleanup in addUserAndGenerateKeyStore */
    @Test
    public void addUserAndGenerateKeyStoreErrorHandling() throws Exception {
        expectAddUserAndGenerateKeystorePreparations();
        expect(keyStoreCreateSessionMock.generateOrKeyRecoverTokenWithoutViewEndEntityAccessRule(same(adminMock),
                    eq(MOCKED_USERNAME), // Username
                    eq(MOCKED_PASSWORD),
                    eq(MOCKED_CAID),
                    eq(AlgorithmConstants.KEYALGORITHM_ED25519),
                    eq(AlgorithmConstants.SIGALG_ED25519),
                    isNull(), // No notAfter
                    isNull(), // No notBefore
                    eq(EndEntityConstants.TOKEN_SOFT_P12), // Type of token
                    eq(false), // Perform key recovery?
                    eq(false), // Save private keys?
                    eq(false), // Reuse recovered cert?
                    eq(MOCKED_EEP_ID)))
                .andThrow(new CertificateSerialNumberException("Simulated exception"));
        // Expect cleanup after error
        expect(endEntityMock.getUsername()).andReturn(MOCKED_USERNAME);
        endEntityManagementSessionMock.deleteUser(
                eq(new AlwaysAllowLocalAuthenticationToken("Failed Enrollment Cleanup")),
                eq(MOCKED_USERNAME));
        expectLastCall().andVoid();
        replay(allMocks);
        try {
            raMasterApi.addUserAndGenerateKeyStore(adminMock, endEntityMock, false);
            fail("Expected an exception");
        } catch (KeyStoreGeneralRaException e) {
            // NOPMD Expected
        }
        verify(allMocks);
    }

    private KeyStore getDummyKeyStore() {
        try {
            final KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            try (final InputStream is = new ByteArrayInputStream(TEST_P12)) {
                ks.load(is, MOCKED_PASSWORD_CHARS);
            }
            return ks;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
