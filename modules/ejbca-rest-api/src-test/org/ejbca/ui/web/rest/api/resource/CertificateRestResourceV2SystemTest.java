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
package org.ejbca.ui.web.rest.api.resource;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.rest.api.resource.util.CertificateRestResourceSystemTestUtil;
import org.ejbca.ui.web.rest.api.resource.util.TestEndEntityParamHolder;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.Optional;
import java.util.Random;

import static org.junit.Assert.assertEquals;

/**
 * A system test class for the {@link CertificateRestResourceV2} to test its content.
 */
public class CertificateRestResourceV2SystemTest extends RestResourceSystemTestBase {

    private static final Random RANDOM = new Random();
    private static final JSONParser JSON_PARSER = new JSONParser();

    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private CertificateRestResourceSystemTestUtil certificateRestResourceSystemTestUtil = new CertificateRestResourceSystemTestUtil();

    private X509CA x509TestCa;
    private String testCaName = "CertificateRestSystemTestCa";
    private String testIssuerDn = "C=SE,CN=" + testCaName;
    private String testUsername = "CertificateRestSystemTestUser";
    private String testCertProfileName = "CertificateRestSystemTestCertProfile";
    private String testEeProfileName = "CertificateRestSystemTestEeProfile";

    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @Before
    public void setUp() throws Exception {
        final int randomSuffix = RANDOM.nextInt();
        testCaName += randomSuffix;
        testIssuerDn += randomSuffix;
        testUsername += randomSuffix;
        testCertProfileName += randomSuffix;
        testEeProfileName += randomSuffix;
        CryptoProviderTools.installBCProvider();
        x509TestCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(INTERNAL_ADMIN_TOKEN, testIssuerDn);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (x509TestCa != null) {
            CaTestUtils.removeCa(INTERNAL_ADMIN_TOKEN, x509TestCa.getCAInfo());
        }
        try {
            endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, testUsername);
        } catch (Exception e) {
            // ignore
        }
        internalCertificateStoreSession.removeCertificatesByUsername(testUsername);
        certificateProfileSession.removeCertificateProfile(INTERNAL_ADMIN_TOKEN, testCertProfileName);
        endEntityProfileSessionRemote.removeEndEntityProfile(INTERNAL_ADMIN_TOKEN, testEeProfileName);
    }

    @Test
    public void shouldGetIssuedCertificateCount() throws Exception {
		//given
        certificateRestResourceSystemTestUtil.createTestEndEntity(TestEndEntityParamHolder.newBuilder()
                        .withTestCertProfileName(testCertProfileName)
                        .withInternalAdminToken(INTERNAL_ADMIN_TOKEN)
                        .withTestUsername(testUsername)
                        .withX509TestCa(x509TestCa)
                        .withTestEeProfileName(testEeProfileName)
                        .withCertificateProfileSession(certificateProfileSession)
                        .withEndEntityManagementSession(endEntityManagementSession)
                        .withEndEntityProfileSessionRemote(endEntityProfileSessionRemote)
                .build());

		//when
		final Response actualResponse = newRequest("/v2/certificate/count").request().get();

		//then
		final String actualJsonString = actualResponse.readEntity(String.class);
		final JSONObject actualJsonObject = (JSONObject) JSON_PARSER.parse(actualJsonString);
		final Long count = (Long) actualJsonObject.get("count");
		assertEquals(Optional.of(2L), Optional.of(count));
	}

    @Test
    public void shouldGetActiveCertificateCount() throws Exception {
		//given
        certificateRestResourceSystemTestUtil.createTestEndEntity(TestEndEntityParamHolder.newBuilder()
                .withTestCertProfileName(testCertProfileName)
                .withInternalAdminToken(INTERNAL_ADMIN_TOKEN)
                .withTestUsername(testUsername)
                .withX509TestCa(x509TestCa)
                .withTestEeProfileName(testEeProfileName)
                .withCertificateProfileSession(certificateProfileSession)
                .withEndEntityManagementSession(endEntityManagementSession)
                .withEndEntityProfileSessionRemote(endEntityProfileSessionRemote)
                .build());

		//when
		final Response actualResponse = newRequest("/v2/certificate/count?isActive=true").request().get();

		//then
		final String actualJsonString = actualResponse.readEntity(String.class);
		final JSONObject actualJsonObject = (JSONObject) JSON_PARSER.parse(actualJsonString);
		final Long count = (Long) actualJsonObject.get("count");
		assertEquals(Optional.of(2L), Optional.of(count));
	}

}
