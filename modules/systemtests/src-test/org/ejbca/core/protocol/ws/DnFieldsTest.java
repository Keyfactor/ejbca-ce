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
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * 
 * This test class collects WS tests that have to do with DN Fields.
 * 
 * @version $Id$
 *
 */
public class DnFieldsTest extends CommonEjbcaWs {

    private static final Logger log = Logger.getLogger(DnFieldsTest.class);
    
    private static final String PROFILE_NAME = "TW";
    private static final String TEST_USERNAME = "tester";
    private static final String TEST_SUBJECTDN = "E=test@example.com,CN=DnFieldsTest,C=SE";
    private static final String TEST_SUBJECTALTNAME = "rfc822name=test@example.com";
    
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("DnFieldsTest"));
    


    
    private static List<File> fileHandles = new ArrayList<>();

    
    @BeforeClass
    public static void beforeClass() throws Exception {
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);

    }
    
    @AfterClass
    public static void afterClass() {
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }
 
    @Override
    @Before
    public void setUp() throws Exception {
        
        adminSetUpAdmin();
        
        if(certificateProfileSession.getCertificateProfile(PROFILE_NAME) == null) {
            certificateProfileSession.addCertificateProfile(internalAdmin, PROFILE_NAME, new CertificateProfile());
        }
        
        EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.addField(DnComponents.DNEMAILADDRESS);
        endEntityProfile.addField(DnComponents.COUNTRY);
        endEntityProfile.addField(DnComponents.RFC822NAME);     
        endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certificateProfileSession.getCertificateProfileId(PROFILE_NAME)));
        endEntityProfile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        if (endEntityProfileSession.getEndEntityProfile(PROFILE_NAME) == null) {
            endEntityProfileSession.addEndEntityProfile(internalAdmin, PROFILE_NAME, endEntityProfile);
        }
      
       
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        
        if (endEntityManagementSession.existsUser(TEST_USERNAME)) {
            // Remove user
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }

        if (endEntityProfileSession.getEndEntityProfile(PROFILE_NAME) != null) {
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, PROFILE_NAME);
        }
        if(certificateProfileSession.getCertificateProfile(PROFILE_NAME) != null) {
            certificateProfileSession.removeCertificateProfile(internalAdmin, PROFILE_NAME);
        }
    }
    
    @Test
    public void testEmailInBothSanAndDn() throws Exception {
        UserMatch um = new UserMatch(UserMatch.MATCH_WITH_USERNAME, UserMatch.MATCH_TYPE_EQUALS, "tomcat");
        for (UserDataVOWS ud : ejbcaraws.findUser(um)) {
            log.info("User: " + ud.getSubjectDN());
        }

        final String caName = CaTestUtils.getClientCertCaName(internalAdmin);
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String p10 = new String(Base64.encode(CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"), keys
                .getPublic(), new DERSet(), keys.getPrivate(), null).toASN1Structure().getEncoded()));
        UserDataVOWS user = new UserDataVOWS();
        user.setUsername(TEST_USERNAME);
        user.setPassword("foo123");
        user.setClearPwd(false);
        user.setSubjectDN(TEST_SUBJECTDN);
        user.setCaName(caName);
        user.setSubjectAltName(TEST_SUBJECTALTNAME);
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setEndEntityProfileName(PROFILE_NAME);
        user.setCertificateProfileName(PROFILE_NAME);
        final CertificateResponse resp = ejbcaraws.certificateRequest(user, p10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        assertNotNull("Response was null", resp);
        assertNotNull("Data was null", resp.getRawData());
        final X509Certificate cert = resp.getCertificate();
        assertNotNull("Certificate was null", cert);
        assertEquals("Wrong Subject DN.", TEST_SUBJECTDN, CertTools.getSubjectDN(cert));
        assertEquals("Wrong Subject Alternative Name.", TEST_SUBJECTALTNAME, CertTools.getSubjectAlternativeName(cert));
    }

    @Override
    public String getRoleName() {
        return DnFieldsTest.class.getSimpleName();
    }

}
