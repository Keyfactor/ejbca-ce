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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EndEntityProfileNotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * This test class collects WS tests that have to do with DN Fields.
 * 
 * @version $Id$
 *
 */
public class DnFieldsTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(DnFieldsTest.class);
    
    private static final String PROFILE_NAME = "TW";
    private static final String TEST_USERNAME = "tester";
    
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("DnFieldsTest"));
    
    private final String wsadminRoleName = "WsTEstRole";
    
    @BeforeClass
    public static void beforeClass() {
        adminBeforeClass();
    }
 
    @Before
    public void setUp() throws Exception {
        setupAccessRights(wsadminRoleName);
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
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        super.cleanUpAdmins(wsadminRoleName);
        
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
    public void testEmailInBothSanAndDn() throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, AuthorizationDeniedException_Exception, EjbcaException_Exception, IllegalQueryException_Exception,
            InvalidKeyException, SignatureException, ApprovalException_Exception, CADoesntExistsException_Exception, NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, IOException, OperatorCreationException, EndEntityProfileNotFoundException_Exception {

        UserMatch um = new UserMatch(UserMatch.MATCH_WITH_USERNAME, UserMatch.MATCH_TYPE_EQUALS, "tomcat");
        for (UserDataVOWS ud : ejbcaraws.findUser(um)) {
            log.info("User: " + ud.getSubjectDN());
        }

        String caname = null;
        CaSession caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        List<String> cas = caSession.getActiveCANames(internalAdmin);
        if(cas.contains("ManagementCA")) {
            caname = "ManagementCA";
        } else {
            caname = "AdminCA1";
        }
        
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        String p10 = new String(Base64.encode(CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"), keys
                .getPublic(), new DERSet(), keys.getPrivate(), null).toASN1Structure().getEncoded()));
        UserDataVOWS user = new UserDataVOWS();
        user.setUsername(TEST_USERNAME);
        user.setPassword("foo123");
        user.setClearPwd(false);
        user.setSubjectDN("E=boss@fire.com,CN=Tester,C=SE");
        user.setCaName(caname);
        user.setSubjectAltName("rfc822name=boss@fire.com");
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setEndEntityProfileName(PROFILE_NAME);
        user.setCertificateProfileName(PROFILE_NAME);
        ejbcaraws.certificateRequest(user, p10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE)
                .getRawData();

    }

    @Override
    public String getRoleName() {
        return DnFieldsTest.class.getSimpleName();
    }

}
