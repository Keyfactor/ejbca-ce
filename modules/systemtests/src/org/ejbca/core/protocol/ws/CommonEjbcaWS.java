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
package org.ejbca.core.protocol.ws;

import java.io.File;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.ejb.CreateException;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.CVCCAInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.DummyCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.protocol.CVCRequestMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.ErrorCode;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.HardTokenExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.PinDataWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;
import org.ejbca.util.TestTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;

/**
 * 
 * @version $Id$
 */
public abstract class CommonEjbcaWS extends TestCase {

    private static final Logger log = Logger.getLogger(CommonEjbcaWS.class);

    public final static String TEST_ADMIN_USERNAME = "wstest";
    public final static String TEST_NONADMIN_USERNAME = "wsnonadmintest";
    public final static String TEST_NONADMIN_CN = "CN=wsnonadmintest";

    protected EjbcaWS ejbcaraws;

    protected final static Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
    protected final static String hostname;
    protected final static String httpsPort;
    
    private static final String SPCAK = "MIICSjCCATIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbiUJ4Q7a9"
        + "oaSaHjv4GxYWFTJ3qv1dUmpnEXvIwdWps9W2HHWNki9VzsbT2dBck3kISU7MBCI/" + "J4xgL5I766r4rdvXjy6w9K3pvXcyi+odTngxw8zU1PaKWONcAm7ulDEAiAzM3boM"
        + "/TGnF+0EzPU6mUv/cWfOICDdhFkGuAscKdewdWvJn6zJpizbgVimewM0p8QDHsoS" + "elap2stD9TPP+KKf3dZGN0NcmndTbtoPxyBgXCQZJfavFP7FLpAgC3EKVWLqtRij"
        + "5PBmYEMzd306/hSEECp4kJZi704p5pCMgzC9/3086AuAo+VEMDalsd0GwUan4YFi" + "G+I/CTHq8AszAgMBAAEWCjExMjU5ODMwMjEwDQYJKoZIhvcNAQEEBQADggEBAK/D"
        + "JcXBf2SESg/gguctpDn/z1uueuzxWwaHeD25WBUeqrdNOsGEqGarKP/Xtw2zPO9f" + "NSJ/AtxaNXRLUL0qpGgbhuclX4qJk4+rYAdlse9S2uJFIZEn41qLO1uoygvdoKZh"
        + "QJN3EABQ5QJP3R3Mhiu2tEtUuZ5zPq3vd/RBoOx5JbzZ1WZdk+dPbqdhyjsCy5ne" + "EkXFB6zflvR1fRrIxhDD0EnylHP1fz2p2kj2nOaQI6vQBH9CgTwkrAGEhy/Iq8aU"
        + "slAJUoE1+eCkUN/RHm/Z5XaZ2Le4BnjaDRTWJIglAUvFhuCEm7qCi1/bMof8V9Md" + "IP7NsueJRV9KvzdA7y0=";
    
    private static final String CRMF = "MIIBdjCCAXIwgdkCBQCghr4dMIHPgAECpRYwFDESMBAGA1UEAxMJdW5kZWZpbmVk"
        + "poGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCi6+Bmo+0I/ye8k6B6BkhXgv03" + "1jEeD3mEuvjIEZUmmdt2RBvW2qfJzqXV8dsI1HZT4fZqo8SBsrYls4AC7HooWI6g"
        + "DjSyd3kFcb5HP+qnNlz6De/Ab+qAF1rLJhfb2cXib4C7+bap2lwA56jTjY0qWRYb" + "v3IIfxEEKozVlbg0LQIDAQABqRAwDgYDVR0PAQH/BAQDAgXgoYGTMA0GCSqGSIb3"
        + "DQEBBQUAA4GBAJEhlvfoWNIAOSvFnLpg59vOj5jG0Urfv4w+hQmtCdK7MD0nyGKU" + "cP5CWCau0vK9/gikPoA49n0PK81SPQt9w2i/A81OJ3eSLIxTqi8MJS1+/VuEmvRf"
        + "XvedU84iIqnjDq92dTs6v01oRyPCdcjX8fpHuLk1VA96hgYai3l/D8lg";  

    private static final String BADCANAME = "BadCaName";

    private static final String CA1_WSTESTUSER1 = "CA1_WSTESTUSER1";
    private static final String CA1_WSTESTUSER2 = "CA1_WSTESTUSER2";
    private static final String CA2_WSTESTUSER1 = "CA2_WSTESTUSER1";
    protected static final String CA1_WSTESTUSER1CVCRSA = "TstCVCRSA";
    protected static final String CA2_WSTESTUSER1CVCEC = "TstCVCEC";
    private static final String CA1 = "CA1";
    private static final String CA2 = "CA2";

    static {
        String tmp;
        try {
            tmp = TestTools.getConfigurationSession().getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME, "localhost");
        } catch (RemoteException e) {
            tmp = "localhost";
            log.error("Not possible to get property " + WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME, e);
        }
        hostname = tmp;
        try {
            tmp = TestTools.getConfigurationSession().getProperty(WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS, "8443");
        } catch (RemoteException e) {
            tmp = "8443";
            log.error("Not possible to get property " + WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS, e);
        }
        httpsPort = tmp;
    }

    protected String getAdminCAName() {
        return "AdminCA1";
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    protected IHardTokenSessionRemote getHardTokenSession() throws RemoteException, CreateException, NamingException {
        return TestTools.getHardTokenSession();
    }

    protected ICertificateStoreSessionRemote getCertStore() throws RemoteException, CreateException, NamingException {
        return TestTools.getCertificateStoreSession();
    }

    protected IRaAdminSessionRemote getRAAdmin() throws RemoteException, CreateException, NamingException {
        return TestTools.getRaAdminSession();
    }

    protected IUserAdminSessionRemote getUserAdminSession() throws RemoteException, CreateException, NamingException {
        return TestTools.getUserAdminSession();
    }

    protected ICAAdminSessionRemote getCAAdminSession() throws RemoteException, CreateException, NamingException {
        return TestTools.getCAAdminSession();
    }

    protected IAuthorizationSessionRemote getAuthSession() throws RemoteException, CreateException, NamingException {
        return TestTools.getAuthorizationSession();
    }

    protected IApprovalSessionRemote getApprovalSession() throws RemoteException, CreateException, NamingException {
        return TestTools.getApprovalSession();
    }

    protected void setupAccessRights() throws Exception {
        boolean userAdded = false;

        if (!getUserAdminSession().existsUser(intAdmin, TEST_ADMIN_USERNAME)) {
            UserDataVO user1 = new UserDataVO();
            user1.setUsername(TEST_ADMIN_USERNAME);
            user1.setPassword("foo123");
            user1.setDN("CN=wstest");
            CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
            user1.setCAId(cainfo.getCAId());
            user1.setEmail(null);
            user1.setSubjectAltName(null);
            user1.setStatus(UserDataVOWS.STATUS_NEW);
            user1.setTokenType(SecConst.TOKEN_SOFT_JKS);
            user1.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
            user1.setCertificateProfileId(SecConst.CERTPROFILE_FIXED_ENDUSER);
            user1.setType(65);

            getUserAdminSession().addUser(intAdmin, user1, true);
            userAdded = true;

            boolean adminExists = false;
            AdminGroup admingroup = getAuthSession().getAdminGroup(intAdmin, AdminGroup.TEMPSUPERADMINGROUP);
            Iterator iter = admingroup.getAdminEntities().iterator();
            while (iter.hasNext()) {
                AdminEntity adminEntity = (AdminEntity) iter.next();
                if (adminEntity.getMatchValue().equals(TEST_ADMIN_USERNAME)) {
                    adminExists = true;
                }
            }

            if (!adminExists) {
                List list = new ArrayList();
                list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASE, TEST_ADMIN_USERNAME, cainfo.getCAId()));
                getAuthSession().addAdminEntities(intAdmin, AdminGroup.TEMPSUPERADMINGROUP, list);
                getAuthSession().forceRuleUpdate(intAdmin);
            }

        }

        if (!getUserAdminSession().existsUser(intAdmin, TEST_NONADMIN_USERNAME)) {
            UserDataVO user1 = new UserDataVO();
            user1.setUsername(TEST_NONADMIN_USERNAME);
            user1.setPassword("foo123");
            user1.setDN("CN=wsnonadmintest");
            CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
            user1.setCAId(cainfo.getCAId());
            user1.setEmail(null);
            user1.setSubjectAltName(null);
            user1.setStatus(UserDataVOWS.STATUS_NEW);
            user1.setTokenType(SecConst.TOKEN_SOFT_JKS);
            user1.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
            user1.setCertificateProfileId(SecConst.CERTPROFILE_FIXED_ENDUSER);
            user1.setType(1);

            getUserAdminSession().addUser(intAdmin, user1, true);
            userAdded = true;
        }

        if (userAdded) {
            BatchMakeP12 batch = new BatchMakeP12();
            batch.setMainStoreDir("p12");
            batch.createAllNew();
        }

    }

    private String getDN(String userName) {
        return "CN=" + userName + ",O=" + userName.charAt(userName.length() - 1) + "Test";
    }

    private String getReversedDN(String userName) {
        return "O=" + userName.charAt(userName.length() - 1) + "Test,CN=" + userName;
    }

    private void editUser(String userName, String caName) throws Exception {
        // Test to add a user.
        final UserDataVOWS user = new UserDataVOWS();
        user.setUsername(userName);
        user.setPassword("foo123");
        user.setClearPwd(true);
        user.setSubjectDN("CN=" + userName);
        user.setCaName(caName);
        user.setEmail(null);
        user.setSubjectAltName(null);
        user.setStatus(UserDataVOWS.STATUS_NEW);
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setEndEntityProfileName("EMPTY");
        user.setCertificateProfileName("ENDUSER");

        ejbcaraws.editUser(user);

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(userName);

        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        UserDataVOWS userdata = userdatas.get(0);
        assertTrue(userdata.getUsername().equals(userName));
        assertTrue(userdata.getPassword() == null);
        assertTrue(!userdata.isClearPwd());
        assertTrue(userdata.getSubjectDN().equals("CN=" + userName));
        assertTrue(userdata.getCaName().equals(caName));
        assertTrue(userdata.getSubjectAltName() == null);
        assertTrue(userdata.getEmail() == null);
        assertTrue(userdata.getCertificateProfileName().equals("ENDUSER"));
        assertTrue(userdata.getEndEntityProfileName().equals("EMPTY"));
        assertTrue(userdata.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_USERGENERATED));
        assertTrue(userdata.getStatus() == UserDataVOWS.STATUS_NEW);

        // Edit the user
        final String sDN = getDN(userName);
        userdata.setSubjectDN(sDN);
        ejbcaraws.editUser(userdata);
        List<UserDataVOWS> userdatas2 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas2 != null);
        assertTrue(userdatas2.size() == 1);
        UserDataVOWS userdata2 = userdatas2.get(0);
        assertTrue(userdata2.getSubjectDN().equals(sDN));

    }

    private void editUser(UserDataVOWS userdata, String subjectDN) throws Exception {
        // Edit the user
        userdata.setSubjectDN(subjectDN);
        userdata.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        ejbcaraws.editUser(userdata);
        final UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(userdata.getUsername());
        final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        final UserDataVOWS userdata2 = userdatas.get(0);
        assertTrue(userdata2.getSubjectDN().equals(subjectDN));
    }

    protected void editUser() throws Exception {
        TestTools.createTestCA(CA1);
        TestTools.createTestCA(CA2);
        editUser(CA1_WSTESTUSER1, CA1);
        editUser(CA1_WSTESTUSER2, CA1);
        editUser(CA2_WSTESTUSER1, CA2);
    }

    protected void findUser() throws Exception {

        // Nonexisting users should return null
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("noneExsisting");
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 0);

        // Find an exising user
        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);

        List<UserDataVOWS> userdatas2 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas2 != null);
        assertTrue(userdatas2.size() == 1);

        // Find by O
        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_ORGANIZATION);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_BEGINSWITH);
        usermatch.setMatchvalue("2Te");
        List<UserDataVOWS> userdatas3 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas3 != null);
        assertTrue(userdatas3.size() == 1);
        assertTrue(userdatas3.get(0).getSubjectDN().equals(getDN(CA1_WSTESTUSER2)));

        // Find by subjectDN pattern
        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_DN);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas4 = ejbcaraws.findUser(usermatch);
        assertNotNull(userdatas4);
        assertEquals(1, userdatas4.size());
        assertEquals(getDN(CA1_WSTESTUSER1), userdatas4.get(0).getSubjectDN());

        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_ENDENTITYPROFILE);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("EMPTY");
        List<UserDataVOWS> userdatas5 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas5 != null);
        assertTrue(userdatas5.size() > 0);

        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_CERTIFICATEPROFILE);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("ENDUSER");
        List<UserDataVOWS> userdatas6 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas6 != null);
        assertTrue(userdatas6.size() > 0);

        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_CA);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(getAdminCAName());
        List<UserDataVOWS> userdatas7 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas7 != null);
        assertTrue(userdatas7.size() > 0);

        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_TOKEN);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        List<UserDataVOWS> userdatas8 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas8 != null);
        assertTrue(userdatas8.size() > 0);
    }

    protected void generatePkcs10() throws Exception {

        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(),
                new DERSet(), keys.getPrivate());

        CertificateResponse certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, "foo123", new String(Base64.encode(pkcs10.getEncoded())), null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);

        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);

        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());

    }

    /**
     * Perform two WS certificate requests with different response-types:
     * Certificate and PKCS#7. If the first one fails an error code will be
     * returned. I the second fails a Exception will be thrown.
     */
    private ErrorCode certreqInternal(UserDataVOWS userdata, String requestdata, int requesttype) throws Exception {
        // Request a certificate via the WS API
        final CertificateResponse certificateResponse;
        try {
            certificateResponse = ejbcaraws.certificateRequest(userdata, requestdata, requesttype, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            final ErrorCode errorCode = e.getFaultInfo().getErrorCode();
            log.info(errorCode.getInternalErrorCode(), e);
            assertNotNull("error code should not be null", errorCode);
            return errorCode;
        }
        // Verify that the response is of the right type
        assertNotNull(certificateResponse);
        assertTrue(certificateResponse.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
        // Verify that the certificate in the response has the same Subject DN
        // as in the request.
        final X509Certificate cert = certificateResponse.getCertificate();
        assertNotNull(cert);
        assertTrue(cert.getSubjectDN().toString().equals(userdata.getSubjectDN()));

        // Request a PKCS#7 via the WS API
        final CertificateResponse pkcs7Response = ejbcaraws.certificateRequest(userdata, requestdata, requesttype, null, CertificateHelper.RESPONSETYPE_PKCS7);
        // Verify that the response is of the right type
        assertTrue(pkcs7Response.getResponseType().equals(CertificateHelper.RESPONSETYPE_PKCS7));
        // Verify that the PKCS#7 response contains a certificate
        CMSSignedData cmsSignedData = new CMSSignedData(CertificateHelper.getPKCS7(pkcs7Response.getData()));
        assertNotNull(cmsSignedData);
        CertStore certStore = cmsSignedData.getCertificatesAndCRLs("Collection", "BC");
        assertTrue(certStore.getCertificates(null).size() == 1);
        return null;
    }

    /**
     * Fetch a user's data via the WS API and reset some of its values.
     */
    private UserDataVOWS getUserData(String userName) throws Exception {
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(userName);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setTokenType(null);
        userdatas.get(0).setPassword(null);
        userdatas.get(0).setClearPwd(true);
        return userdatas.get(0);
    }

    /**
     * Generate a new key pair and return a B64 encoded PKCS#10 encoded
     * certificate request for the keypair.
     */
    private String getP10() throws Exception {
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        return new String(Base64.encode(new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(),
                new DERSet(), keys.getPrivate()).getEncoded()));
    }

    /**
     * Test method for creating/editing a user a requesting a certificate in a
     * single transaction.
     */
    protected void certificateRequest() throws Exception {

        final UserDataVOWS userData1 = getUserData(CA1_WSTESTUSER1);
        ErrorCode errorCode = certreqInternal(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNull("PKCS#10 request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, CRMF, CertificateHelper.CERT_REQ_TYPE_CRMF);
        assertNull("CRMF request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, SPCAK, CertificateHelper.CERT_REQ_TYPE_SPKAC);
        assertNull("SPKAC request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
    }

    protected void enforcementOfUniquePublicKeys() throws Exception {

        final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
        final UserDataVOWS ca1userData1 = getUserData(CA1_WSTESTUSER1);
        final UserDataVOWS ca1userData2 = getUserData(CA1_WSTESTUSER2);
        final UserDataVOWS ca2userData1 = getUserData(CA2_WSTESTUSER1);
        final String p10_1 = getP10();
        final String p10_2 = getP10();
        final CAInfo ca1Info = TestTools.getCAAdminSession().getCAInfo(admin, CA1);

        // make sure same keys for different users is prevented
        ca1Info.setDoEnforceUniquePublicKeys(true);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);

        // fetching cert for new key on should be no problem
        assertNull(certreqInternal(ca1userData1, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // fetching cert for existing key for a user that does not have a
        // certificate for this key should be impossible
        final ErrorCode errorCode = certreqInternal(ca1userData2, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.ejbca.core.ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER.getInternalErrorCode(), errorCode
                .getInternalErrorCode());

        // test that the user that was denied a cert can get a cert with another
        // key.
        assertNull(certreqInternal(ca1userData2, p10_2, CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // fetching more than one cert for the same key should be possible for
        // the same user
        assertNull(certreqInternal(ca1userData1, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // A user could get a certificate for a key already included in a
        // certificate from another user if another CA is issuing it.
        assertNull(certreqInternal(ca2userData1, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // permit same key for different users
        ca1Info.setDoEnforceUniquePublicKeys(false);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);
        // fetching cert for existing key for a user that does not have a
        // certificate for this key is now permitted
        assertNull(certreqInternal(ca1userData2, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));
        // forbid same key for different users
        ca1Info.setDoEnforceUniquePublicKeys(true);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);
    }

    protected void enforcementOfUniqueSubjectDN() throws Exception {

        final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
        final UserDataVOWS ca1userData1 = getUserData(CA1_WSTESTUSER1);
        final UserDataVOWS ca1userData2 = getUserData(CA1_WSTESTUSER2);
        final UserDataVOWS ca2userData1 = getUserData(CA2_WSTESTUSER1);
        final CAInfo ca1Info = TestTools.getCAAdminSession().getCAInfo(admin, CA1);
        final int iRandom = SecureRandom.getInstance("SHA1PRNG").nextInt(); // to make sure a new DN is used
        // in next test
        final String subjectDN_A = "CN=EnforcementOfUniqueSubjectDN Test A " + iRandom;
        final String subjectDN_B = "CN=EnforcementOfUniqueSubjectDN Test B " + iRandom;

        // set same DN for all users
        editUser(ca1userData1, subjectDN_A);
        editUser(ca1userData2, subjectDN_A);
        editUser(ca2userData1, subjectDN_A);

        // make sure same DN for different users is prevented
        ca1Info.setDoEnforceUniqueDistinguishedName(true);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);

        // fetching first cert for a DN should be no problem
        assertNull(certreqInternal(ca1userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // fetching another cert for the same DN for a user that does not have a
        // certificate with this DN should fail
        final ErrorCode errorCode = certreqInternal(ca1userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.ejbca.core.ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALLREADY_EXISTS_FOR_ANOTHER_USER.getInternalErrorCode(), errorCode
                .getInternalErrorCode());

        // test that the user that was denied a cert can get a cert with another
        // DN.
        editUser(ca1userData2, subjectDN_B);
        assertNull(certreqInternal(ca1userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));
        editUser(ca1userData2, subjectDN_A);

        // fetching more than one cert with the same DN should be possible for
        // the same user
        assertNull(certreqInternal(ca1userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // A user could get a certificate for a DN used in another certificate
        // from another user if another CA is issuing it.
        assertNull(certreqInternal(ca2userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // permit same DN for different users
        ca1Info.setDoEnforceUniqueDistinguishedName(false);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);
        // fetching cert for existing DN for a user that does not have a
        // certificate with this DN is now permitted
        assertNull(certreqInternal(ca1userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));
        // forbid same DN for different users
        ca1Info.setDoEnforceUniqueDistinguishedName(true);
        TestTools.getCAAdminSession().editCA(admin, ca1Info);

        // set back original DN for all users
        editUser(ca1userData1, getDN(CA1_WSTESTUSER1));
        editUser(ca1userData2, getDN(CA1_WSTESTUSER2));
        editUser(ca2userData1, getDN(CA2_WSTESTUSER1));
    }


    protected void generateCrmf() throws Exception {

        // Edit our favorite test user
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN(getDN(CA1_WSTESTUSER1));
        user1.setCaName(CA1);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        CertificateResponse certenv = ejbcaraws.crmfRequest(CA1_WSTESTUSER1, "foo123", CRMF, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);

        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);
        log.info(cert.getSubjectDN().toString());
        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
    }



    protected void generateSpkac() throws Exception {

        // Edit our favorite test user
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN(getDN(CA1_WSTESTUSER1));
        user1.setCaName(CA1);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        CertificateResponse certenv = ejbcaraws.spkacRequest(CA1_WSTESTUSER1, "foo123", SPCAK, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);

        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);

        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
    }

    protected void generatePkcs12() throws Exception {

        boolean exceptionThrown = false;
        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown);// Should fail

        // Change token to P12
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        ejbcaraws.editUser(userdatas.get(0));

        exceptionThrown = false;
        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            exceptionThrown = true;
        }
        assertTrue(exceptionThrown); // Should fail

        // Change password to foo456 and status to NEW
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo456");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));

        KeyStore ksenv = null;
        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }

        assertNotNull(ksenv);

        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");

        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertEquals(cert.getSubjectDN().toString(), getDN(CA1_WSTESTUSER1));
        PrivateKey privK1 = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());
        log.info("test04GeneratePkcs12() Certificate " + cert.getSubjectDN().toString() + " equals " + getDN(CA1_WSTESTUSER1));

        // Generate a new one and make sure it is a new one and that key
        // recovery does not kick in by mistake
        // Set status to new
        usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo456");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));
        // A new PK12 request now should return the same key and certificate
        KeyStore ksenv2 = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = (String) en.nextElement();
        X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectDN().toString(), getDN(CA1_WSTESTUSER1));
        PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());

        // Compare certificates, must not be the same
        assertFalse(cert.getSerialNumber().toString(16).equals(cert2.getSerialNumber().toString(16)));
        // Compare keys, must not be the same
        String key1 = new String(Hex.encode(privK1.getEncoded()));
        String key2 = new String(Hex.encode(privK2.getEncoded()));
        assertFalse(key1.equals(key2));

        // Test the method for adding/editing and requesting a PKCS#12 KeyStore
        // in a single transaction
        ksenv2 = ejbcaraws.softTokenRequest(userdatas.get(0), null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = (String) en.nextElement();
        cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectDN().toString(), getDN(CA1_WSTESTUSER1));
        privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());

        // Test the method for adding/editing and requesting a JKS KeyStore in a
        // single transaction
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_JKS);
        ksenv2 = ejbcaraws.softTokenRequest(userdatas.get(0), null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "JKS", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = (String) en.nextElement();
        cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectX500Principal().getName(), getReversedDN(CA1_WSTESTUSER1));
        privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());
    }

    protected void findCerts() throws Exception {

        // First find all certs
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));
        KeyStore ksenv = null;
        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo123");

        assertNotNull(ks);
        Enumeration<String> en = ks.aliases();
        String alias = en.nextElement();
        java.security.cert.Certificate gencert = (java.security.cert.Certificate) ks.getCertificate(alias);

        List<Certificate> foundcerts = ejbcaraws.findCerts(CA1_WSTESTUSER1, false);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 0);

        boolean certFound = false;
        for (int i = 0; i < foundcerts.size(); i++) {
            java.security.cert.Certificate cert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(i).getCertificateData());
            if (CertTools.getSerialNumber(gencert).equals(CertTools.getSerialNumber(cert))) {
                certFound = true;
            }
        }
        assertTrue(certFound);

        String issuerdn = CertTools.getIssuerDN(gencert);
        String serno = CertTools.getSerialNumberAsString(gencert);

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        foundcerts = ejbcaraws.findCerts(CA1_WSTESTUSER1, true);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 0);

        certFound = false;
        for (int i = 0; i < foundcerts.size(); i++) {
            java.security.cert.Certificate cert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(i).getCertificateData());
            if (CertTools.getSerialNumber(gencert).equals(CertTools.getSerialNumber(cert))) {
                certFound = true;
            }
        }
        assertFalse(certFound);

    }

    protected void revokeCert() throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo456");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));

        KeyStore ksenv = null;
        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }

        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertTrue(cert.getSubjectDN().toString().equals(getDN(CA1_WSTESTUSER1)));

        String issuerdn = cert.getIssuerDN().toString();
        String serno = cert.getSerialNumber().toString(16);

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);

        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);

        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);

        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        try {
            ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
            assertTrue(false);
        } catch (EjbcaException_Exception e) {
        }

    }

    protected void revokeToken() throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));
        KeyStore ksenv = null;
        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", "12345678", "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo123");

        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert1 = (X509Certificate) ks.getCertificate(alias);

        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));

        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", "12345678", "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }
        ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo123");

        assertNotNull(ks);
        en = ks.aliases();
        alias = (String) en.nextElement();
        X509Certificate cert2 = (X509Certificate) ks.getCertificate(alias);

        ejbcaraws.revokeToken("12345678", RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE);

        String issuerdn1 = cert1.getIssuerDN().toString();
        String serno1 = cert1.getSerialNumber().toString(16);

        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn1, serno1);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE);

        String issuerdn2 = cert2.getIssuerDN().toString();
        String serno2 = cert2.getSerialNumber().toString(16);

        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn2, serno2);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokeStatus.REVOKATION_REASON_KEYCOMPROMISE);

    }

    protected void checkRevokeStatus() throws Exception {

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));
        KeyStore ksenv = null;
        try {
            ksenv = ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, "foo123", "12345678", "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        }
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo123");

        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        String issuerdn = cert.getIssuerDN().toString();
        String serno = cert.getSerialNumber().toString(16);

        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());
    }

    protected void utf8() throws Exception {

        // Test to add a user.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WS������");
        user1.setCaName(getAdminCAName());
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");

        ejbcaraws.editUser(user1);

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);

        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        UserDataVOWS userdata = userdatas.get(0);
        assertTrue(userdata.getUsername().equals(CA1_WSTESTUSER1));
        assertTrue(userdata.getSubjectDN().equals("CN=WS������"));

    }

    protected void revokeUser() throws Exception {

        // Revoke and delete
        ejbcaraws.revokeUser(CA1_WSTESTUSER1, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE, true);

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 0);

    }

    protected void genTokenCertificates(boolean onlyOnce) throws Exception {

        GlobalConfiguration gc = getRAAdmin().loadGlobalConfiguration(intAdmin);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
        if (getCertStore().getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0) {
            getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }

        CertificateProfile profile = new EndUserCertificateProfile();
        profile.setAllowValidityOverride(true);
        getCertStore().addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);

        // first a simple test
        UserDataVOWS tokenUser1 = new UserDataVOWS();
        tokenUser1.setUsername("WSTESTTOKENUSER1");
        tokenUser1.setPassword("foo123");
        tokenUser1.setClearPwd(true);
        tokenUser1.setSubjectDN("CN=WSTESTTOKENUSER1");
        tokenUser1.setCaName(getAdminCAName());
        tokenUser1.setEmail(null);
        tokenUser1.setSubjectAltName(null);
        tokenUser1.setStatus(UserDataVOWS.STATUS_NEW);
        tokenUser1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        tokenUser1.setEndEntityProfileName("EMPTY");
        tokenUser1.setCertificateProfileName("ENDUSER");

        KeyPair basickeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"),
                basickeys.getPublic(), new DERSet(), basickeys.getPrivate());

        ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
        TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
        tokenCertReqWS.setCAName(getAdminCAName());
        tokenCertReqWS.setCertificateProfileName("WSTESTPROFILE");
        tokenCertReqWS.setValidityIdDays("1");
        tokenCertReqWS.setPkcs10Data(basicpkcs10.getDEREncoded());
        tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST);
        requests.add(tokenCertReqWS);
        tokenCertReqWS = new TokenCertificateRequestWS();
        tokenCertReqWS.setCAName(getAdminCAName());
        tokenCertReqWS.setCertificateProfileName("ENDUSER");
        tokenCertReqWS.setKeyalg("RSA");
        tokenCertReqWS.setKeyspec("1024");
        tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST);
        requests.add(tokenCertReqWS);

        HardTokenDataWS hardTokenDataWS = setupHardTokenDataWS("12345678");

        List<TokenCertificateResponseWS> responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, true, false);
        assertTrue(responses.size() == 2);

        Iterator<TokenCertificateResponseWS> iter = responses.iterator();
        TokenCertificateResponseWS next = iter.next();
        assertTrue(next.getType() == HardTokenConstants.RESPONSETYPE_CERTIFICATE_RESPONSE);
        Certificate cert = next.getCertificate();
        X509Certificate realcert = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());
        assertNotNull(realcert);
        assertTrue(realcert.getNotAfter().toString(), realcert.getNotAfter().before(new Date(System.currentTimeMillis() + 2 * 24 * 3600 * 1000)));
        next = iter.next();
        assertTrue(next.getType() == HardTokenConstants.RESPONSETYPE_KEYSTORE_RESPONSE);
        KeyStore keyStore = next.getKeyStore();
        java.security.KeyStore realKeyStore = KeyStoreHelper.getKeyStore(keyStore.getKeystoreData(), HardTokenConstants.TOKENTYPE_PKCS12, "foo123");
        assertTrue(realKeyStore.containsAlias("WSTESTTOKENUSER1"));
        assertTrue(((X509Certificate) realKeyStore.getCertificate("WSTESTTOKENUSER1")).getNotAfter().after(
                new Date(System.currentTimeMillis() + 48 * 24 * 3600 * 1000)));

        if (!onlyOnce) {
            try {
                responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, false, false);
                assertTrue(false);
            } catch (HardTokenExistsException_Exception e) {

            }
        }

        getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
        getRAAdmin().saveGlobalConfiguration(intAdmin, gc);

    }

    protected HardTokenDataWS setupHardTokenDataWS(int hardTokenserialNumber) {
        return setupHardTokenDataWS(Integer.toString(hardTokenserialNumber));
    }

    protected HardTokenDataWS setupHardTokenDataWS(String hardTokenserialNumber) {
        HardTokenDataWS hardTokenDataWS = new HardTokenDataWS();
        hardTokenDataWS.setLabel(HardTokenConstants.LABEL_PROJECTCARD);
        hardTokenDataWS.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
        hardTokenDataWS.setHardTokenSN(hardTokenserialNumber);

        PinDataWS basicPinDataWS = new PinDataWS();
        basicPinDataWS.setType(HardTokenConstants.PINTYPE_BASIC);
        basicPinDataWS.setInitialPIN("1234");
        basicPinDataWS.setPUK("12345678");
        PinDataWS signaturePinDataWS = new PinDataWS();
        signaturePinDataWS.setType(HardTokenConstants.PINTYPE_SIGNATURE);
        signaturePinDataWS.setInitialPIN("5678");
        signaturePinDataWS.setPUK("23456789");

        hardTokenDataWS.getPinDatas().add(basicPinDataWS);
        hardTokenDataWS.getPinDatas().add(signaturePinDataWS);

        return hardTokenDataWS;
    }

    protected void getExistsHardToken() throws Exception {

        assertTrue(ejbcaraws.existsHardToken("12345678"));
        assertFalse(ejbcaraws.existsHardToken("23456789"));
    }

    protected void getHardTokenData(String serialNumber, boolean onlyOnce) throws Exception {

        HardTokenDataWS hardTokenDataWS = ejbcaraws.getHardTokenData(serialNumber, true, true);
        assertNotNull(hardTokenDataWS);
        assertTrue("" + hardTokenDataWS.getTokenType(), hardTokenDataWS.getTokenType() == HardTokenConstants.TOKENTYPE_SWEDISHEID);
        assertTrue(hardTokenDataWS.getHardTokenSN().equals(serialNumber));
        assertTrue(hardTokenDataWS.getCopyOfSN(), hardTokenDataWS.getCopyOfSN() == null);
        assertTrue(hardTokenDataWS.getCopies().size() == 0);
        // assertTrue(hardTokenDataWS.getCertificates().size() == 2);
        assertTrue(hardTokenDataWS.getPinDatas().size() == 2);

        Iterator<PinDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
        while (iter.hasNext()) {
            PinDataWS next = iter.next();
            if (next.getType() == HardTokenConstants.PINTYPE_BASIC) {
                assertTrue(next.getPUK().equals("12345678"));
                assertTrue(next.getInitialPIN().equals("1234"));
            }
            if (next.getType() == HardTokenConstants.PINTYPE_SIGNATURE) {
                assertTrue(next.getPUK(), next.getPUK().equals("23456789"));
                assertTrue(next.getInitialPIN().equals("5678"));
            }
        }
        if (!onlyOnce) {
            hardTokenDataWS = ejbcaraws.getHardTokenData(serialNumber, false, false);
            assertNotNull(hardTokenDataWS);
            // assertTrue(""+ hardTokenDataWS.getCertificates().size(),
            // hardTokenDataWS.getCertificates().size() == 2);
            assertTrue("" + hardTokenDataWS.getPinDatas().size(), hardTokenDataWS.getPinDatas().size() == 0);

            try {
                ejbcaraws.getHardTokenData("12345679", false, false);
                assertTrue(false);
            } catch (HardTokenDoesntExistsException_Exception e) {

            }
        }

    }

    protected void getHardTokenDatas() throws Exception {

        Collection<HardTokenDataWS> hardTokenDatas = ejbcaraws.getHardTokenDatas("WSTESTTOKENUSER1", true, true);
        assertTrue(hardTokenDatas.size() == 1);
        HardTokenDataWS hardTokenDataWS = hardTokenDatas.iterator().next();
        assertNotNull(hardTokenDataWS);
        assertTrue("" + hardTokenDataWS.getTokenType(), hardTokenDataWS.getTokenType() == HardTokenConstants.TOKENTYPE_SWEDISHEID);
        assertTrue(hardTokenDataWS.getHardTokenSN().equals("12345678"));
        assertTrue(hardTokenDataWS.getCopyOfSN(), hardTokenDataWS.getCopyOfSN() == null);
        assertTrue(hardTokenDataWS.getCopies().size() == 0);
        assertTrue(hardTokenDataWS.getCertificates().size() == 2);
        assertTrue(hardTokenDataWS.getPinDatas().size() == 2);

        Iterator<PinDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
        while (iter.hasNext()) {
            PinDataWS next = iter.next();
            if (next.getType() == HardTokenConstants.PINTYPE_BASIC) {
                assertTrue(next.getPUK().equals("12345678"));
                assertTrue(next.getInitialPIN().equals("1234"));
            }
            if (next.getType() == HardTokenConstants.PINTYPE_SIGNATURE) {
                assertTrue(next.getPUK(), next.getPUK().equals("23456789"));
                assertTrue(next.getInitialPIN().equals("5678"));
            }
        }

        try {
            hardTokenDatas = ejbcaraws.getHardTokenDatas("WSTESTTOKENUSER2", true, true);
            assertTrue(hardTokenDatas.size() == 0);
        } catch (EjbcaException_Exception e) {

        }
    }

    protected void customLog() throws Exception {

        // The logging have to be checked manually
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_INFO, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null, "Message 1 generated from WS test Script");
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_ERROR, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null, "Message 1 generated from WS test Script");
    }

    protected void getCertificate() throws Exception {
        List<Certificate> certs = ejbcaraws.findCerts("WSTESTTOKENUSER1", true);
        Certificate cert = certs.get(0);
        X509Certificate realcert = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());

        cert = ejbcaraws.getCertificate(realcert.getSerialNumber().toString(16), CertTools.getIssuerDN(realcert));
        assertNotNull(cert);
        X509Certificate realcert2 = (X509Certificate) CertificateHelper.getCertificate(cert.getCertificateData());

        assertTrue(realcert.getSerialNumber().equals(realcert2.getSerialNumber()));

        cert = ejbcaraws.getCertificate("1234567", CertTools.getIssuerDN(realcert));
        assertNull(cert);
    }

    protected void revocationApprovals() throws Exception {
        final String APPROVINGADMINNAME = "superadmin";
        final String TOKENSERIALNUMBER = "42424242";
        final String TOKENUSERNAME = "WSTESTTOKENUSER3";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNOTSUPPORTEDSUCCEEDED = "Reactivation of users is not supported, but succeeded anyway.";

        // Generate random username and CA name
        String randomPostfix = Integer.toString(SecureRandom.getInstance("SHA1PRNG").nextInt(999999));
        String caname = "wsRevocationCA" + randomPostfix;
        String username = "wsRevocationUser" + randomPostfix;
        int caID = -1;
        try {
            caID = RevocationApprovalTest.createApprovalCA(intAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, getCAAdminSession());
            X509Certificate adminCert = (X509Certificate) getCertStore().findCertificatesByUsername(intAdmin, APPROVINGADMINNAME).iterator().next();
            Admin approvingAdmin = new Admin(adminCert, APPROVINGADMINNAME, null);
            try {
                X509Certificate cert = createUserAndCert(username, caID);
                String issuerdn = cert.getIssuerDN().toString();
                String serno = cert.getSerialNumber().toString(16);
                // revoke via WS and verify response
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e1) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e1) {
                }
                RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
                assertNotNull(revokestatus);
                assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
                // Approve revocation and verify success
                RevocationApprovalTest.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession(), caID);
                // Try to unrevoke certificate
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                RevocationApprovalTest.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession(), caID);
                // Revoke user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                RevocationApprovalTest.approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, getCertStore(), getApprovalSession(), caID);
                // Try to reactivate user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.NOT_REVOKED, false);
                    assertTrue(ERRORNOTSUPPORTEDSUCCEEDED, false);
                } catch (AlreadyRevokedException_Exception e) {
                }
            } finally {
                getUserAdminSession().deleteUser(intAdmin, username);
            }
            try {
                // Create a hard token issued by this CA
                createHardToken(TOKENUSERNAME, caname, TOKENSERIALNUMBER);
                assertTrue(ejbcaraws.existsHardToken(TOKENSERIALNUMBER));
                // Revoke token
                try {
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeToken(TOKENSERIALNUMBER, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (ApprovalException_Exception e) {
                }
                // Approve actions and verify success
                RevocationApprovalTest.approveRevocation(intAdmin, approvingAdmin, TOKENUSERNAME, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, getCertStore(), getApprovalSession(), caID);
            } finally {
                getHardTokenSession().removeHardToken(intAdmin, TOKENSERIALNUMBER);
            }
        } finally {
            // Nuke CA
            try {
                getCAAdminSession().revokeCA(intAdmin, caID, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            } finally {
                getCAAdminSession().removeCA(intAdmin, caID);
            }
        }
    } // testRevocationApprovals

    protected void generatePkcs10Request() throws Exception {

        // Change token to P12
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
        userdatas.get(0).setPassword("foo123");
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));

        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keys.getPublic(),
                new DERSet(), keys.getPrivate());

        CertificateResponse certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, "foo123", new String(Base64.encode(pkcs10.getEncoded())), null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);
        assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);
        assertTrue(cert.getSubjectDN().toString().equals(getDN(CA1_WSTESTUSER1)));

        ejbcaraws.editUser(userdatas.get(0));
        certenv = ejbcaraws
                .pkcs10Request(CA1_WSTESTUSER1, "foo123", new String(Base64.encode(pkcs10.getEncoded())), null, CertificateHelper.RESPONSETYPE_PKCS7);
        assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_PKCS7));
        CMSSignedData cmsSignedData = new CMSSignedData(CertificateHelper.getPKCS7(certenv.getData()));
        assertTrue(cmsSignedData != null);

        CertStore certStore = cmsSignedData.getCertificatesAndCRLs("Collection", "BC");
        assertTrue(certStore.getCertificates(null).size() == 1);

    }

    protected void keyRecover() throws Exception {

        GlobalConfiguration gc = getRAAdmin().loadGlobalConfiguration(intAdmin);
        boolean krenabled = gc.getEnableKeyRecovery();
        if (krenabled == true) {
            gc.setEnableKeyRecovery(false);
            getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
        }

        boolean trows = false;
        try {
            // This should throw an exception that key recovery is not enabled
            ejbcaraws.keyRecoverNewest(CA1_WSTESTUSER1);
        } catch (EjbcaException_Exception e) {
            trows = true;
            // e.printStackTrace();
            assertEquals(e.getMessage(), "Keyrecovery have to be enabled in the system configuration in order to use this command.");
        }
        assertTrue(trows);

        // Set key recovery enabled
        gc.setEnableKeyRecovery(true);
        getRAAdmin().saveGlobalConfiguration(intAdmin, gc);

        trows = false;
        try {
            // This should throw an exception that the user does not exist
            ejbcaraws.keyRecoverNewest("sdfjhdiuwerw43768754###");
        } catch (NotFoundException_Exception e) {
            trows = true;
            // e.printStackTrace();
            assertEquals(e.getMessage(), "Entity sdfjhdiuwerw43768754### does not exist.");
        }
        assertTrue(trows);

        // Add a new End entity profile, KEYRECOVERY
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COMMONNAME);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setReUseKeyRevoceredCertificate(true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        getRAAdmin().addEndEntityProfile(intAdmin, "KEYRECOVERY", profile);

        // Add a new user, set token to P12, status to new and end entity
        // profile to key recovery
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setKeyRecoverable(true);
        user1.setUsername("WSTESTUSERKEYREC1");
        user1.setPassword("foo456");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSERKEYREC1");
        user1.setCaName(getAdminCAName());
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        user1.setEndEntityProfileName("KEYRECOVERY");
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        KeyStore ksenv = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks);
        Enumeration en = ks.aliases();
        String alias = (String) en.nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertEquals(cert.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC1");
        PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());

        // This should work now
        ejbcaraws.keyRecoverNewest("WSTESTUSERKEYREC1");

        // Set status to new
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSERKEYREC1");
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 1);
        userdatas.get(0).setStatus(UserDataConstants.STATUS_KEYRECOVERY);
        ejbcaraws.editUser(userdatas.get(0));
        // A new PK12 request now should return the same key and certificate
        KeyStore ksenv2 = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = (String) en.nextElement();
        X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC1");
        PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());

        // Compare certificates
        assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
        // Compare keys
        String key1 = new String(Hex.encode(privK.getEncoded()));
        String key2 = new String(Hex.encode(privK2.getEncoded()));
        assertEquals(key1, key2);

    } // test20KeyRecover

    protected void getAvailableCAs() throws Exception {

        ICAAdminSessionRemote casession = getCAAdminSession();
        Collection ids = casession.getAvailableCAs(intAdmin);
        List<NameAndId> cas = ejbcaraws.getAvailableCAs();
        assertNotNull(cas);
        assertEquals(cas.size(), ids.size());
        boolean found = false;
        for (NameAndId n : cas) {
            if (n.getName().equals(getAdminCAName())) {
                found = true;
            }
        }
        assertTrue(found);
    } // test21GetAvailableCAs

    protected void getAuthorizedEndEntityProfiles() throws Exception {

        Collection<Integer> ids = getRAAdmin().getAuthorizedEndEntityProfileIds(intAdmin);
        List<NameAndId> profs = ejbcaraws.getAuthorizedEndEntityProfiles();
        assertNotNull(profs);
        assertEquals(profs.size(), ids.size());
        boolean foundkeyrec = false;
        for (NameAndId n : profs) {
            log.info("name: " + n.getName());
            if (n.getName().equals("KEYRECOVERY")) {
                foundkeyrec = true;
            }
            boolean found = false;
            for (Integer i : ids) {
                // All ids must be in profs
                if (n.getId() == i) {
                    found = true;
                }
            }
            assertTrue(found);
        }
        assertTrue(foundkeyrec);
    } // test22GetAuthorizedEndEntityProfiles

    protected void getAvailableCertificateProfiles() throws Exception {

        int id = getRAAdmin().getEndEntityProfileId(intAdmin, "KEYRECOVERY");
        List<NameAndId> profs = ejbcaraws.getAvailableCertificateProfiles(id);
        assertNotNull(profs);
        for (NameAndId n : profs) {
            log.info("name: " + n.getName());
        }
        assertTrue(profs.size() > 1);
        NameAndId n = profs.get(0);
        // This profile only has the enduser certificate profile available
        assertEquals(1, n.getId());
        assertEquals("ENDUSER", n.getName());
    } // test23GetAvailableCertificateProfiles

    protected void getAvailableCAsInProfile() throws Exception {

        int id = getRAAdmin().getEndEntityProfileId(intAdmin, "KEYRECOVERY");
        log.info("id: " + id);
        List<NameAndId> cas = ejbcaraws.getAvailableCAsInProfile(id);
        assertNotNull(cas);
        // This profile only has ALLCAS available, so this list will be empty
        assertTrue(cas.size() == 0);

    } // test24GetAvailableCAsInProfile

    protected void createCRL() throws Exception {

        String caname = getAdminCAName();
        // This will throw exception if it fails
        ejbcaraws.createCRL(caname);
    } // test25CreateCRL

    protected void cvcRequest(String rootcadn, String rootcaname, String subcadn, String subcaname, String username, String keyspec, String keyalg, String signalg) throws Exception {

        createCVCCA(rootcadn, rootcaname, subcadn, subcaname, keyspec, keyalg, signalg);

        // 
        // create a set of requests for WS test
        //
        // Create new keypairs
        KeyPair keyPair = KeyTools.genKeys(keyspec, keyalg);
        KeyPair keyPair1 = KeyTools.genKeys(keyspec, keyalg);
        KeyPair keyPair2 = KeyTools.genKeys(keyspec, keyalg);

        CAReferenceField caRef = new CAReferenceField("SE", "WSTEST", "00111");
        HolderReferenceField holderRef = new HolderReferenceField(caRef.getCountry(), caRef.getMnemonic(), caRef.getSequence());

        // Simple self signed request
        CVCertificate request = CertificateGenerator.createRequest(keyPair, signalg, caRef, holderRef);

        // A renew request with an outer signature created with the same keys as
        // the old one
        CVCAuthenticatedRequest authRequestSameKeys = CertificateGenerator.createAuthenticatedRequest(request, keyPair, signalg, caRef);

        // An renew request with an inner request with new keys and an outer
        // request with the same keys as in the last request
        CVCertificate request1 = CertificateGenerator.createRequest(keyPair1, signalg, caRef, holderRef);
        CVCAuthenticatedRequest authRequestRenew = CertificateGenerator.createAuthenticatedRequest(request1, keyPair, signalg, caRef);

        // A false renew request with new keys all over, both for inner ant
        // outer signatures
        CVCertificate request2 = CertificateGenerator.createRequest(keyPair2, signalg, caRef, holderRef);
        CVCAuthenticatedRequest authRequestRenewFalse = CertificateGenerator.createAuthenticatedRequest(request2, keyPair2, signalg, caRef);

        //
        // First test that we register a new user (like in admin GUI) and gets a
        // certificate for that. This should work fine.
        // 

        // Edit our favorite test user
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(username);
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN="+username+",C=SE");
        user1.setCaName(subcaname);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        // editUser and set status to new
        ejbcaraws.editUser(user1);

        List<Certificate> certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(request.getDEREncoded())));

        assertNotNull(certenv);

        Certificate wscert = certenv.get(0);
        byte[] b64cert = wscert.getCertificateData();
        CVCObject parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
        CVCertificate cert = (CVCertificate) parsedObject;
        CardVerifiableCertificate cvcert = new CardVerifiableCertificate(cert);

        assertNotNull(cert);
        assertEquals("CN="+username+",C=SE", CertTools.getSubjectDN(cvcert));
        assertEquals("00111", CertTools.getSerialNumberAsString(cvcert));
        PublicKey pk = cvcert.getPublicKey();
        assertEquals("CVC", pk.getFormat());
        // Verify that we have the complete chain
        assertEquals(3, certenv.size());
        Certificate wsdvcert = certenv.get(1);
        Certificate wscvcacert = certenv.get(2);
        b64cert = wsdvcert.getCertificateData();
        parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
        CVCertificate dvcert = (CVCertificate) parsedObject;
        b64cert = wscvcacert.getCertificateData();
        parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
        CVCertificate cvcacert = (CVCertificate) parsedObject;
        assertEquals(AuthorizationRoleEnum.DV_D, dvcert.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole());
        assertEquals(AuthorizationRoleEnum.CVCA, cvcacert.getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole());
        PublicKey cvcapubk = cvcacert.getCertificateBody().getPublicKey();
        PublicKey dvpubk = dvcert.getCertificateBody().getPublicKey();
        dvpubk = KeyTools.getECPublicKeyWithParams(dvpubk, cvcapubk);
        cvcert.verify(dvpubk);
        CardVerifiableCertificate dvjavacert = new CardVerifiableCertificate(dvcert);
        dvjavacert.verify(cvcapubk);

        //
        // Second test that we try to get a new certificate for this user
        // without outer (renewal) signature. This should fail.
        // 
        boolean thrown = false;
        try {
            certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(request.getDEREncoded())));
        } catch (EjbcaException_Exception e) {
            thrown = true;
            String msg = e.getMessage();
            assertTrue(msg.contains("NEW, FAILED or INPROCESS required"));
        }
        assertTrue(thrown);

        //
        // Third test that we can not renew a certificate with the same keys as
        // the old request. This should fail.
        // 
        thrown = false;
        try {
            certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(authRequestSameKeys.getDEREncoded())));
        } catch (AuthorizationDeniedException_Exception e) {
            thrown = true;
            String msg = e.getMessage();
            assertTrue(msg.contains("Trying to renew a certificate using the same key"));
        }
        assertTrue(thrown);

        //
        // Fourth test that we can renew a certificate using an outer signature
        // made with the old keys. This should succeed.
        // 
        certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(authRequestRenew.getDEREncoded())));
        assertNotNull(certenv);
        wscert = certenv.get(0);
        b64cert = wscert.getCertificateData();
        parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
        cert = (CVCertificate) parsedObject;
        cvcert = new CardVerifiableCertificate(cert);
        assertNotNull(cert);
        assertEquals("CN="+username+",C=SE", CertTools.getSubjectDN(cvcert));
        assertEquals("00111", CertTools.getSerialNumberAsString(cvcert));

        //
        // Fifth test try to renew with an outer signature which is not by the
        // last issued cert (false renew request). This should fail.
        //
        thrown = false;
        try {
            certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(authRequestRenewFalse.getDEREncoded())));
        } catch (AuthorizationDeniedException_Exception e) {
            thrown = true;
            String msg = e.getMessage();
            assertTrue(msg.contains("No certificate found that could authenticate request"));
        }
        assertTrue(thrown);
    } // cvcRequest

    protected void ejbcaVersion() throws Exception {

        String version = ejbcaraws.getEjbcaVersion();
        assertTrue(version.contains("EJBCA 4")); // We don't know which specific
        // version we are testing
    }

    protected void getLastCertChain() throws Exception {

        List<Certificate> foundcerts = ejbcaraws.getLastCertChain(CA1_WSTESTUSER1);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 1);

        java.security.cert.Certificate cacert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(foundcerts.size() - 1)
                .getCertificateData());
        assertTrue(CertTools.isSelfSigned(cacert));
        java.security.cert.Certificate cert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(0).getCertificateData());
        assertEquals(getDN(CA1_WSTESTUSER1), CertTools.getSubjectDN(cert));
        for (int i = 1; i < foundcerts.size(); i++) {
            java.security.cert.Certificate cert2 = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(i).getCertificateData());
            cert.verify(cert2.getPublicKey()); // will throw if verification
            // fails
            cert = cert2;
        }
        
        String randomuser = TestTools.genRandomUserName();
        List<Certificate> foundnocerts = ejbcaraws.getLastCertChain(randomuser);
        assertTrue(foundnocerts != null);
        assertTrue(foundnocerts.size() == 0);
    }

    protected void errorOnEditUser() throws Exception {

        // Test to add a user.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER29");
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSER29");
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");

        ErrorCode errorCode = null;

        // /// Check ErrorCode.CA_NOT_EXISTS /////
        user1.setCaName(BADCANAME);
        try {
            ejbcaraws.editUser(user1);
        } catch (CADoesntExistsException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }
        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.CA_NOT_EXISTS.getInternalErrorCode());

        // restore CA name
        user1.setCaName(getAdminCAName());
        errorCode = null;

        // /// Check ErrorCode.EE_PROFILE_NOT_EXISTS /////
        user1.setEndEntityProfileName("Bad EE profile");
        try {
            ejbcaraws.editUser(user1);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }

        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.EE_PROFILE_NOT_EXISTS.getInternalErrorCode());

        // restore EE profile
        user1.setEndEntityProfileName("EMPTY");
        errorCode = null;

        // /// Check ErrorCode.CERT_PROFILE_NOT_EXISTS /////
        user1.setCertificateProfileName("Bad cert profile");
        try {
            ejbcaraws.editUser(user1);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }

        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.CERT_PROFILE_NOT_EXISTS.getInternalErrorCode());

        // restore Certificate profile
        user1.setCertificateProfileName("ENDUSER");
        errorCode = null;

        // /// Check ErrorCode.UNKOWN_TOKEN_TYPE /////
        user1.setTokenType("Bad token type");
        try {
            ejbcaraws.editUser(user1);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }

        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.UNKOWN_TOKEN_TYPE.getInternalErrorCode());
    }

    protected void errorOnGeneratePkcs10() throws Exception {

        // Add a user for this test purpose.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER30");
        user1.setPassword("foo1234");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSER30");
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        user1.setCaName(getAdminCAName());
        ejbcaraws.editUser(user1);

        KeyPair keys = null;
        PKCS10CertificationRequest pkcs10 = null;
        ErrorCode errorCode = null;

        // ///// Check Error.LOGIN_ERROR ///////
        keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=WSTESTUSER30"), keys.getPublic(), new DERSet(), keys
                .getPrivate());

        try {
            ejbcaraws.pkcs10Request("WSTESTUSER30", "foo123", new String(Base64.encode(pkcs10.getEncoded())), null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }

        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.LOGIN_ERROR.getInternalErrorCode());

        errorCode = null;

        // ///// Check Error.USER_WRONG_STATUS ///////
        user1.setStatus(UserDataConstants.STATUS_REVOKED);
        ejbcaraws.editUser(user1);

        keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=WSTESTUSER30"), keys.getPublic(), new DERSet(), keys
                .getPrivate());

        try {
            ejbcaraws
                    .pkcs10Request("WSTESTUSER30", "foo1234", new String(Base64.encode(pkcs10.getEncoded())), null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }

        assertNotNull("error code should not be null", errorCode);
        assertEquals(errorCode.getInternalErrorCode(), org.ejbca.core.ErrorCode.USER_WRONG_STATUS.getInternalErrorCode());

    }

    protected void errorOnGeneratePkcs12() throws Exception {

        // Add a user for this test purpose.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER31");
        user1.setPassword("foo1234");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSER31");
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        user1.setCaName(getAdminCAName());
        ejbcaraws.editUser(user1);

        ErrorCode errorCode = null;

        // Should failed because of the bad token type (USERGENERATED instead of
        // P12)
        try {
            ejbcaraws.pkcs12Req("WSTESTUSER31", "foo1234", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception ex) {
            errorCode = ex.getFaultInfo().getErrorCode();
            assertEquals(org.ejbca.core.ErrorCode.BAD_USER_TOKEN_TYPE.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        assertNotNull(errorCode);
        errorCode = null;
        // restore correct token type
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        ejbcaraws.editUser(user1);

        // Should failed because of the bad password
        try {
            ejbcaraws.pkcs12Req("WSTESTUSER31", "foo123", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception ex) {
            errorCode = ex.getFaultInfo().getErrorCode();
            assertEquals(org.ejbca.core.ErrorCode.LOGIN_ERROR.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        assertNotNull(errorCode);
        errorCode = null;

        // insert wrong status
        user1.setStatus(UserDataConstants.STATUS_REVOKED);
        ejbcaraws.editUser(user1);

        // Should failed because certificate already exists.
        try {
            ejbcaraws.pkcs12Req("WSTESTUSER31", "foo1234", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception ex) {
            errorCode = ex.getFaultInfo().getErrorCode();
            assertEquals(org.ejbca.core.ErrorCode.USER_WRONG_STATUS.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        assertNotNull(errorCode);
    }

    protected void operationOnNonexistingCA() throws Exception {
        final String MOCKSERIAL = "AABBCCDDAABBCCDD";

        // Add a user for this test purpose.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER32");
        user1.setPassword("foo1234");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSER32");
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        user1.setCaName(BADCANAME);
        try {
            ejbcaraws.editUser(user1);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        // Untested: ejbcaraws.pkcs10Request
        // Untested: ejbcaraws.pkcs12Req
        try {
            ejbcaraws.revokeCert("CN=" + BADCANAME, MOCKSERIAL, RevokedCertInfo.NOT_REVOKED);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        // Untested: ejbcaraws.revokeUser
        // Untested: ejbcaraws.keyRecoverNewest
        // Untested: ejbcaraws.revokeToken
        try {
            ejbcaraws.checkRevokationStatus("CN=" + BADCANAME, MOCKSERIAL);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        // Untested: ejbcaraws.genTokenCertificates
        try {
            UserDataVOWS badUserDataWS = new UserDataVOWS();
            badUserDataWS.setCaName(BADCANAME);
            ejbcaraws.genTokenCertificates(badUserDataWS, new ArrayList<TokenCertificateRequestWS>(), null, false, false);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        // Untested: ejbcaraws.getHardTokenData
        // Untested: ejbcaraws.getHardTokenDatas
        try {
            ejbcaraws.republishCertificate(MOCKSERIAL, "CN=" + BADCANAME);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        try {
            ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_ERROR, "prefix", BADCANAME, null, null, "This should not have been logged");
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        try {
            ejbcaraws.getCertificate(MOCKSERIAL, "CN=" + BADCANAME);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
        try {
            ejbcaraws.createCRL(BADCANAME);
            assertTrue("WS did not throw CADoesntExistsException as expected", false);
        } catch (CADoesntExistsException_Exception e) {
        } // Expected
    }

    protected void checkQueueLength() throws Exception {

        final String PUBLISHER_NAME = "myPublisher";
        final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
        try {
            assertEquals(-4, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            final CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(DummyCustomPublisher.class.getName());
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, PUBLISHER_NAME, publisher);
            assertEquals(0, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            final int publisherID = TestTools.getPublisherSession().getPublisherId(admin, PUBLISHER_NAME);
            TestTools.getPublisherQueueSession().addQueueData(publisherID, PublisherQueueData.PUBLISH_TYPE_CERT, "XX", null, PublisherQueueData.STATUS_PENDING);
            assertEquals(1, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            TestTools.getPublisherQueueSession().addQueueData(publisherID, PublisherQueueData.PUBLISH_TYPE_CERT, "XX", null, PublisherQueueData.STATUS_PENDING);
            assertEquals(2, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            TestTools.getPublisherQueueSession().removeQueueData(
                    ((PublisherQueueData) TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(publisherID).iterator().next()).getPk());
            assertEquals(1, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            TestTools.getPublisherQueueSession().removeQueueData(
                    ((PublisherQueueData) TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(publisherID).iterator().next()).getPk());
            assertEquals(0, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        } finally {
            TestTools.getPublisherSession().removePublisher(admin, PUBLISHER_NAME);
        }
    }

    /**
     * This method tests the WS API calls caRenewCertRequest and caCertResponse
     */
    protected void caRenewCertRequest(String keyspec, String keyalg, String signalg) throws Exception {

        List<byte[]> cachain = new ArrayList<byte[]>();
        String pwd = "foo123"; // use default hard coded soft CA token password
        // first we just try to create a simple request from an active X.509 CA.
        // A request like this can be used to request a cross certificate
        byte[] request = ejbcaraws.caRenewCertRequest(getAdminCAName(), cachain, false, false, false, pwd);
        assertNotNull(request);
        PKCS10RequestMessage msg = RequestMessageUtils.genPKCS10RequestMessage(request);
        assertNotNull(msg);
        CAInfo info = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
        assertEquals(info.getSubjectDN(), msg.getRequestDN());
        assertTrue(msg.verify());
        // System.out.println(ASN1Dump.dumpAsString(msg.getCertificationRequest()));

        /*
         * First test is to renew a CA signed by an external CA *without
         * renewing the keys*. This just creates a new certificate request,
         * without setting status to "waiting for certificate response" or
         * anything.
         */
        // Now we want to renew a DVCA signed by an external CVCA

        // Create the self signed CVCA, we do it here locally
        KeyPair cvcakeypair = KeyTools.genKeys(keyspec, keyalg);
        CAReferenceField caRef = new CAReferenceField("SE", "CVCAEXT", "00001");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "CVCAEXT", "00001");
        CVCertificate cvcert = CertificateGenerator.createTestCertificate(cvcakeypair.getPublic(), cvcakeypair.getPrivate(), caRef, holderRef, signalg,
                AuthorizationRoleEnum.CVCA);
        CardVerifiableCertificate cvcacert = new CardVerifiableCertificate(cvcert);
        // Create the DVCA signed by our external CVCA
        String caname = createDVCCASignedByExternal("1024", AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        assertEquals(caname, "WSTESTDVCASIGNEDBYEXTERNAL");
        // Now test our WS API to generate a request, setting status to
        // "WAITING_FOR_CERTIFICATE_RESPONSE"
        CAInfo dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
        cachain.add(cvcacert.getEncoded());
        // Create the request with WS API
        request = ejbcaraws.caRenewCertRequest(caname, cachain, false, false, false, pwd);
        // make the mandatory junit checks...
        assertNotNull(request);
        CVCRequestMessage cvcreq = RequestMessageUtils.genCVCRequestMessage(request);
        assertNotNull(request);
        assertEquals(dvinfo.getSubjectDN(), cvcreq.getRequestDN());
        CVCObject obj = CertificateParser.parseCVCObject(request);
        // System.out.println(obj.getAsText());
        CVCertificate cert = (CVCertificate) obj;
        assertEquals(cvcacert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated(), cert.getCertificateBody()
                .getAuthorityReference().getConcatenated());

        // Receive the response so the DV CA is activated
        HolderReferenceField dvholderref = cert.getCertificateBody().getHolderReference();
        CVCertificate dvretcert = CertificateGenerator.createTestCertificate(cert.getCertificateBody().getPublicKey(), cvcakeypair.getPrivate(), caRef,
                dvholderref, signalg, AuthorizationRoleEnum.DV_D);
        ejbcaraws.caCertResponse(caname, dvretcert.getDEREncoded(), cachain, pwd);
        // Check that the cert was received and the CA activated
        dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_ACTIVE);
        Collection dvcerts = dvinfo.getCertificateChain();
        assertEquals(2, dvcerts.size());
        CardVerifiableCertificate dvcertactive = (CardVerifiableCertificate) dvcerts.iterator().next();
        obj = CertificateParser.parseCVCObject(dvcertactive.getEncoded());
        // System.out.println(obj.getAsText());
        dvcertactive.verify(cvcakeypair.getPublic());
        // Check to see that is really the same keypair
        String pubk1 = new String(Base64.encode(dvcertactive.getPublicKey().getEncoded(), false));
        String pubk2 = new String(Base64.encode(cert.getCertificateBody().getPublicKey().getEncoded(), false));
        assertTrue(pubk1.compareTo(pubk2) == 0);
        String sequence1 = dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getSequence();

        /*
         * Second test is to renew a CA signed by an external CA *with renewing
         * the keys*, and activating them. This creates a new key pair and a
         * certificate request. Status is set to
         * "waiting for certificate response" because the new keys can not be
         * used until we have receive a certificate.
         */
        // Now we want to renew a DVCA signed by an external CVCA, generating
        // new keys
        // Create the request with WS API, cachain is our CVCA cert from
        // previously created CVCA, we use the previously created DV as well.
        pwd = "foo123";
        request = ejbcaraws.caRenewCertRequest(caname, cachain, true, false, true, pwd);
        // make the mandatory junit checks...
        assertNotNull(request);
        cvcreq = RequestMessageUtils.genCVCRequestMessage(request);
        assertNotNull(request);
        assertEquals(dvinfo.getSubjectDN(), cvcreq.getRequestDN());
        obj = CertificateParser.parseCVCObject(request);
        // System.out.println(obj.getAsText());
        // We should have created an authenticated request signed by the old
        // certificate
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) obj;
        assertEquals(dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated(), authreq.getAuthorityReference()
                .getConcatenated());
        cert = authreq.getRequest();
        assertEquals(cvcacert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated(), cert.getCertificateBody()
                .getAuthorityReference().getConcatenated());
        // Now test our WS API to generate a request, setting status to
        // "WAITING_FOR_CERTIFICATE_RESPONSE"
        dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_WAITING_CERTIFICATE_RESPONSE);
        // Check to see that is really is a new keypair
        pubk1 = new String(Base64.encode(dvcertactive.getPublicKey().getEncoded(), false));
        pubk2 = new String(Base64.encode(cert.getCertificateBody().getPublicKey().getEncoded(), false));
        assertTrue(pubk1.compareTo(pubk2) != 0);

        // Receive the response so the DV CA is activated
        dvholderref = cert.getCertificateBody().getHolderReference();
        dvretcert = CertificateGenerator.createTestCertificate(cert.getCertificateBody().getPublicKey(), cvcakeypair.getPrivate(), caRef, dvholderref,
        		signalg, AuthorizationRoleEnum.DV_D);
        ejbcaraws.caCertResponse(caname, dvretcert.getDEREncoded(), cachain, pwd);
        // Check that the cert was received and the CA activated
        dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_ACTIVE);
        dvcerts = dvinfo.getCertificateChain();
        assertEquals(2, dvcerts.size());
        dvcertactive = (CardVerifiableCertificate) dvcerts.iterator().next();
        obj = CertificateParser.parseCVCObject(dvcertactive.getEncoded());
        // System.out.println(obj.getAsText());
        dvcertactive.verify(cvcakeypair.getPublic());
        String sequence2 = dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
        int s1 = Integer.parseInt(sequence1);
        int s2 = Integer.parseInt(sequence2);
        assertEquals(s1 + 1, s2); // sequence in new certificate should be old
        // sequence + 1

        /*
         * Third test is to renew a CA signed by an external CA *with renewing
         * the keys* saying to *not* activate the key now. This creates a new
         * key pair and a certificate request, but the new key pair is not used
         * by the CA for issuing certificates. Status is not set to
         * "waiting for certificate response" because the old keys can still be
         * used until we have received a certificate and activated the new keys.
         */
        request = ejbcaraws.caRenewCertRequest(caname, cachain, true, false, false, pwd);
        // make the mandatory junit checks...
        assertNotNull(request);
        cvcreq = RequestMessageUtils.genCVCRequestMessage(request);
        assertNotNull(request);
        assertEquals(dvinfo.getSubjectDN(), cvcreq.getRequestDN());
        obj = CertificateParser.parseCVCObject(request);
        // System.out.println(obj.getAsText());
        // We should have created an authenticated request signed by the old
        // certificate
        authreq = (CVCAuthenticatedRequest) obj;
        assertEquals(dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated(), authreq.getAuthorityReference()
                .getConcatenated());
        cert = authreq.getRequest();
        assertEquals(cvcacert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated(), cert.getCertificateBody()
                .getAuthorityReference().getConcatenated());
        String sequence3 = cert.getCertificateBody().getHolderReference().getSequence();
        int s3 = Integer.parseInt(sequence3);
        assertEquals(s2 + 1, s3); // sequence in new certificate request should
        // be old certificate sequence + 1
        // status should not be "WAITING_FOR_CERTIFICATE_RESPONSE"
        dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_ACTIVE);
        // Check to see that is really is a new keypair
        dvcerts = dvinfo.getCertificateChain();
        assertEquals(2, dvcerts.size());
        dvcertactive = (CardVerifiableCertificate) dvcerts.iterator().next();
        String sequence4 = dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
        assertEquals(sequence2, sequence4);
        PublicKey oldPublicKey = dvcertactive.getPublicKey();
        PublicKey newPublicKey = cert.getCertificateBody().getPublicKey();
        pubk1 = new String(Base64.encode(oldPublicKey.getEncoded(), false));
        pubk2 = new String(Base64.encode(newPublicKey.getEncoded(), false));
        assertTrue(pubk1.compareTo(pubk2) != 0);

        // Try to issue an IS certificate, it should be issued using the OLD
        // private key
        // Simple self signed request
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        CVCertificate isrequest = CertificateGenerator.createRequest(keyPair, signalg, caRef, holderRef);
        // Edit our favorite test user
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER1");
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=Test,C=SE");
        user1.setCaName(caname);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        user1.setTokenType("USERGENERATED");
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        // editUser and set status to new
        ejbcaraws.editUser(user1);
        List<Certificate> certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(isrequest.getDEREncoded())));
        assertNotNull(certenv);
        Certificate wscert = certenv.get(0);
        byte[] b64cert = wscert.getCertificateData();
        java.security.cert.Certificate iscert = CertTools.getCertfromByteArray(Base64.decode(b64cert));
        obj = CertificateParser.parseCVCObject(Base64.decode(b64cert));
        CVCertificate iscvc = (CVCertificate) obj;
        assertEquals("Test", iscvc.getCertificateBody().getHolderReference().getMnemonic());
        // It must verify using the DVCAs old public key
        iscert.verify(oldPublicKey);
        boolean thrown = false;
        try {
            // it must not be possible to verify this with the new public key
            iscert.verify(newPublicKey);
        } catch (SignatureException e) {
            thrown = true;
        }
        assertTrue(thrown);

        // Receive the CA certificate response so the DV CA's new key is
        // activated
        dvholderref = cert.getCertificateBody().getHolderReference();
        dvretcert = CertificateGenerator.createTestCertificate(cert.getCertificateBody().getPublicKey(), cvcakeypair.getPrivate(), caRef, dvholderref,
        		signalg, AuthorizationRoleEnum.DV_D);
        // Here we want to activate the new key pair
        // System.out.println(dvretcert.getAsText());
        ejbcaraws.caCertResponse(caname, dvretcert.getDEREncoded(), cachain, pwd);
        // Check that the cert was received and the CA activated
        dvinfo = getCAAdminSession().getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getStatus(), SecConst.CA_ACTIVE);
        dvcerts = dvinfo.getCertificateChain();
        assertEquals(2, dvcerts.size());
        dvcertactive = (CardVerifiableCertificate) dvcerts.iterator().next();
        obj = CertificateParser.parseCVCObject(dvcertactive.getEncoded());
        // System.out.println(obj.getAsText());
        dvcertactive.verify(cvcakeypair.getPublic());
        String sequence5 = dvcertactive.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
        assertEquals(sequence3, sequence5); // sequence in new certificate
        // should be same as sequence in
        // request, which was old sequence +
        // 1
        // Check to see that is really is the new keypair
        pubk1 = new String(Base64.encode(dvcertactive.getPublicKey().getEncoded(), false));
        pubk2 = new String(Base64.encode(newPublicKey.getEncoded(), false));
        assertEquals(pubk1, pubk2);
        // Finally verify that we can issue an IS certificate and verify with
        // the new public key, i.e. it is signed by the new private key
        // Simple self signed request
        isrequest = CertificateGenerator.createRequest(keyPair, signalg, caRef, holderRef);
        // Edit our favorite test user
        user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER1");
        user1.setPassword("foo123");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=Test1,C=SE");
        user1.setCaName(caname);
        user1.setStatus(UserDataConstants.STATUS_NEW);
        user1.setTokenType("USERGENERATED");
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        // editUser and set status to new
        ejbcaraws.editUser(user1);
        certenv = ejbcaraws.cvcRequest(user1.getUsername(), user1.getPassword(), new String(Base64.encode(isrequest.getDEREncoded())));
        assertNotNull(certenv);
        wscert = certenv.get(0);
        b64cert = wscert.getCertificateData();
        iscert = CertTools.getCertfromByteArray(Base64.decode(b64cert));
        obj = CertificateParser.parseCVCObject(Base64.decode(b64cert));
        iscvc = (CVCertificate) obj;
        assertEquals("Test1", iscvc.getCertificateBody().getHolderReference().getMnemonic());
        // It must verify using the DVCAs new public key, wsich is the same as
        // the one we imported
        iscert.verify(dvcertactive.getPublicKey());
        iscert.verify(dvretcert.getCertificateBody().getPublicKey());

    } // test34CaRenewCertRequest

    protected void cleanUpCACertRequest() throws Exception {
        // Remove CAs created by previous test test34CaRenewCertRequest
        deleteDVCAExt();
    }

    protected void cleanUpAdmins() throws Exception {
        if (getUserAdminSession().existsUser(intAdmin, TEST_ADMIN_USERNAME)) {
            // Remove from admin group
            CAInfo cainfo = getCAAdminSession().getCAInfo(intAdmin, getAdminCAName());
            AdminGroup admingroup = getAuthSession().getAdminGroup(intAdmin, AdminGroup.TEMPSUPERADMINGROUP);
            Iterator iter = admingroup.getAdminEntities().iterator();
            while (iter.hasNext()) {
                AdminEntity adminEntity = (AdminEntity) iter.next();
                if (adminEntity.getMatchValue().equals(TEST_ADMIN_USERNAME)) {
                    ArrayList<AdminEntity> list = new ArrayList<AdminEntity>();
                    list.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASE, TEST_ADMIN_USERNAME, cainfo.getCAId()));
                    getAuthSession().removeAdminEntities(intAdmin, AdminGroup.TEMPSUPERADMINGROUP, list);
                    getAuthSession().forceRuleUpdate(intAdmin);
                }
            }
            // Remove user
            getUserAdminSession().revokeAndDeleteUser(intAdmin, TEST_ADMIN_USERNAME, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        }
        if (getUserAdminSession().existsUser(intAdmin, TEST_NONADMIN_USERNAME)) {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, TEST_NONADMIN_USERNAME, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        }
        if (new File("p12/" + TEST_ADMIN_USERNAME + ".jks").exists()) {
            new File("p12/" + TEST_ADMIN_USERNAME + ".jks").delete();
        }
        if (new File("p12/" + TEST_NONADMIN_USERNAME + ".jks").exists()) {
            new File("p12/" + TEST_NONADMIN_USERNAME + ".jks").delete();
        }

        // Remove test user
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER1, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER2, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, CA2_WSTESTUSER1, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER1CVCRSA, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, CA2_WSTESTUSER1CVCEC, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTUSERKEYREC1", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTUSER30", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            getUserAdminSession().revokeAndDeleteUser(intAdmin, "WSTESTUSER31", RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Remove Key recovery end entity profile
        try {
            getRAAdmin().removeEndEntityProfile(intAdmin, "KEYRECOVERY");
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            TestTools.removeTestCA(CA1);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            TestTools.removeTestCA(CA2);
        } catch (Exception e) {
            e.printStackTrace();
        }

    } 


    /**
     * Create a CVCA, and a DV CA signed by the CVCA
     * 
     */
    private void createCVCCA(String rootcadn, String rootcaname, String subcadn, String subcaname, String keyspec, String keyalg, String signalg) throws Exception {
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignKeySpec(keyspec);
        catokeninfo.setEncKeySpec("1024");
        catokeninfo.setSignKeyAlgorithm(keyalg);
        catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setSignatureAlgorithm(signalg);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        // No CA Services.
        List extendedcaservices = new ArrayList();

        java.security.cert.Certificate cvcacert = null;
        int cvcaid = rootcadn.hashCode();
        try {
            getAuthSession().initialize(intAdmin, rootcadn.hashCode(), TestTools.defaultSuperAdminCN);

            CVCCAInfo cvccainfo = new CVCCAInfo(rootcadn, rootcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, CAInfo.SELFSIGNED, null, catokeninfo, "JUnit WS CVC CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false // isDoEnforceUniqueSibjectDNSerialnumber
            );

            getCAAdminSession().createCA(intAdmin, cvccainfo);

            CAInfo info = getCAAdminSession().getCAInfo(intAdmin, rootcaname);
            cvcaid = info.getCAId();
            assertEquals(CAInfo.CATYPE_CVC, info.getCAType());
            Collection col = info.getCertificateChain();
            assertEquals(1, col.size());
            Iterator iter = col.iterator();
            cvcacert = (java.security.cert.Certificate) iter.next();
        } catch (CAExistsException pee) {
            pee.printStackTrace();
        }

        try {

            CVCCAInfo cvcdvinfo = new CVCCAInfo(subcadn, subcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, cvcaid, null, catokeninfo, "JUnit WS CVC DV CA", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false // isDoEnforceUniqueSubjectDNSerialnumber
            );

            getCAAdminSession().createCA(intAdmin, cvcdvinfo);

            CAInfo info = getCAAdminSession().getCAInfo(intAdmin, subcaname);
            assertEquals(CAInfo.CATYPE_CVC, info.getCAType());
            Collection col = info.getCertificateChain();
            assertEquals(2, col.size());
            Iterator iter = col.iterator();
            java.security.cert.Certificate dvcacert = (java.security.cert.Certificate) iter.next();
            dvcacert.verify(cvcacert.getPublicKey());
        } catch (CAExistsException pee) {
            pee.printStackTrace();
        }
    }

    /**
     * Create a DVCA, signed by an external CVCA
     * 
     */
    private String createDVCCASignedByExternal(String keyspec, String keyalg, String signalg) throws Exception {
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignKeySpec(keyspec);
        catokeninfo.setEncKeySpec("1024");
        catokeninfo.setSignKeyAlgorithm(keyalg);
        catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setSignatureAlgorithm(signalg);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // No CA Services.
        ArrayList extendedcaservices = new ArrayList();

        try {
            String dvcadn = "CN=WSDVEXT,C=SE";
            String dvcaname = "WSTESTDVCASIGNEDBYEXTERNAL";

            CVCCAInfo cvcdvinfo = new CVCCAInfo(dvcadn, dvcaname, SecConst.CA_ACTIVE, new Date(), SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                    CAInfo.CATYPE_CVC, CAInfo.SIGNEDBYEXTERNALCA, null, catokeninfo, "JUnit WS CVC DV signed by external", -1, null, 24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList(), // CRL publishers
                    true, // Finish User
                    extendedcaservices, new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    true, // Include in health check
                    true, // isDoEnforceUniquePublicKeys
                    true, // isDoEnforceUniqueDistinguishedName
                    false // isDoEnforceUniqueSubjectDNSerialnumber
            );

            getCAAdminSession().createCA(intAdmin, cvcdvinfo);
            CAInfo info = getCAAdminSession().getCAInfo(intAdmin, dvcaname);
            assertEquals(CAInfo.CATYPE_CVC, info.getCAType());
            // It is signed by external so no certificates exists yet
            Collection col = info.getCertificateChain();
            assertEquals(0, col.size());
            return info.getName();
        } catch (CAExistsException pee) {
            pee.printStackTrace();
        }
        return null;
    }

    /**
     * Delete the CVCA and DVCA
     * 
     */
    protected void deleteCVCCA(String rootcadn, String subcadn) throws Exception {
        // Clean up by removing the CVC CA
        try {
            String dn = CertTools.stringToBCDNString(rootcadn);
            getCAAdminSession().removeCA(intAdmin, dn.hashCode());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        try {
            String dn = CertTools.stringToBCDNString(subcadn);
            getCAAdminSession().removeCA(intAdmin, dn.hashCode());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    private void deleteDVCAExt() throws Exception {
        // Clean up by removing the DVCA signed by external
        try {
            String dn = CertTools.stringToBCDNString("CN=WSDVEXT,C=SE");
            getCAAdminSession().removeCA(intAdmin, dn.hashCode());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Create a user a generate cert.
     */
    private X509Certificate createUserAndCert(String username, int caID) throws Exception {
        UserDataVO userdata = new UserDataVO(username, "CN=" + username, caID, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        getUserAdminSession().addUser(intAdmin, userdata, true);
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        Collection userCerts = getCertStore().findCertificatesByUsername(intAdmin, username);
        assertTrue(userCerts.size() == 1);
        return (X509Certificate) userCerts.iterator().next();
    }

    /**
     * Creates a "hardtoken" with certficates.
     */
    private void createHardToken(String username, String caName, String serialNumber) throws Exception {
        GlobalConfiguration gc = getRAAdmin().loadGlobalConfiguration(intAdmin);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
        if (getCertStore().getCertificateProfileId(intAdmin, "WSTESTPROFILE") != 0) {
            getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        }
        CertificateProfile profile = new EndUserCertificateProfile();
        profile.setAllowValidityOverride(true);
        getCertStore().addCertificateProfile(intAdmin, "WSTESTPROFILE", profile);
        UserDataVOWS tokenUser1 = new UserDataVOWS();
        tokenUser1.setUsername(username);
        tokenUser1.setPassword("foo123");
        tokenUser1.setClearPwd(true);
        tokenUser1.setSubjectDN("CN=" + username);
        tokenUser1.setCaName(caName);
        tokenUser1.setEmail(null);
        tokenUser1.setSubjectAltName(null);
        tokenUser1.setStatus(UserDataVOWS.STATUS_NEW);
        tokenUser1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        tokenUser1.setEndEntityProfileName("EMPTY");
        tokenUser1.setCertificateProfileName("ENDUSER");
        KeyPair basickeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOTUSED"), basickeys
                .getPublic(), new DERSet(), basickeys.getPrivate());
        ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
        TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
        tokenCertReqWS.setCAName(caName);
        tokenCertReqWS.setCertificateProfileName("WSTESTPROFILE");
        tokenCertReqWS.setValidityIdDays("1");
        tokenCertReqWS.setPkcs10Data(basicpkcs10.getDEREncoded());
        tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST);
        requests.add(tokenCertReqWS);
        tokenCertReqWS = new TokenCertificateRequestWS();
        tokenCertReqWS.setCAName(caName);
        tokenCertReqWS.setCertificateProfileName("ENDUSER");
        tokenCertReqWS.setKeyalg("RSA");
        tokenCertReqWS.setKeyspec("1024");
        tokenCertReqWS.setType(HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST);
        requests.add(tokenCertReqWS);
        HardTokenDataWS hardTokenDataWS = new HardTokenDataWS();
        hardTokenDataWS.setLabel(HardTokenConstants.LABEL_PROJECTCARD);
        hardTokenDataWS.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
        hardTokenDataWS.setHardTokenSN(serialNumber);
        PinDataWS basicPinDataWS = new PinDataWS();
        basicPinDataWS.setType(HardTokenConstants.PINTYPE_BASIC);
        basicPinDataWS.setInitialPIN("1234");
        basicPinDataWS.setPUK("12345678");
        PinDataWS signaturePinDataWS = new PinDataWS();
        signaturePinDataWS.setType(HardTokenConstants.PINTYPE_SIGNATURE);
        signaturePinDataWS.setInitialPIN("5678");
        signaturePinDataWS.setPUK("23456789");
        hardTokenDataWS.getPinDatas().add(basicPinDataWS);
        hardTokenDataWS.getPinDatas().add(signaturePinDataWS);
        List<TokenCertificateResponseWS> responses = ejbcaraws.genTokenCertificates(tokenUser1, requests, hardTokenDataWS, true, false);
        assertTrue(responses.size() == 2);
        getCertStore().removeCertificateProfile(intAdmin, "WSTESTPROFILE");
        gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
        getRAAdmin().saveGlobalConfiguration(intAdmin, gc);
    } // createHardToken
}
