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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.cvc.CvCertificateUtility;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorProxySessionRemote;
import org.cesecore.keys.validation.KeyValidatorSessionSystemTest;
import org.cesecore.keys.validation.KeyValidatorSettingsTemplate;
import org.cesecore.keys.validation.RsaKeyValidator;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalProfileExistsException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.unidfnr.UnidFnrHandlerMock;
import org.ejbca.core.ejb.unidfnr.UnidfnrProxySessionRemote;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalSystemTest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.CesecoreException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.KeyValuePair;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.UnknownProfileTypeException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.cvc.CVCProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CeSecoreNameStyle;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;

/**
 * System tests for the EjbcaWS API. This test uses remote EJB calls to setup the environment.
 * <p>
 * The tests have five pre-requisites (all fulfilled in a "default" EJBCA installation):
 * <li>A CA named ManagementCA or AdminCA1 must exist, and:
 *     <ul>
 *     <li>That CA must be trusted in the appserver truststore.
 *     <li>That CA must have issued the EJBCA server certificate.
 *     </ul>
 * <li>If you use different names, you can configure alternate CA names systemtests.properties.
 * <li>If EJBCA is not running on localhost, then target.hostname must be configured in systemtests.properties
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EjbcaWSSystemTest extends CommonEjbcaWs {

    private static final Logger log = Logger.getLogger(EjbcaWSSystemTest.class);

    public final static String WS_TEST_ROLENAME = "WsTestRoleMgmt";
    private final static String WS_TEST_CERTIFICATE_PROFILE_NAME = "WSTESTPROFILE";
    private static final String KEY_RECOVERY_EEP = "KEYRECOVERY";
    private static final String BADCANAME = "BadCaName";

    private static final String PKCS10 = "MIIChTCCAW0CAQAwQDELMAkGA1UEBhMCU0UxDjAMBgNVBAgMBVNvbG5hMREwDwYD" + 
            "VQQKDAhQcmltZUtleTEOMAwGA1UEAwwFVG9tYXMwggEiMA0GCSqGSIb3DQEBAQUA" + 
            "A4IBDwAwggEKAoIBAQDfOpmUDnUsilYoaYpHUGN9AvAkK2AdHoYz4cTkKD4kPPvq" + 
            "ErRdayyGWiuKrmhH6v+jPvh5ZYQoqL2viSTIkcvr7BIo9pgqSVswxvC5v4GGy3R4" + 
            "nme0El27oB5X0AJl3X5STT5GwIWw66XHcTeg1ux62bfY/N1RhiHanFOZ00DokPyW" + 
            "/s+dGcnZ9kBC5s5jcEEEwcGXCyKuyCoy60Z87asOraCsYeRlq3qqdms0BZEM7lLK" + 
            "7oP4HjIpk9VSLYihGlFsbophw96gNGtYjorX//CYvuyckUpA9TLdfx8IoQSiKlsJ" + 
            "CDdMeDXnkqOZAmXj3xos3qm1VJV2J9AVggzQ1SUnAgMBAAGgADANBgkqhkiG9w0B" + 
            "AQsFAAOCAQEAGcK8aMvmdhsTeCv+D1R21Bjc5fb+dmrXcYdR4RI8roW4GZDqGdBU" + 
            "8bYDZfO0SnV0q6m23G6upVhtYpzOrVcDaiQ4iFvGQkz8pfErZ+qqwZhE6yvbc+2p" + 
            "0BVuIIePbgdAW17acxkOF4p0Z5TkNazdNwePyjW8dfUvarVX//AA48l66bUXu6IM" + 
            "X2LU/OY1hcLETlAqV2o1iDPRsOTnF2OpV8FdmpBhD7VUa78h8n3w3l+WdmaAhcy4" + 
            "jItzjKHi5CEoJ3s15Yo4zuwZt2g+bmGGfBqGcSKkPAlsQ+A79DMwzJXLN/Cs/joY" + 
            "gwObGYEkQqkX1DGjDNzYyw+RtvdzJV8shQ==";

    private static final String CRMF = "MIIBdjCCAXIwgdkCBQCghr4dMIHPgAECpRYwFDESMBAGA1UEAxMJdW5kZWZpbmVk"
            + "poGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCi6+Bmo+0I/ye8k6B6BkhXgv03" + "1jEeD3mEuvjIEZUmmdt2RBvW2qfJzqXV8dsI1HZT4fZqo8SBsrYls4AC7HooWI6g"
            + "DjSyd3kFcb5HP+qnNlz6De/Ab+qAF1rLJhfb2cXib4C7+bap2lwA56jTjY0qWRYb" + "v3IIfxEEKozVlbg0LQIDAQABqRAwDgYDVR0PAQH/BAQDAgXgoYGTMA0GCSqGSIb3"
            + "DQEBBQUAA4GBAJEhlvfoWNIAOSvFnLpg59vOj5jG0Urfv4w+hQmtCdK7MD0nyGKU" + "cP5CWCau0vK9/gikPoA49n0PK81SPQt9w2i/A81OJ3eSLIxTqi8MJS1+/VuEmvRf"
            + "XvedU84iIqnjDq92dTs6v01oRyPCdcjX8fpHuLk1VA96hgYai3l/D8lg";
    
    private static final String PUBLICKEY_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC/kSfVJ/hyq96xwRRwVdO0ltD\n"
            + "glRyKhVhA0OyI/4ux4a0NIxD4OVstfQmoyt/X7olMG29mZGpinQC6wuaaL0JJ9To\n"
            + "ejr41IwvDrkLKQKdY+mAJ8zUUWFWYqbcurTXrYJCYeG/ETAJZLfD4EKMNCd/lC/r\n" + "G4yg9pzLOMjNr2tQ4wIDAQAB";
    
    private static final String PUBLICKEY_PEM = "-----BEGIN PUBLIC KEY-----\n" + PUBLICKEY_BASE64 + "\n-----END PUBLIC KEY-----";

    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private final CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final EjbcaWSHelperSessionRemote ejbcaWSHelperSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaWSHelperSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final KeyValidatorProxySessionRemote keyValidatorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final UnidfnrProxySessionRemote unidfnrProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST); 
    
    private static char[] originalForbiddenChars;
    private final static SecureRandom secureRandom;

    static {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<File> fileHandles = new ArrayList<>();

    private GlobalConfiguration originalGlobalConfiguration = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);
        CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        originalForbiddenChars = cesecoreConfigurationProxySession.getForbiddenCharacters();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new CvCertificateUtility());
        Security.addProvider(new CVCProvider());   
    }

    @Before
    public void setUpAdmin() throws Exception {
        adminSetUpAdmin();
        originalGlobalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpAdmins(WS_ADMIN_ROLENAME);
        cleanUpAdmins(WS_TEST_ROLENAME);
        CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        cesecoreConfigurationProxySession.setForbiddenCharacters(originalForbiddenChars);
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    @Override
    public String getRoleName() {
        return WS_TEST_ROLENAME;
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        // Restore WS admin access
        setAccessRulesForWsAdmin(Collections.singletonList(StandardRules.ROLE_ROOT.resource()), null);
        // Restore key recovery, end entity profile limitations etc
        if (originalGlobalConfiguration!=null) {
            globalConfigurationSession.saveConfiguration(intAdmin, originalGlobalConfiguration);
        }
    }


    /** This test is not a WebService test, but for simplicity it re-uses the created administrator certificate in order to connect to the
     * EJBCA Admin Web and verify returned security headers.
     * @throws IOException
     * @throws CertificateException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws UnrecoverableKeyException
     */
    @Test
    public void testAdminWebSecurityHeaders() throws UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        HttpURLConnection con = super.getHttpsURLConnection("https://" + hostname + ":" + httpsPort + "/ejbca/adminweb/index.xhtml");
        String xframe = con.getHeaderField("X-FRAME-OPTIONS");
        String csp = con.getHeaderField("content-security-policy");
        String xcsp = con.getHeaderField("x-content-security-policy");
        con.disconnect();
        assertNotNull("Admin web page should return X-FRAME-OPTIONS header", xframe);
        assertNotNull("Admin web page should return content-security-policy header", csp);
        assertNotNull("Admin web page should return x-content-security-policy header", xcsp);
        assertEquals("Admin web page should return X-FRAME-OPTIONS SAMEORIGIN", "SAMEORIGIN", xframe);
        assertEquals("Admin web page should return csp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", 
                "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", csp);
        assertEquals("Admin web page should return xcsp default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", 
                "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; reflected-xss block", xcsp);
    }

    @Test
    public void testCaRolloverCommands() throws Exception {
        final String rootCaName ="RollOverRootCA";
        final String rootCaDn = "CN="+rootCaName;
        final String subCaName = "RollOverSubCA";
        final String subCaSubjectDn = "CN=" + subCaName;
        X509CA subCA = null;
        X509CA rootCA = null;
        try {
            //rootCA a rootCA
            rootCA = CaTestUtils.createTestX509CA(rootCaDn, PASSWORD.toCharArray(), false);
            caSession.addCA(intAdmin, rootCA);
            X509Certificate cacert = (X509Certificate) rootCA.getCACertificate();
            certificateStoreSession.storeCertificateRemote(intAdmin, EJBTools.wrap(cacert), "testuser", "1234",  CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_NO_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, null, new Date().getTime(), null);
            //Create a SubCA for this test.
            subCA = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(intAdmin, subCaSubjectDn, rootCA.getCAId());
            int cryptoTokenId = subCA.getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.createKeyPair(intAdmin, cryptoTokenId, "signKeyAlias", KeyGenParams.builder("RSA1024").build());
            X509Certificate subCaCertificate = (X509Certificate) subCA.getCACertificate();
            //Store the CA Certificate.
            certificateStoreSession.storeCertificateRemote(intAdmin, EJBTools.wrap(subCaCertificate), "foo", "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_SUBCA, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, EndEntityConstants.NO_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION, "footag", new Date().getTime(), null);
            final EndEntityInformation endentity = new EndEntityInformation(subCaName, subCaSubjectDn, rootCA.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, null);
            endentity.setStatus(EndEntityConstants.STATUS_NEW);
            endentity.setPassword("foo123");
            final ExtendedInformation ei = new ExtendedInformation();
            long rolloverStartTime = System.currentTimeMillis()+7L*24L*3600L*1000L;

            ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, ValidityDate.formatAsUTC(rolloverStartTime));
            ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, ValidityDate.formatAsUTC(rolloverStartTime+14L*24L*3600L*1000L));
            endentity.setExtendedInformation(ei);

            //Make sure there is a rollover certificate in store
            final byte[] requestbytes = caAdminSessionRemote.makeRequest(intAdmin, subCA.getCAId(), null, null);
            final PKCS10RequestMessage req = new PKCS10RequestMessage(requestbytes);
            final X509ResponseMessage respmsg = (X509ResponseMessage) certificateCreateSession.createCertificate(intAdmin, endentity, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate newCertificate =  (X509Certificate) respmsg.getCertificate();
            ejbcaraws.caCertResponseForRollover(subCaName, newCertificate.getEncoded(), null, "foo123");

            //Check that sub CA has a rollover certificate
            Certificate rolloverCertificate = caSession.getFutureRolloverCertificate(subCA.getCAId());
            assertNotNull("No rollover certificate was found in subCA", rolloverCertificate);
            X509CAInfo subCAInfo = (X509CAInfo) caSession.getCAInfo(intAdmin, subCA.getCAId());
            assertFalse("CA was unintentionally rolled over.", subCAInfo.getCertificateChain().iterator().next().equals(rolloverCertificate));
            //Perform the rollover
            ejbcaraws.rolloverCACert(subCaName);
            subCAInfo = (X509CAInfo) caSession.getCAInfo(intAdmin, subCA.getCAId());
            assertTrue("CA was not rolled over.", subCAInfo.getCertificateChain().iterator().next().equals(rolloverCertificate));

        } finally {
            if (subCA != null) {
                CaTestUtils.removeCa(intAdmin, subCA.getCAInfo());
            }
            if(rootCA != null) {
                CaTestUtils.removeCa(intAdmin, rootCA.getCAInfo());
            }
            internalCertificateStoreSession.removeCertificatesBySubject(subCaSubjectDn);
            internalCertificateStoreSession.removeCertificatesBySubject(rootCaDn);

        }
    }

    @Test
    public void test01EditUser() throws Exception {
        super.editUser();
    }

    @Test
    public void test03_1GeneratePkcs10() throws Exception {
        generatePkcs10();
    }

    @Test
    public void test03_2GenerateCrmfNoPop() throws Exception {
        generateCrmf(false, false, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSign() throws Exception {
        generateCrmf(true, false, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSignPkMac() throws Exception {
        generateCrmf(true, true, false);
    }
    @Test
    public void test03_2GenerateCrmfPopSignSender() throws Exception {
        generateCrmf(true, false, true);
    }

    @Test
    public void test03_3GenerateSpkac() throws Exception {
        generateSpkac();
    }

    @Test
    public void test03_4GeneratePkcs10Request() throws Exception {
        generatePkcs10Request();
    }

    @Test
    public void test03_5CertificateRequest() throws Exception {
        final UserDataVOWS userData1 = getUserData(CA1_WSTESTUSER1);
        org.ejbca.core.protocol.ws.client.gen.ErrorCode errorCode = certreqInternal(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNull("PKCS#10 request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, CRMF, CertificateHelper.CERT_REQ_TYPE_CRMF);
        assertNull("CRMF request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, SPCAK, CertificateHelper.CERT_REQ_TYPE_SPKAC);
        assertNull("SPKAC request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, PUBLICKEY_PEM, CertificateHelper.CERT_REQ_TYPE_PUBLICKEY);
        assertNull("PUBLICKEY request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);
        errorCode = certreqInternal(userData1, PUBLICKEY_BASE64, CertificateHelper.CERT_REQ_TYPE_PUBLICKEY);
        assertNull("PUBLICKEY request resulted in error code: " + (errorCode == null ? "" : errorCode.getInternalErrorCode()), errorCode);

        // Test with custom extensions
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

        userData1.setStatus(EndEntityConstants.STATUS_NEW);
        userData1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userData1.setEndEntityProfileName(WS_EEPROF_EI);
        userData1.setCertificateProfileName(WS_CERTPROF_EI);
        ejbcaraws.editUser(userData1);
        CertificateResponse certificateResponse = ejbcaraws.certificateRequest(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);
        X509Certificate cert = certificateResponse.getCertificate();
        byte[] ext = cert.getExtensionValue("1.2.3.4");
        // Certificate profile did not allow extension override
        assertNull("no extension should exist", ext);
        // Allow extension override
        CertificateProfile profile = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
        profile.setAllowExtensionOverride(true);
        certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);
        // Now our extension should be possible to get in there
        try {
            ejbcaraws.editUser(userData1);
            certificateResponse = ejbcaraws.certificateRequest(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            cert = certificateResponse.getCertificate();
            assertNotNull(cert);
            assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
            ext = cert.getExtensionValue("1.2.3.4");
            assertNotNull("there should be an extension", ext);
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(ext))) {
                final ASN1OctetString oct = ASN1OctetString.getInstance(asn1InputStream.readObject());
                assertEquals("Extension did not have the correct value", "foo123", (new String(oct.getOctets())).trim());
            }
        } finally {
            // restore
            profile.setAllowExtensionOverride(false);
            certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);
        }

        // Make a test with EV TLS DN components
        try {
            final UserDataVOWS userData2 = getUserData(CA1_WSTESTUSER1);
            userData2.setUsername("EVTLSEJBCAWSTEST");
            userData2.setSubjectDN("CN=EVTLSEJBCAWSTEST,JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna");
            try {
                certificateResponse = ejbcaraws.certificateRequest(userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                        CertificateHelper.RESPONSETYPE_CERTIFICATE);
                // Verify that the response is of the right type
                assertNotNull(certificateResponse);
                assertTrue(certificateResponse.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
                // Verify that the certificate in the response has the same Subject DN
                // as in the request.
                cert = certificateResponse.getCertificate();
                assertNotNull(cert);
                assertEquals("JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,CN=EVTLSEJBCAWSTEST",
                        CertTools.getSubjectDN(cert));
            } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
                // If running EJBCA Community this will be the result of this
                if (!enterpriseEjbBridgeSession.isRunningEnterprise()) {
                    log.debug("Community Edition, JurisdictionXY DN components are not available");
                } else {
                    log.info("Certificate request with EV TLS DN components should not fail on Enterprise Edition", e);
                    fail("Certificate request with EV TLS DN components should not fail on Enterprise Edition: " + e.getMessage());
                }
            } catch (EjbcaException_Exception e) {
                errorCode = e.getFaultInfo().getErrorCode();
                log.info(errorCode.getInternalErrorCode(), e);
                assertNotNull("error code should not be null", errorCode);
                fail("certificate request with EV TLS DN components failed with error code " + errorCode.getInternalErrorCode());
            }
        } finally {
            // Clean up immediately
            if (endEntityManagementSession.existsUser("EVTLSEJBCAWSTEST")) {
                endEntityManagementSession.deleteUser(admin, "EVTLSEJBCAWSTEST");
            }
            internalCertificateStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert));
        }
    }
    
    /**
     * Test running a certificate request (including creating an end entity) using the UnidFnr plugin
     */
    @Test
    public void testEditUserWithUnidFnr() throws InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateProfileExistsException, AuthorizationDeniedException, EndEntityProfileExistsException, CryptoTokenOfflineException,
            InvalidAlgorithmException, CAExistsException, ApprovalException_Exception, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception, IOException, CertificateException, CouldNotRemoveEndEntityException, CADoesntExistsException_Exception, CesecoreException_Exception {
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final String username = "testEditUserWithUnidFnr";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN="+username;
       
        
        final String profileNameUnidPrefix = "1234-5678-";
        final String profileName = profileNameUnidPrefix + "testEditUserWithUnidFnr";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(intAdmin, profileName, certificateProfile);
        
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);       
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, endEntityProfile);
        
        final String issuerDN = "CN=testEditUserWithUnidFnrCa";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false, X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo testX509CaInfo = (X509CAInfo) testX509Ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testX509Ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(intAdmin, testX509Ca);
        final UserDataVOWS endEntity = new UserDataVOWS();
        endEntity.setUsername(username);
        endEntity.setPassword(password);
        endEntity.setClearPwd(false);
        endEntity.setSubjectDN(subjectDn);
        endEntity.setCaName(testX509CaInfo.getName());
        endEntity.setEmail(null);
        endEntity.setSubjectAltName(null);
        endEntity.setStatus(EndEntityConstants.STATUS_NEW);
        endEntity.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        endEntity.setEndEntityProfileName(profileName);
        endEntity.setCertificateProfileName(profileName);
        endEntity.setExtendedInformation(new ArrayList<ExtendedInformationWS>());        
       
        try {
            ejbcaraws.editUser(endEntity);
            EndEntityInformation createdUser = endEntityAccessSession.findUser(intAdmin, username);
            final String endEntityInformationUnid = IETFUtils.valueToString(
                    DnComponents.stringToBcX500Name(createdUser.getCertificateDN()).getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            final String resultingFnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(endEntityInformationUnid);
            assertNotNull("Unid value was not stored", resultingFnr);
            assertEquals("FNR value was not correctly converted", fnr, resultingFnr);      
            //Generate a certificate, see what happens. 
            PKCS10CertificationRequest request = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, DnComponents.stringToBcX500Name(subjectDn),
                    keys.getPublic(), null, keys.getPrivate(), null);
            //Yeah, what happens, Shoresy?
            CertificateResponse response = ejbcaraws.pkcs10Request(username, password, new String(Base64.encode(request.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE); 
            X509Certificate certificate = response.getCertificate();
            final X500Name x500Name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            final String unidFromCertificate = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            assertEquals("serialNumber value in certificate was not the same as in end entity", endEntityInformationUnid, unidFromCertificate);
           
                
        } finally {
            CaTestUtils.removeCa(intAdmin, testX509CaInfo);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, profileName);
            try {
                endEntityManagementSession.deleteUser(intAdmin, username);
            } catch (NoSuchEndEntityException e) {
                //NOPMD
            } 
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
    }
    
    /**
     * Test running a certificate request (including creating an end entity) using the UnidFnr plugin for ML-DSA-44 Protocol
     */
    @Test
    public void testEditUserWithUnidFnrUsingMlDsa()
            throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateProfileExistsException, AuthorizationDeniedException,
            EndEntityProfileExistsException, CryptoTokenOfflineException, InvalidAlgorithmException, CAExistsException, ApprovalException_Exception,
            AuthorizationDeniedException_Exception, EjbcaException_Exception, NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, IOException, CertificateException,
            CouldNotRemoveEndEntityException, CADoesntExistsException_Exception, CesecoreException_Exception {
        final KeyPair keys = KeyTools.genKeys("ML-DSA-44", AlgorithmConstants.KEYALGORITHM_MLDSA44);
        final String username = "testEditUserWithUnidFnrUsingMlDsa";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN=" + username;

        final String profileNameUnidPrefix = "1234-5678-";
        final String profileName = profileNameUnidPrefix + "testEditUserWithUnidFnrUsingMlDsa";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(intAdmin, profileName, certificateProfile);

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, endEntityProfile);

        final String issuerDN = "CN=testEditUserWithUnidFnrUsingMlDsaCa";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false,
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo testX509CaInfo = (X509CAInfo) testX509Ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testX509Ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(intAdmin, testX509Ca);
        final UserDataVOWS endEntity = new UserDataVOWS();
        endEntity.setUsername(username);
        endEntity.setPassword(password);
        endEntity.setClearPwd(false);
        endEntity.setSubjectDN(subjectDn);
        endEntity.setCaName(testX509CaInfo.getName());
        endEntity.setEmail(null);
        endEntity.setSubjectAltName(null);
        endEntity.setStatus(EndEntityConstants.STATUS_NEW);
        endEntity.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        endEntity.setEndEntityProfileName(profileName);
        endEntity.setCertificateProfileName(profileName);
        endEntity.setExtendedInformation(new ArrayList<ExtendedInformationWS>());

        try {
            ejbcaraws.editUser(endEntity);
            EndEntityInformation createdUser = endEntityAccessSession.findUser(intAdmin, username);
            final String endEntityInformationUnid = IETFUtils.valueToString(
                    DnComponents.stringToBcX500Name(createdUser.getCertificateDN()).getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            final String resultingFnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(endEntityInformationUnid);
            assertNotNull("Unid value was not stored", resultingFnr);
            assertEquals("FNR value was not correctly converted", fnr, resultingFnr);
            //Generate a certificate, see what happens. 
            PKCS10CertificationRequest request = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.KEYALGORITHM_MLDSA44,
                    DnComponents.stringToBcX500Name(subjectDn), keys.getPublic(), null, keys.getPrivate(), null);
            //Yeah, what happens, Shoresy?
            CertificateResponse response = ejbcaraws.pkcs10Request(username, password, new String(Base64.encode(request.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            X509Certificate certificate = response.getCertificate();
            final X500Name x500Name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            final String unidFromCertificate = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            assertEquals("serialNumber value in certificate was not the same as in end entity", endEntityInformationUnid, unidFromCertificate);

        } finally {
            CaTestUtils.removeCa(intAdmin, testX509CaInfo);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, profileName);
            try {
                endEntityManagementSession.deleteUser(intAdmin, username);
            } catch (NoSuchEndEntityException e) {
                //NOPMD
            }
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
    }
    
    /**
     * Test running a certificate request (including creating an end entity) using the UnidFnr plugin
     */
    @Test
    public void testCertificateRequestWithUnidFnr() throws InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateProfileExistsException, AuthorizationDeniedException, EndEntityProfileExistsException, CryptoTokenOfflineException,
            InvalidAlgorithmException, CAExistsException, ApprovalException_Exception, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception, IOException, CertificateException, CouldNotRemoveEndEntityException {
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final String username = "testCertificateRequestWithUnidFnr";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN="+username;
        PKCS10CertificationRequest request = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, DnComponents.stringToBcX500Name(subjectDn),
                keys.getPublic(), null, keys.getPrivate(), null);
        
        final String profileNameUnidPrefix = "1234-5678-";
        final String profileName = profileNameUnidPrefix + "testCertificateRequestWithUnidFnr";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(intAdmin, profileName, certificateProfile);
        
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);       
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, endEntityProfile);
        
        final String issuerDN = "CN=testCertificateRequestWithUnidFnrCa";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false, X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo testX509CaInfo = (X509CAInfo) testX509Ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testX509Ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(intAdmin, testX509Ca);
        final UserDataVOWS endEntity = new UserDataVOWS();
        endEntity.setUsername(username);
        endEntity.setPassword(password);
        endEntity.setClearPwd(false);
        endEntity.setSubjectDN(subjectDn);
        endEntity.setCaName(testX509CaInfo.getName());
        endEntity.setEmail(null);
        endEntity.setSubjectAltName(null);
        endEntity.setStatus(EndEntityConstants.STATUS_NEW);
        endEntity.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        endEntity.setEndEntityProfileName(profileName);
        endEntity.setCertificateProfileName(profileName);
        endEntity.setExtendedInformation(new ArrayList<ExtendedInformationWS>());        
        try {
            CertificateResponse certificateResponse = ejbcaraws.certificateRequest(endEntity, new String(Base64.encode(request.getEncoded())),
                    CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            X509Certificate certificate = certificateResponse.getCertificate();
            final X500Name x500Name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            final String unid = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            final String resultingFnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(unid);
            assertNotNull("Unid value was not stored", fnr);
            assertEquals("FNR value was not correctly converted", fnr, resultingFnr);           
        } finally {
            CaTestUtils.removeCa(intAdmin, testX509CaInfo);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, profileName);
            try {
                endEntityManagementSession.deleteUser(intAdmin, username);
            } catch (NoSuchEndEntityException e) {
                //NOPMD
            } 
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
    }
    
    /**
     * Test running a certificate request (including creating an end entity) using the UnidFnr plugin for ML-DSA-44 Protocol
     */
    @Test
    public void testCertificateRequestWithUnidFnrUsingMlDsa() throws InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateProfileExistsException, AuthorizationDeniedException, EndEntityProfileExistsException, CryptoTokenOfflineException,
            InvalidAlgorithmException, CAExistsException, ApprovalException_Exception, AuthorizationDeniedException_Exception,
            EjbcaException_Exception, NotFoundException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception, IOException, CertificateException, CouldNotRemoveEndEntityException {
        final KeyPair keys = KeyTools.genKeys("ML-DSA-44", AlgorithmConstants.KEYALGORITHM_MLDSA44);
        final String username = "testCertificateRequestWithUnidFnrUsingMlDsa";
        final String password = "foo123";
        final String fnr = "90123456789";
        final String lra = "01234";
        final String serialNumber = fnr + '-' + lra;
        final String subjectDn = "C=SE, serialnumber=" + serialNumber + ", CN=" + username;
        PKCS10CertificationRequest request = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.KEYALGORITHM_MLDSA44,
                DnComponents.stringToBcX500Name(subjectDn), keys.getPublic(), null, keys.getPrivate(), null);

        final String profileNameUnidPrefix = "1234-5678-";
        final String profileName = profileNameUnidPrefix + "testCertificateRequestWithUnidFnrUsingMlDsa";
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(intAdmin, profileName, certificateProfile);

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileId));
        endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, endEntityProfile);

        final String issuerDN = "CN=testCertificateRequestWithUnidFnrUsingMlDsaCa";
        X509CA testX509Ca = CaTestUtils.createTestX509CA(issuerDN, null, false,
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        X509CAInfo testX509CaInfo = (X509CAInfo) testX509Ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testX509Ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(intAdmin, testX509Ca);
        final UserDataVOWS endEntity = new UserDataVOWS();
        endEntity.setUsername(username);
        endEntity.setPassword(password);
        endEntity.setClearPwd(false);
        endEntity.setSubjectDN(subjectDn);
        endEntity.setCaName(testX509CaInfo.getName());
        endEntity.setEmail(null);
        endEntity.setSubjectAltName(null);
        endEntity.setStatus(EndEntityConstants.STATUS_NEW);
        endEntity.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        endEntity.setEndEntityProfileName(profileName);
        endEntity.setCertificateProfileName(profileName);
        endEntity.setExtendedInformation(new ArrayList<ExtendedInformationWS>());
        try {
            CertificateResponse certificateResponse = ejbcaraws.certificateRequest(endEntity, new String(Base64.encode(request.getEncoded())),
                    CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            X509Certificate certificate = certificateResponse.getCertificate();
            final X500Name x500Name = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
            final String unid = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
            final String resultingFnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(unid);
            assertNotNull("Unid value was not stored", fnr);
            assertEquals("FNR value was not correctly converted", fnr, resultingFnr);
        } finally {
            CaTestUtils.removeCa(intAdmin, testX509CaInfo);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(intAdmin, profileName);
            try {
                endEntityManagementSession.deleteUser(intAdmin, username);
            } catch (NoSuchEndEntityException e) {
                //NOPMD
            }
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
    }

    @Test
    public void test03_6EnforcementOfUniquePublicKeys() throws Exception {
        enforcementOfUniquePublicKeys();
    }

    @Test
    public void test03_6EnforcementOfUniqueSubjectDN() throws Exception {
        enforcementOfUniqueSubjectDN();
    }

    @Test
    public void test03_7ThrowAwayConfiguration() throws Exception {
        certificateRequestThrowAway();
    }

    @Test
    public void test03_8DontStoreFullCert() throws Exception {
        certificateRequestDontStoreFullCert();
    }

    @Test
    public void test03_9CertificateRequestBadParameters() throws Exception {
        final UserDataVOWS userDataVOWS = new UserDataVOWS();
        userDataVOWS.setCaName("EjbcaWSTest_NonexistentCA");
        userDataVOWS.setEndEntityProfileName("EjbcaWSTest_NonexistentEEProfile");
        userDataVOWS.setEndEntityProfileName("EjbcaWSTest_NonexistentCertProfile");

        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Should have failed because CA is missing");
        } catch (EjbcaException_Exception e) {
            assertEquals(ErrorCode.CA_NOT_EXISTS.getInternalErrorCode(), e.getFaultInfo().getErrorCode().getInternalErrorCode());
        }
        userDataVOWS.setCaName(CA1);
        userDataVOWS.setEndEntityProfileName(WS_EEPROF_EI);
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Should have failed because no certificate profile is set");
        } catch (EjbcaException_Exception e) {
            assertEquals(ErrorCode.CERT_PROFILE_NOT_EXISTS.getInternalErrorCode(), e.getFaultInfo().getErrorCode().getInternalErrorCode());
        }
        userDataVOWS.setCertificateProfileName(WS_CERTPROF_EI);
        try {
            ejbcaraws.certificateRequest(userDataVOWS, PKCS10, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("Expected empty username to be rejected according to profile settings.");
        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
            // NOPMD expected
        }
        userDataVOWS.setUsername("EjbcaWSTestBadUser"); // should never be successfully created, so no cleanup is needed
        userDataVOWS.setSubjectDN("CN=EjbcaWSTestBadUser");
        try {
            ejbcaraws.certificateRequest(userDataVOWS, "junk", CertificateHelper.CERT_REQ_TYPE_PKCS10, null, "xx");
            fail("Should have failed because of invalid RESPONSETYPE value.");
        } catch (EjbcaException_Exception e) {
            assertEquals(ErrorCode.INTERNAL_ERROR.getInternalErrorCode(), e.getFaultInfo().getErrorCode().getInternalErrorCode());
            assertEquals("Wrong response message", "Bad responseType:xx", e.getMessage());
        }
    }

    @Test
    public void test03_10MultiValueRDN() throws Exception {
        final String username = "test03_9MultiValueRDN";
        final UserDataVOWS user = new UserDataVOWS();
        user.setUsername(username);
        user.setPassword(PASSWORD);
        user.setClearPwd(false);
        user.setSubjectDN("CN=Tomas+UID=12334,O=Test,C=SE");
        user.setCaName(CA1);
        user.setSubjectAltName(null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setEndEntityProfileName(WS_EEPROF_EI);
        user.setCertificateProfileName(WS_CERTPROF_EI);
        
        try {
            // First try to issue the certificate without having it allowed in the EED profile, that should not be possible
            try {
                ejbcaraws.certificateRequest(user, super.getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                fail("Should not be possible to create certificate with multi-value RDN when it is not enabled in EE profile");
            } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
                assertTrue("Error message does not relate to multi-value RDN. Message is: "+e.getMessage(), e.getMessage().endsWith("Subject DN has multi value RDNs, which is not allowed."));
            }
            
            // Allow multi-value RDNs in the EE profile and try again, it should fail now as well, as the EE profile does not have UID as field (default created WS_EEPROF_EI in the beginning)
            EndEntityProfile prof = endEntityProfileSession.getEndEntityProfile(WS_EEPROF_EI);
            prof.setAllowMultiValueRDNs(true);
            endEntityProfileSession.changeEndEntityProfile(intAdmin, WS_EEPROF_EI, prof);
            try {
                ejbcaraws.certificateRequest(user, super.getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                fail("Should not be possible to create certificate with multi-value RDN when it is not enabled in EE profile");
            } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
                assertTrue("Error message does not relate to multi-value RDN. Message is: "+e.getMessage(), e.getMessage().endsWith("Wrong number of UID fields in Subject DN."));
            }

            // Add UID as allowed field in the EE profile
            prof = endEntityProfileSession.getEndEntityProfile(WS_EEPROF_EI);
            prof.addField(DnComponents.UID);
            endEntityProfileSession.changeEndEntityProfile(intAdmin, WS_EEPROF_EI, prof);
            try {
                CertificateResponse response = ejbcaraws.certificateRequest(user, super.getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                X509Certificate cert = response.getCertificate();
                assertEquals("SubjectDN should be multi-value RDN", "CN=Tomas+UID=12334,O=Test,C=SE", cert.getSubjectDN().toString());
            } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
                fail("Should be possible to create certificate with multi-value RDN when EE profile is configured correctly: "+e.getMessage());
            }
        } finally {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.revokeAndDeleteUser(intAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            }
        }
    }

    @Test
    public void test04GeneratePkcs12() throws Exception {
        // A: Generate P12 before key validation.
        generatePkcs12();
        // B: add RSA key validator with min. key size of 2048 bits -> P12 generation should fail.
        generatePkcs12WithFailedKeyValidation();
    }

    private void generatePkcs12WithFailedKeyValidation() throws Exception {
        final UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertNotNull(userdatas);
        assertEquals(1, userdatas.size());
        final String oldTokenType = userdatas.get(0).getTokenType();
        final String oldSubjectDn = userdatas.get(0).getSubjectDN();
        final String oldPassword = userdatas.get(0).getPassword();
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setStatus(EndEntityConstants.STATUS_NEW);
        userdatas.get(0).setSubjectDN(getDN(CA1_WSTESTUSER1));
        userdatas.get(0).setPassword(PASSWORD);
        ejbcaraws.editUser(userdatas.get(0));

        final Integer certificateProfileId = certificateProfileSession.getCertificateProfileId(userdatas.get(0).getCertificateProfileName());
        final String keyValidatorName = "WSPKCS12-RsaKeyValidatorTest";
        final RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorSessionSystemTest.createKeyValidator(RsaKeyValidator.class,
                keyValidatorName, keyValidatorName, null, -1, null, -1, KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex(),
                certificateProfileId);
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        keyValidator.setBitLengths(RsaKeyValidator.getAvailableBitLengths(2048));
        int keyValidatorId = keyValidatorSession.addKeyValidator(intAdmin, keyValidator);

        // Add key validator to CA.
        final CAInfo caInfo = caSession.getCAInfo(intAdmin, CA1);
        final Collection<Integer> keyValidatorIds = new ArrayList<>();
        keyValidatorIds.add(keyValidatorId);
        caInfo.setValidators(keyValidatorIds);
        caSession.editCA(intAdmin, caInfo);

        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, userdatas.get(0).getPassword(), null, "1024", AlgorithmConstants.KEYALGORITHM_RSA); // generatePkcs12();
            fail("With a RSA key validator and a minimum key size of 2048 bits, the generation of P12 file with a 1024 bit RSA key should fail with an EjbcaException_Exception wrapping a KeyValidationException");
        } catch(Exception e) {
            Assert.assertTrue( "EjbcaException_Exception expected: " + e.getClass().getName(), e instanceof EjbcaException_Exception);
            Assert.assertTrue( "EjbcaException_Exception with failed key validation must have message: " + e.getMessage(), (e.getMessage().startsWith("org.cesecore.keys.validation.ValidationException: Key Validator 'WSPKCS12-RsaKeyValidatorTest' could not validate sufficient key quality")));
        }

        // Clean up.
        caInfo.setValidators(new ArrayList<Integer>());
        caSession.editCA(intAdmin, caInfo);
        userdatas.get(0).setTokenType(oldTokenType);
        userdatas.get(0).setSubjectDN(oldSubjectDn);
        userdatas.get(0).setPassword(oldPassword);
        ejbcaraws.editUser(userdatas.get(0));
        keyValidatorSession.removeKeyValidator(intAdmin, keyValidatorId);
    }

    @Test
    public void test05FindCerts() throws Exception {
        findCerts();
    }

    @Test
    public void test060RevokeCert() throws Exception {
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        {
            final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);

            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());
        }
        this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
        {
            final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
        }
        {
            //final long beforeTimeMilliseconds = new Date().getTime();
            final Date beforeRevoke = new Date();
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            final Date afterRevoke = new Date();
            //final Date beforeRevoke = new Date(beforeTimeMilliseconds-beforeTimeMilliseconds%1000);
            final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            final Date revokeDate  = revokestatus.getRevocationDate().toGregorianCalendar().getTime();
            assertTrue("Too early revocation date. Before time '"+beforeRevoke+"'. Revoke time '"+revokeDate+"'.", !revokeDate.before(beforeRevoke));
            assertTrue("Too late revocation date. After time '"+afterRevoke+"'. Revoke time '"+revokeDate+"'.", !revokeDate.after(afterRevoke));
        }
        try {
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
            fail("AlreadyRevokedException_Exception was expected.");
        } catch (AlreadyRevokedException_Exception e){}
    }

    @Test(expected=CADoesntExistsException_Exception.class)
    public void testRevokeCertFromNonExistingCA() throws Exception {
        final String issuerdn = "";
        final String serno = "";
        this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
    }

    @Test
    public void test0601RevokeThrowAwayCert () throws Exception {
        final String issuerDn = "CN=" + CA1;
        // This certificate doesn't exist in EJBCA Database. Though it should be possible to revoke with a throw away CA.
        final String serialNumber = "1a1a1a1a1a1a1a1a";

        final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST-revokeThrowAwayCert"));
        // Use throw away CA mode (don't store UserData, CertificateData or CertReqHistoryData)
        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, CA1);
        final boolean originalUseCertificateStorage = caInfo.isUseCertificateStorage();
        final boolean originalUseCertReqHistory = caInfo.isUseCertReqHistory();
        final boolean originalUseUserStorage = caInfo.isUseUserStorage();
        final boolean originalAcceptRevokeNonExisting = caInfo.isAcceptRevocationNonExistingEntry();
        try {
            caInfo.setUseCertificateStorage(false);
            caInfo.setUseCertReqHistory(false);
            caInfo.setUseUserStorage(false);
            caInfo.setAcceptRevocationNonExistingEntry(true);
            caSession.editCA(authenticationToken, caInfo);

            try {
                this.ejbcaraws.revokeCert(issuerDn, serialNumber, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                {
                    final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerDn, serialNumber);
                    assertNotNull("Certificate status should be available.", revokestatus);
                    assertEquals("Certificate should be 'on hold'.", RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, revokestatus.getReason());
                    assertEquals(serialNumber, revokestatus.getCertificateSN());
                    assertEquals(issuerDn, revokestatus.getIssuerDN());
                    assertNotNull("Revocation date should not be null.", revokestatus.getRevocationDate());
                }

                this.ejbcaraws.revokeCert(issuerDn, serialNumber, RevokedCertInfo.NOT_REVOKED);
                {
                    final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerDn, serialNumber);
                    assertNotNull("Certificate status should exist after unrevoking.", revokestatus);
                    assertEquals("Certificate status should be 'not revoked'.", RevokedCertInfo.NOT_REVOKED, revokestatus.getReason());
                }
            } catch (NotFoundException_Exception e) {
                fail("Unexpected behaviour: Revocation of throw away cert required certificate in database");
            }

        } finally {
            final CAInfo caInfoToRestore = caSession.getCAInfo(authenticationToken, CA1);
            caInfoToRestore.setUseCertificateStorage(originalUseCertificateStorage);
            caInfoToRestore.setUseCertReqHistory(originalUseCertReqHistory);
            caInfoToRestore.setUseUserStorage(originalUseUserStorage);
            caInfoToRestore.setAcceptRevocationNonExistingEntry(originalAcceptRevokeNonExisting);
            caSession.editCA(authenticationToken, caInfoToRestore);
            internalCertificateStoreSession.removeCertificate(new BigInteger(serialNumber, 16));
        }
    }

    @Test
    public void test061RevokeCertBackdated() throws Exception {
        revokeCertBackdated();
    }

    @Test(expected = AlreadyRevokedException_Exception.class)
    public void test062RevokeCertChangeReasonToKeyCompromiseWithoutFlag() throws Exception {
        // Revocation reason change should fail if not enabled on CA  level.

        // Given that we have a certificate that is unrevoked, and a CA that doesn't have the "allow
        // revocation reason change" flag enabled:
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        final RevokeStatus initialRevocationStatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(initialRevocationStatus);
        assertTrue(initialRevocationStatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        // First changed into SUPERSEDED
        this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);

        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());

        // This should throw an exception because CA doesn't have the allow revocation reason change flag.
        this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
    }

    @Test()
    public void test063RevokeCertChangeReasonToKeyCompromise() throws Exception {
        // revokeCert end point should be able to change revocation reason from allowed reasons to Key Compromise

        // Given that we have a certificate that is unrevoked, and a CA has the "allow
        // revocation reason change" flag enabled:
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        final RevokeStatus initialRevocationStatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(initialRevocationStatus);
        assertTrue(initialRevocationStatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        CAInfo cainfo = caSession.getCAInfo(intAdmin, CA1);

        try {
            // Change the CA flag to TRUE
            cainfo.setAllowChangingRevocationReason(true);
            caSession.editCA(intAdmin, cainfo);

            // First changed into SUPERSEDED
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
            RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);

            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());

            // Revocation reason can be changed into KEYCOMPROMISE
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);

            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());

            // Revocation reason cannot be changed back from KEYCOMPROMISE to SUPERSEDED
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
            fail("should throw");

        } catch (AlreadyRevokedException_Exception e) {
            final String message = "Certificate with issuer: CN=CA1 and serial number: " + serno + " has previously been revoked. Revocation reason could not be changed or was not allowed.";
            assertEquals(message, e.getMessage());
        } finally {
            // Clean up
            cainfo.setAllowChangingRevocationReason(false);
            caSession.editCA(intAdmin, cainfo);
        }
    }

    @Test
    public void test064RevokeCertBackdatedChangeReasonWithBackdating() throws Exception {
        // revokeCertBackdated should be able to change reason with backdating from allowed reasons to Key Compromise.

        // Given that we have a certificate that is unrevoked
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        final RevokeStatus initialRevocationStatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(initialRevocationStatus);
        assertTrue(initialRevocationStatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        CAInfo cainfo = caSession.getCAInfo(intAdmin, CA1);
        CertificateProfile cp = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);

        try {
            // Set the CA to allow change of revocation reason 
            cainfo.setAllowChangingRevocationReason(true);
            caSession.editCA(intAdmin, cainfo);

            // Set the Certificate Profile to allow backdated revocation
            cp.setAllowBackdatedRevocation(true);
            certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, cp);

            final String originalRevocationDate = "2022-05-15";
            final String backDatedRevocationDate = "2020-05-15";

            // Revoke certificate with Revocation reason KeyCompromise and with a set revocation date
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, originalRevocationDate);
           
            RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());
            assertEquals(originalRevocationDate, revokestatus.getRevocationDate().toString().substring(0, 10));

            // Change date for revocation to earlier date
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, backDatedRevocationDate);

            revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());
            assertEquals(backDatedRevocationDate, revokestatus.getRevocationDate().toString().substring(0, 10));

        } finally {
            // Cleanup
            cainfo.setAllowChangingRevocationReason(false);
            caSession.editCA(intAdmin, cainfo);

            cp.setAllowBackdatedRevocation(false);
            certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, cp);
        }
    }

    @Test
    public void test065RevokeCertBackdateChangeReasonFutureDateShouldFail() throws Exception {
        // revokeCertBackdated should only allow backdating.

        // Given that we have a certificate that is unrevoked
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        final RevokeStatus initialRevocationStatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(initialRevocationStatus);
        assertTrue(initialRevocationStatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        CAInfo cainfo = caSession.getCAInfo(intAdmin, CA1);
        CertificateProfile cp = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);

        try {
            // Set the CA to allow change of revocation reason 
            cainfo.setAllowChangingRevocationReason(true);
            caSession.editCA(intAdmin, cainfo);

            // Set the Certificate Profile to allow backdated revocation
            cp.setAllowBackdatedRevocation(true);
            certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, cp);
            
            final String originalRevocationDate = "2020-05-15T14:07:09Z";
            final String forwardDatedRevocationDate = "2022-05-15T14:07:09Z";
            
            // Revoke certificate with Revocation reason KeyCompromise and a set revocation date
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, originalRevocationDate);
            
            RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);

            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());
            assertEquals(originalRevocationDate.substring(0, 10), revokestatus.getRevocationDate().toString().substring(0, 10));

            // Change date for revocation to later date. Should not be possible.
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, forwardDatedRevocationDate);

            fail("should throw");
        }
        catch (Exception e) {
            final String message = "New revocation date must be earlier than current revocation date";
            assertEquals(message, e.getMessage());
            assertNotNull(e.getMessage());
        } finally {
            // Cleanup
            cainfo.setAllowChangingRevocationReason(false);
            caSession.editCA(intAdmin, cainfo);

            cp.setAllowBackdatedRevocation(false);
            certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, cp);
        }
    }

    @Test
    public void test066RevokeCertBackdatedChangeReasonWithoutCertificateProfileAllow() throws Exception {
        // revokeCertBackdated should not be able to use backdated revocation date if it is not allowed
        // on the Certificate Profile level.

        // Given that we have a certificate that is unrevoked
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);
        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);

        final RevokeStatus initialRevocationStatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(initialRevocationStatus);
        assertTrue(initialRevocationStatus.getReason() == RevokedCertInfo.NOT_REVOKED);

        CAInfo cainfo = caSession.getCAInfo(intAdmin, CA1);
        CertificateProfile cp = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);

        assertEquals(false, cp.getAllowBackdatedRevocation());

        try {
            // Set the CA to allow change of revocation reason
            cainfo.setAllowChangingRevocationReason(true);
            caSession.editCA(intAdmin, cainfo);

            final String backdatedRevocationDate = "2022-05-15T14:07:09Z";

            // Revoke certificate with Revocation reason KeyCompromise and a set revocation date
            this.ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);

            assertNotNull(revokestatus);
            assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            assertTrue(revokestatus.getCertificateSN().equals(serno));
            assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
            assertNotNull(revokestatus.getRevocationDate());

            // Change date for revocation to later date. Should not be possible.
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, backdatedRevocationDate);

            fail("should throw");
        }
        catch (Exception e) {
            final String message = "Back dated revocation not allowed for certificate profile '" + WS_CERTPROF_EI + "'. Certificate serialNumber '" + serno + "', issuerDN 'CN=CA1'.";
            assertEquals(message, e.getMessage());
            assertNotNull(e.getMessage());
        }
        finally {
            // Cleanup
            cainfo.setAllowChangingRevocationReason(false);
            caSession.editCA(intAdmin, cainfo);
        }
    }
    
    @Test
    public void test08CheckRevokeStatus() throws Exception {
        checkRevokeStatus();
    }

    @Test
    public void test09Utf8EditUser() throws Exception {
        utf8EditUser();
    }

    @Test
    public void test10GetLastCertChain() throws Exception {
        getLastCertChain();
    }

    @Test
    public void test11RevokeUser() throws Exception {
        revokeUser();
    }

    @Test
    public void test12IsAuthorized() throws Exception {
        // This is a superadmin keystore, improve in the future
        isAuthorized(true);
    }

    @Test
    public void test17CustomLog() throws Exception {
        customLog();
    }

    @Test
    public void test19RevocationApprovals() throws Exception {
        log.trace(">test19RevocationApprovals");
        final String APPROVINGADMINNAME = TEST_ADMIN_USERNAME;
        final String TOKENUSERNAME = "WSTESTTOKENUSER3";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNOTSUPPORTEDSUCCEEDED = "Reactivation of users is not supported, but succeeded anyway.";
        final String approvalProfileName = this.getClass().getName() + "-AccumulativeApprovalProfile";
        String caname = "wsRevocationCA";
        String username = "wsRevocationUser";
        int cryptoTokenId = 0;
        int caID = -1;
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
        int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
        approvalProfile.setNumberOfApprovalsRequired(1);
        final int approvalProfileId = createApprovalProfile(approvalProfile, true);
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(intAdmin, caname, "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            caID = RevocationApprovalSystemTest.createApprovalCA(intAdmin, caname, ApprovalRequestType.REVOCATION, approvalProfileId, caAdminSessionRemote, caSession, catoken);
            X509Certificate adminCert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(APPROVINGADMINNAME)).iterator().next();
            Set<X509Certificate> credentials = new HashSet<>();
            credentials.add(adminCert);
            Set<Principal> principals = new HashSet<>();
            principals.add(adminCert.getSubjectX500Principal());
            AuthenticationToken approvingAdmin = simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, credentials));
            try {
                X509Certificate cert = createUserAndCert(username, caID, true);
                String issuerdn = cert.getIssuerDN().toString();
                String serno = cert.getSerialNumber().toString(16);
                // revoke via WS and verify response
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    fail(ERRORNOTSENTFORAPPROVAL);
                } catch (WaitingForApprovalException_Exception e1) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                    fail(ERRORNOTSENTFORAPPROVAL);
                } catch (ApprovalException_Exception e1) {
                }

                RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
                assertNotNull(revokestatus);
                assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Try to unrevoke certificate
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    fail(ERRORNOTSENTFORAPPROVAL);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.NOT_REVOKED);
                    fail(ERRORNOTSENTFORAPPROVAL);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED, ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE,
                        caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Revoke user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, false);
                    assertTrue(ERRORNOTSENTFORAPPROVAL, false);
                } catch (WaitingForApprovalException_Exception e) {
                }
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, false);
                    fail(ERRORNOTSENTFORAPPROVAL);
                } catch (ApprovalException_Exception e) {
                }
                // Approve revocation and verify success
                approveRevocation(intAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, caID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                // Try to reactivate user
                try {
                    ejbcaraws.revokeUser(username, RevokedCertInfo.NOT_REVOKED, false);
                    fail(ERRORNOTSUPPORTEDSUCCEEDED);
                } catch (AlreadyRevokedException_Exception e) {
                }
            } finally {
                deleteUser(username);
            }
            try {
                // Approve actions and verify success
                approveRevocation(intAdmin, approvingAdmin, TOKENUSERNAME, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, caID,
                        approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
            } finally {
                
            }
        } finally {
            approvalProfileSession.removeApprovalProfile(intAdmin, approvalProfileId);
            // Nuke CA
            CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caID));
        }
        log.trace("<test19RevocationApprovals");
    }

    private AuthenticationSubject makeAuthenticationSubject(X509Certificate certificate) {
        Set<Principal> principals = new HashSet<>();
        principals.add(certificate.getSubjectX500Principal());
        Set<X509Certificate> credentials = new HashSet<>();
        credentials.add(certificate);
        return new AuthenticationSubject(principals, credentials);
    }

    @Test
    public void testGetNumberOfApprovals() throws Exception {
        log.trace(">testGetNumberOfApprovals");
        final String adminUsername = "testGetNumberOfApprovalsApprovalAdmin";
        final String approvalProfileName = this.getClass().getName() + "-AccumulativeApprovalProfile";
        String caname = "testGetNumberOfApprovalsCa";
        String username = "testGetNumberOfApprovals";
        int cryptoTokenId = 0;
        int caId = 0;
        int approvalProfileId = 0;
        int roleId = 0;
        try {
            AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
            approvalProfile.setNumberOfApprovalsRequired(2);
            int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
            approvalProfileId = approvalProfileSession.addApprovalProfile(intAdmin, approvalProfile);
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(intAdmin, caname, "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            createTestCA();
            EndEntityInformation approvingAdmin = new EndEntityInformation(adminUsername, "CN=" + adminUsername, getTestCAId(), null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, null);
            approvingAdmin.setPassword("foo123");
            try {
                endEntityManagementSession.addUser(intAdmin, approvingAdmin, true);
            } catch(EndEntityExistsException e) {}
            final Role role = roleSession.persistRole(intAdmin,
                    new Role(null, getRoleName(),
                            Arrays.asList(AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRulesConstants.REGULAR_REVOKEENDENTITY,
                                    AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRulesConstants.ENDENTITYPROFILEBASE,
                                    StandardRules.CAACCESSBASE.resource()),
                            null));
            roleMemberSession.persist(intAdmin,
                    new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, getTestCAId(), RoleMember.NO_PROVIDER,
                            X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                            adminUsername, role.getRoleId(), null));
            roleId = role.getRoleId();
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            caId = RevocationApprovalSystemTest.createApprovalCA(intAdmin, caname, ApprovalRequestType.ADDEDITENDENTITY, approvalProfileId,
                    caAdminSessionRemote, caSession, catoken);
            KeyPair keys = KeyTools.genKeys("1024", "RSA");
            X509Certificate admincert = (X509Certificate) this.signSession.createCertificate(intAdmin, adminUsername, "foo123", new PublicKeyWrapper(keys.getPublic()));
            AuthenticationToken approvingAdminToken = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert));
            EndEntityInformation endEntityInformation = new EndEntityInformation(username, "CN=" + username, caId, "", "",
                    new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, null);
            ApprovalRequest approvalRequest = new AddEndEntityApprovalRequest(endEntityInformation, false, intAdmin, null, caId,
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, approvalProfileSession.getApprovalProfile(approvalProfileId),
                    /* validation results */ null);
            int approvalId = approvalSession.addApprovalRequest(intAdmin, approvalRequest);
            try {
                assertEquals("There should be two approvals remaining.", 2,
                        ejbcaraws.getRemainingNumberOfApprovals(approvalId));
                Approval rejection = new Approval("", AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
                rejection.setApprovalAdmin(false, approvingAdminToken);
                approvalExecutionSession.reject(approvingAdminToken, approvalRequest.generateApprovalId(), rejection);
                assertEquals("Approval status should be -1", -1, ejbcaraws.getRemainingNumberOfApprovals(approvalId));
            } finally {
                deleteUser(username);
                internalCertificateStoreSession.removeCertificate(username);
                approvalSession.removeApprovalRequest(intAdmin, approvalId);
            }
        } finally {
            deleteUser(adminUsername);
            internalCertificateStoreSession.removeCertificate(adminUsername);
            approvalProfileSession.removeApprovalProfile(intAdmin, approvalProfileId);
            CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caId));
            roleSession.deleteRoleIdempotent(intAdmin, roleId);
            removeTestCA();
        }
        log.trace("<testGetNumberOfApprovals");
    }

    @Test
    public void test20KeyRecoverNewest() throws Exception {
        log.trace(">test20KeyRecoverNewest");
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (gc.getEnableKeyRecovery()) {
            gc.setEnableKeyRecovery(false);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

        try {
            // This should throw an exception that key recovery is not enabled
            ejbcaraws.keyRecoverNewest(CA1_WSTESTUSER1);
            fail("Should throw");
        } catch (EjbcaException_Exception e) {
            assertEquals(e.getMessage(), "Keyrecovery have to be enabled in the system configuration in order to use this command.");
        }

        // Set key recovery enabled
        gc.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(intAdmin, gc);

        try {
            // This should throw an exception that the user does not exist
            ejbcaraws.keyRecoverNewest("sdfjhdiuwerw43768754###");
            fail("Should throw");
        } catch (NotFoundException_Exception e) {
            assertEquals(e.getMessage(), "Wrong username or password");
        }

        // Add a new End entity profile, KEYRECOVERY
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COMMONNAME);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setReUseKeyRecoveredCertificate(true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        endEntityProfileSession.addEndEntityProfile(intAdmin, KEY_RECOVERY_EEP, profile);
        assertTrue("Unable to create KEYRECOVERY end entity profile.", endEntityProfileSession.getEndEntityProfile(KEY_RECOVERY_EEP) != null);

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
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        KeyStore ksenv = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks);
        Enumeration<String> en = ks.aliases();
        String alias = en.nextElement();
        if(!ks.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        assertEquals("CN=WSTESTUSERKEYREC1", cert.getSubjectDN().toString());
        PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());

        // This should work now
        ejbcaraws.keyRecoverNewest("WSTESTUSERKEYREC1");

        // Set status to keyrecovery
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("WSTESTUSERKEYREC1");
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue("UserData for WSTESTUSERKEYREC1 not found", userdatas != null);
        assertTrue("Unexpected amount of UserData entries for WSTESTUSERKEYREC1", userdatas.size() == 1);
        userdatas.get(0).setStatus(EndEntityConstants.STATUS_KEYRECOVERY);
        // Setting new password (which was cleared on last enrollment)
        userdatas.get(0).setPassword("foo456");
        ejbcaraws.editUser(userdatas.get(0));
        // A new PK12 request now should return the same key and certificate
        KeyStore ksenv2 = ejbcaraws.pkcs12Req("WSTESTUSERKEYREC1", "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv2.getKeystoreData(), "PKCS12", "foo456");
        assertNotNull(ks2);
        en = ks2.aliases();
        alias = en.nextElement();
        // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex
        if(!ks2.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
        assertEquals(cert2.getSubjectDN().toString(), "CN=WSTESTUSERKEYREC1");
        PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());

        // Compare certificates
        assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
        // Compare keys
        String key1 = new String(Hex.encode(privK.getEncoded()));
        String key2 = new String(Hex.encode(privK2.getEncoded()));
        assertEquals(key1, key2);
        log.trace("<test20KeyRecoverNewest");
    }

    @Test
    public void test20bKeyRecoverAny() throws Exception {
        log.trace(">test20bKeyRecoverAny");
        final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean eelimitation = gc.getEnableEndEntityProfileLimitations();
        boolean keyrecovery = gc.getEnableKeyRecovery();
        if (!gc.getEnableKeyRecovery() || !gc.getEnableEndEntityProfileLimitations()) {
            gc.setEnableKeyRecovery(true);
            gc.setEnableEndEntityProfileLimitations(true);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

        if(endEntityProfileSession.getEndEntityProfile(KEY_RECOVERY_EEP) == null) {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.COMMONNAME);
            profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
            profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
            profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
            profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
            profile.setReUseKeyRecoveredCertificate(true);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
            endEntityProfileSession.addEndEntityProfile(intAdmin, KEY_RECOVERY_EEP, profile);
        }

        try {
            // Add a new user, set token to P12, status to new and end entity
            // profile to key recovery
            UserDataVOWS user1 = new UserDataVOWS();
            final String username = "WSTESTUSERKEYREC2";
            user1.setKeyRecoverable(true);
            user1.setUsername(username);
            user1.setPassword("foo456");
            user1.setClearPwd(true);
            user1.setSubjectDN("CN="+username);
            user1.setCaName(getAdminCAName());
            user1.setEmail(null);
            user1.setSubjectAltName(null);
            user1.setStatus(EndEntityConstants.STATUS_NEW);
            user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
            user1.setCertificateProfileName("ENDUSER");
            ejbcaraws.editUser(user1);
            final int eepId = endEntityProfileSession.getEndEntityProfileId(KEY_RECOVERY_EEP);
            final int caId = caSession.getCAInfo(intAdmin, getAdminCAName()).getCAId();
            // generate 4 certificates
            UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(username);
            List<java.security.KeyStore> keyStores = new ArrayList<>();
            for (int i=0; i < 4; i++) {
                List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
                assertEquals("Exactly one end entity by the name with the username " + username + " should have been returned.", 1, userdatas.size());
                user1 = userdatas.get(0);
                // Surely not all of these properties need to be set again?
                user1.setKeyRecoverable(true);
                user1.setUsername(username);
                user1.setPassword("foo456");
                user1.setClearPwd(true);
                user1.setSubjectDN("CN="+username);
                user1.setCaName(getAdminCAName());
                user1.setEmail(null);
                user1.setSubjectAltName(null);
                user1.setStatus(EndEntityConstants.STATUS_NEW);
                user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
                user1.setEndEntityProfileName(KEY_RECOVERY_EEP);
                user1.setCertificateProfileName("ENDUSER");
                setAccessRulesForWsAdmin(Collections.singletonList(StandardRules.ROLE_ROOT.resource()), null);
                ejbcaraws.editUser(user1);
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY,
                        // Additionally we need to have edit rights to clear the password, since this is currently not implicitly granted for non-key recovery
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.EDIT_END_ENTITY,
                        AccessRulesConstants.REGULAR_EDITENDENTITY,
                        // Additionally we need to have access to key recovery in this special case
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.REGULAR_KEYRECOVERY
                        ), null);
                KeyStore ksenv = ejbcaraws.pkcs12Req(username, "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
                assertNotNull(ks);
                keyStores.add(ks);
            }
            // user should have 4 certificates
            assertTrue(keyStores.size() == 4);
            // recover all keys
            for (final java.security.KeyStore ks : keyStores){
                Enumeration<String> en = ks.aliases();
                String alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                assertEquals("CN="+username, cert.getSubjectDN().toString());
                PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());
                log.info("recovering key. sn "+ cert.getSerialNumber().toString(16) + " issuer "+ cert.getIssuerDN().toString());
                // recover key
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                        AccessRulesConstants.REGULAR_KEYRECOVERY,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY
                        ), null);
                ejbcaraws.keyRecover(username,cert.getSerialNumber().toString(16),cert.getIssuerDN().toString());
                assertEquals("EjbcaWS.keyRecover failed to set status for end entity.", EndEntityConstants.STATUS_KEYRECOVERY, endEntityAccessSession.findUser(intAdmin, username).getStatus());
                // A new PK12 request now should return the same key and certificate
                setAccessRulesForWsAdmin(Arrays.asList(
                        AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.VIEW_END_ENTITY,
                        StandardRules.CAACCESS.resource() + caId,
                        AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                        AccessRulesConstants.REGULAR_VIEWENDENTITY,
                        // Additionally we need to have access to key recovery in this special case
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.REGULAR_KEYRECOVERY
                        ), null);
                // Password is cleared on each enrollment. Setting new one.
                UserMatch usermatch2 = new UserMatch();
                usermatch2.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
                usermatch2.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
                usermatch2.setMatchvalue(username);
                List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch2);
                assertEquals("Unexpected amount of UserData entries for " + username, 1, userdatas.size());
                userdatas.get(0).setStatus(EndEntityConstants.STATUS_KEYRECOVERY);
                userdatas.get(0).setPassword("foo456");
                ejbcaraws.editUser(userdatas.get(0));
                KeyStore ksenv = ejbcaraws.pkcs12Req(username, "foo456", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
                assertNotNull(ks2);
                en = ks2.aliases();
                alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
                assertEquals("CN="+username, cert2.getSubjectDN().toString());
                PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());
                // Compare certificates
                assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
                // Compare keys
                String key1 = new String(Hex.encode(privK.getEncoded()));
                String key2 = new String(Hex.encode(privK2.getEncoded()));
                assertEquals(key1, key2);
            }

            // Try the single keyRecoverEnroll command as well, making a single call instead of a "keyRecover" followed by a "p12Req".
            for (final java.security.KeyStore ks : keyStores){
                Enumeration<String> en = ks.aliases();
                String alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                assertEquals("CN="+username, cert.getSubjectDN().toString());
                PrivateKey privK = (PrivateKey) ks.getKey(alias, "foo456".toCharArray());
                log.info("recovering key. sn "+ cert.getSerialNumber().toString(16) + " issuer "+ cert.getIssuerDN().toString());

                // Try the single keyRecoverEnroll command
                KeyStore ksenv = ejbcaraws.keyRecoverEnroll(username, cert.getSerialNumber().toString(16), cert.getIssuerDN().toString(), "foo456", null);
                java.security.KeyStore ks2 = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", "foo456");
                assertNotNull(ks2);
                en = ks2.aliases();
                alias = en.nextElement();
                // You never know in which order the certificates in the KS are returned, it's different between java 6 and 7 for ex
                if(!ks.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                X509Certificate cert2 = (X509Certificate) ks2.getCertificate(alias);
                assertEquals("CN="+username, cert2.getSubjectDN().toString());
                PrivateKey privK2 = (PrivateKey) ks2.getKey(alias, "foo456".toCharArray());
                // Compare certificates
                assertEquals(cert.getSerialNumber().toString(16), cert2.getSerialNumber().toString(16));
                // Compare keys
                String key1 = new String(Hex.encode(privK.getEncoded()));
                String key2 = new String(Hex.encode(privK2.getEncoded()));
                assertEquals(key1, key2);
            }
        } finally {
            gc.setEnableEndEntityProfileLimitations(eelimitation);
            gc.setEnableKeyRecovery(keyrecovery);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

        log.trace("<test20bKeyRecoverAny");
    }

    @Test
    public void test21GetAvailableCAs() throws Exception {
        log.trace(">getAvailableCAs");
        Collection<Integer> ids = caSession.getAuthorizedCaIds(intAdmin);
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
        log.trace("<getAvailableCAs");
    }

    @Test
    public void test22GetAuthorizedEndEntityProfiles() throws Exception {
        log.trace(">getAuthorizedEndEntityProfiles");
        Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(intAdmin, AccessRulesConstants.CREATE_END_ENTITY);
        List<NameAndId> profs = ejbcaraws.getAuthorizedEndEntityProfiles();
        assertNotNull(profs);
        assertEquals(profs.size(), ids.size());
        boolean foundkeyrec = false;
        for (NameAndId nameAndId : profs) {
            log.info("name: " + nameAndId.getName());
            if (nameAndId.getName().equals(KEY_RECOVERY_EEP)) {
                foundkeyrec = true;
            }
            boolean found = false;
            for (Integer i : ids) {
                // All ids must be in profs
                if (nameAndId.getId() == i) {
                    found = true;
                }
            }
            assertTrue("Unable to find profile '" + nameAndId.getName() + "' among authorized EEPs reported by Remote EJB call.", found);
        }
        assertTrue("Could not find " + KEY_RECOVERY_EEP + " end entity profile among authorized profiles.", foundkeyrec);
        log.trace("<getAuthorizedEndEntityProfiles");
    }

    @Test
    public void test23GetAvailableCertificateProfiles() throws Exception {
        getAvailableCertificateProfiles();
    }

    @Test
    public void test24GetAvailableCAsInProfile() throws Exception {
        getAvailableCAsInProfile();
    }

    @Test
    public void test25CreateandGetCRL() throws Exception {
        createAndGetCRL();
    }

    @Test
    public void testEjbcaVersion() {
        final String version = ejbcaraws.getEjbcaVersion();
        // We don't know which specific version we are testing
        final String expectedSubString = "EJBCA 9.";
        assertTrue("Wrong version: "+version + " (expected to contain " + expectedSubString + ")", version.contains(expectedSubString));    }

    @Test
    public void test29ErrorOnEditUser() throws Exception {
        errorOnEditUser();
    }

    @Test
    public void test30ErrorOnGeneratePkcs10() throws Exception {
        errorOnGeneratePkcs10();
    }

    @Test
    public void test31ErrorOnGeneratePkcs12() throws Exception {
        errorOnGeneratePkcs12();
    }

    @Test
    public void test32OperationOnNonexistingCA() throws Exception {
        final String MOCKSERIAL = "AABBCCDDAABBCCDD";

        // Add a user for this test purpose.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER32");
        user1.setPassword("foo1234");
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSTESTUSER32");
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(EndEntityConstants.STATUS_NEW);
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
        } // Expected    }
    }

    @Test
    public void test33CheckQueueLength() throws Exception {
        checkQueueLength();
    }

    /** In EJBCA 4.0.0 we changed the date format to ISO 8601. This verifies the that we still accept old requests, but returns UserDataVOWS objects using the new DateFormat
     * @throws AuthorizationDeniedException */
    @Test
    public void testTimeFormatConversionFromUS() throws EjbcaException {
        log.trace(">testTimeFormatConversionFromUs()");
        final Date nowWithOutSeconds = new Date((new Date().getTime() / 60000) * 60000); // To avoid false negatives.. we will loose precision when we convert back and forth..
        final String oldTimeFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).format(nowWithOutSeconds);
        final String newTimeFormatStorage = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
        final String newTimeFormatRequest = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("CEST"))
                .format(nowWithOutSeconds);
        final String newTimeFormatResponse = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("UTC"))
                .format(nowWithOutSeconds);
        log.debug("oldTimeFormat=" + oldTimeFormat);
        log.debug("newTimeFormatStorage=" + newTimeFormatStorage);
        log.debug("newTimeFormatRequest=" + newTimeFormatRequest);
        // Convert from UserDataVOWS with US Locale DateFormat to endEntityInformation
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username",
                "password", false, "CN=User U", "CA1", null, null, 10, "P12", "EMPTY", "ENDUSER");
        userDataVoWs.setStartTime(oldTimeFormat);
        userDataVoWs.setEndTime(oldTimeFormat);
        final EndEntityInformation endEntityInformation1 = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
        assertEquals("CUSTOM_STARTTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage,
                endEntityInformation1.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("CUSTOM_ENDTIME in old format was not correctly handled (VOWS to VO).", newTimeFormatStorage,
                endEntityInformation1.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        // Convert from endEntityInformation with standard DateFormat to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs1 = ejbcaWSHelperSession.convertEndEntityInformation(endEntityInformation1, "CA1", "EEPROFILE", "CERTPROFILE", "P12");
        // We expect that the server will respond using UTC
        assertEquals("CUSTOM_STARTTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getStartTime());
        assertEquals("CUSTOM_ENDTIME in new format was not correctly handled (VO to VOWS).", newTimeFormatResponse, userDataVoWs1.getEndTime());
    }

    @Test
    public void testTimeFormatConversionFromStandard() throws EjbcaException {
        final Date nowWithOutSeconds = new Date((new Date().getTime() / 60000) * 60000); // To avoid false negatives.. we will loose precision when we convert back and forth..
        final String newTimeFormatStorage = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss", TimeZone.getTimeZone("UTC")).format(nowWithOutSeconds);
        final String newTimeFormatRequest = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("CEST"))
                .format(nowWithOutSeconds);
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username",
                "password", false, "CN=User U", "CA1", null, null, 10, "P12", "EMPTY", "ENDUSER");
        // Convert from UserDataVOWS with standard DateFormat to endEntityInformation
        userDataVoWs.setStartTime(newTimeFormatRequest);
        userDataVoWs.setEndTime(newTimeFormatRequest);
        final EndEntityInformation endEntityInformation2 = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in new format was not correctly handled.", newTimeFormatStorage, endEntityInformation2.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
    }

    @Test
    public void testTimeFormatConversionFromCustom() throws EjbcaException {
        final String relativeTimeFormat = "0123:12:31";
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username",
                "password", false, "CN=User U", "CA1", null, null, EndEntityConstants.STATUS_NEW, "P12", "EMPTY", "ENDUSER");
        // Convert from UserDataVOWS with relative date format to endEntityInformation
        userDataVoWs.setStartTime(relativeTimeFormat);
        userDataVoWs.setEndTime(relativeTimeFormat);
        final EndEntityInformation endEntityInformation3 = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
        assertEquals("ExtendedInformation.CUSTOM_STARTTIME in relative format was not correctly handled.", relativeTimeFormat,
                endEntityInformation3.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        assertEquals("ExtendedInformation.CUSTOM_ENDTIME in relative format was not correctly handled.", relativeTimeFormat,
                endEntityInformation3.getExtendedInformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));

        // Convert from EndEntityInformation with relative date format to UserDataVOWS
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs3 = ejbcaWSHelperSession.convertEndEntityInformation(endEntityInformation3, "CA1", "EEPROFILE", "CERTPROFILE", "P12");
        assertEquals("CUSTOM_STARTTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getStartTime());
        assertEquals("CUSTOM_ENDTIME in relative format was not correctly handled (VO to VOWS).", relativeTimeFormat, userDataVoWs3.getEndTime());
        // Try some invalid start time date format
        userDataVoWs.setStartTime("12:32 2011-02-28");  // Invalid
        userDataVoWs.setEndTime("2011-02-28 12:32:00+00:00");   // Valid
        try {
            ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
    }

    @Test
    public void testTimeFormatConversionFromStandardWithZulu() throws EjbcaException {
        final Date nowWithOutSeconds = new Date((new Date().getTime() / 60000) * 60000); // To avoid false negatives.. we will loose precision when we convert back and forth..
        final String newTimeFormatResponse = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZZ", TimeZone.getTimeZone("UTC"))
                .format(nowWithOutSeconds);
        final String newTimeFormatWithZulu = newTimeFormatResponse.replace("+00:00", "Z");
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username",
                "password", false, "CN=User U", "CA1", null, null, EndEntityConstants.STATUS_NEW, "P12", "EMPTY", "ENDUSER");
        // Test using a time format that ends with Z instead of +00.00
        userDataVoWs.setStartTime(newTimeFormatWithZulu);
        final EndEntityInformation endEntityInformationZ = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWsZ = ejbcaWSHelperSession.convertEndEntityInformation(endEntityInformationZ,
                "CA1", "EEPROFILE", "CERTPROFILE", "P12");
        // We expect that the server will respond using UTC
        assertEquals("CUSTOM_STARTTIME in new format using Zulu was not correctly handled (VO to VOWS).", newTimeFormatResponse,
                userDataVoWsZ.getStartTime());
    }

    @Test
    public void testTimeFormatConversionFromInvalid() throws EjbcaException {
        final org.ejbca.core.protocol.ws.objects.UserDataVOWS userDataVoWs = new org.ejbca.core.protocol.ws.objects.UserDataVOWS("username",
                "password", false, "CN=User U", "CA1", null, null, EndEntityConstants.STATUS_NEW, "P12", "EMPTY", "ENDUSER");
        // Try some invalid end time date format
        userDataVoWs.setStartTime("2011-02-28 12:32:00+00:00"); // Valid
        userDataVoWs.setEndTime("12:32 2011-02-28"); // Invalid
        try {
            ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, false);
            fail("Conversion of illegal time format did not generate exception.");
        } catch (EjbcaException e) {
            assertEquals("Unexpected error code in exception.", ErrorCode.FIELD_VALUE_NOT_VALID, e.getErrorCode());
        }
        // Try a raw subjectDN
        userDataVoWs.setStartTime(null); // Valid
        userDataVoWs.setEndTime(null); // Invalid
        userDataVoWs.setSubjectDN("CN=User U,C=SE,O=Foo"); // not normal order
        EndEntityInformation endEntityInformation4 = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, true);
        assertNotNull(endEntityInformation4.getExtendedInformation().getRawSubjectDn());
        endEntityInformation4 = ejbcaWSHelperSession.convertUserDataVOWSInternal(userDataVoWs, 1, 2, 3, 4, true);
        assertEquals("Raw subject DN is not raw order", "CN=User U,C=SE,O=Foo", endEntityInformation4.getExtendedInformation().getRawSubjectDn());
    }

    /** Simulate a simple SQL injection by sending the to-be-escaped char "'". */
    @Test
    public void test40EvilFind01() throws Exception {
        log.trace(">test40EvilFind01");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("A' OR '1=1");
        try {
            List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertEquals("SQL injection caused results to be returned!", 0, userdatas.size());
        } catch (IllegalQueryException_Exception e) {
            fail("SQL injection did cause an unexpected error: " + e.getMessage());
        }
        log.trace("<test40EvilFind01");
    }

    @Test
    public void test40EvilFind02() throws Exception {
        log.trace(">test40EvilFind02");
        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(org.ejbca.util.query.UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue("A'' OR ''1=1");
        try {
            List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertEquals("SQL injection caused results to be returned!", 0, userdatas.size());
        } catch (IllegalQueryException_Exception e) {
            fail("SQL injection did cause an unexpected error: " + e.getMessage());
        }
        log.trace("<test40EvilFind02");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test41CertificateRequestWithSpecialChars01() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=foo\\+bar\\\"\\,, C=SE",
                "CN=test" + rnd + ",O=foo\\+bar\\\"\\,,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test42CertificateRequestWithSpecialChars02() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test42CertificateRequestWithSpecialChars02" + rnd + ",O=foo/bar\\;123, C=SE",
                "CN=test42CertificateRequestWithSpecialChars02" + rnd + ",O=foo/bar/123,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test43CertificateRequestWithSpecialChars03() throws Exception {
        long rnd = secureRandom.nextLong();
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        // an unescaped + must now either be a multi-value RDN, or the string is considered illegal directory string
        testCertificateRequestWithSpecialChars(
                "CN=test43CertificateRequestWithSpecialChars03" + rnd + ", O=foo\\+bar\\+123, C=SE",
                "CN=test43CertificateRequestWithSpecialChars03" + rnd + ",O=foo\\+bar\\+123,C=SE");
        try {
            testCertificateRequestWithSpecialChars(
                    "CN=test43CertificateRequestWithSpecialChars03" + rnd + ", O=foo+bar\\+123, C=SE",
                    "CN=test43CertificateRequestWithSpecialChars03" + rnd + ",O=foo\\+bar\\+123,C=SE");
            fail("Test should fail as badly formatted directory string due to non-escaped +");
        } catch (EjbcaException_Exception e) {
            assertTrue("Exception must be about badly formatted directory string", e.getMessage().contains("badly formatted directory string"));
        }
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test44CertificateRequestWithSpecialChars04() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test" + rnd + ", O=foo\\=bar, C=SE",
                "CN=test" + rnd + ",O=foo\\=bar,C=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test45CertificateRequestWithSpecialChars05() throws Exception {
        long rnd = secureRandom.nextLong();
        testCertificateRequestWithSpecialChars(
                "CN=test45CertificateRequestWithSpecialChars05" + rnd + ", O=\"foo=bar, C=SE\"",
                "CN=test45CertificateRequestWithSpecialChars05" + rnd + ",O=foo\\=bar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test46CertificateRequestWithSpecialChars06() throws Exception {
        long rnd = secureRandom.nextLong();
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        // We now handle + signs "correctly
        testCertificateRequestWithSpecialChars(
                "CN=test46CertificateRequestWithSpecialChars06" + rnd + ", O=\"foo+b\\+ar, C=SE\"",
                "CN=test46CertificateRequestWithSpecialChars06" + rnd + ",O=foo\\+b\\\\\\+ar\\, C\\=SE");
    }

    /**
     * Use single transaction method for requesting KeyStore with special
     * characters in the certificate SubjectDN.
     */
    @Test
    public void test47CertificateRequestWithSpecialChars07() throws Exception {
        long rnd = secureRandom.nextLong();
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        // We now handle + signs "correctly", that's a multi-value RDN.
        // = signs must be escaped, or you get an error.
        testCertificateRequestWithSpecialChars(
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ", O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"",
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
        testCertificateRequestWithSpecialChars(
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ", O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"",
                "CN=test47CertificateRequestWithSpecialChars07" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
        try {
            // 'b' after the + should be an OID, which it's not
            testCertificateRequestWithSpecialChars(
                    "CN=test47CertificateRequestWithSpecialChars07" + rnd + ", O=\\\"foo+b\\+ar\\, C=SE\\\"",
                    "CN=test47CertificateRequestWithSpecialChars07" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
            fail("Test should fail as unknown oid (b) passed as multi-value RDN");
        } catch (EjbcaException_Exception e) {
            assertTrue("Exception must be about Unknown object id", e.getMessage().contains("Unknown object id"));
        }
        try {
            // The , but not the = is not escaped, so this is an error
            testCertificateRequestWithSpecialChars(
                    "CN=test47CertificateRequestWithSpecialChars07" + rnd + ", O=\\\"foo\\+b\\+ar\\, C=SE\\\"",
                    "CN=test47CertificateRequestWithSpecialChars07" + rnd + ",O=\\\"foo\\+b\\+ar\\, C\\=SE\\\"");
            fail("Test should fail as unknown oid (b) passed as multi-value RDN");
        } catch (EjbcaException_Exception e) {
            assertTrue("Exception message must contain \"badly formatted directory string\"", e.getMessage().contains("badly formatted directory string"));
        }
    }

    /**
     * Test that all but one default certificate forbidden characters are substituted
     * with '/'.
     * The one not tested is the null character ('\0'). It is not tested since
     * it is not a valid xml character so the WS protocol can not handle it.
     */
    @Test
    public void test48CertificateRequestWithForbiddenCharsDefault() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setForbiddenCharacters(null);
        testCertificateRequestWithSpecialChars(
                "CN=test48CertificateRequestWithForbiddenCharsDefault" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test48CertificateRequestWithForbiddenCharsDefault" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
    }

    /**
     * Same as {@link #test48CertificateRequestWithForbiddenCharsDefault()} but setting
     * default values in config.
     */
    @Test
    public void test49CertificateRequestWithForbiddenCharsDefinedAsDefault() throws Exception {
        long rnd = secureRandom.nextLong();
        cesecoreConfigurationProxySession.setForbiddenCharacters("\n\r;!\u0000%`?$~".toCharArray());
        testCertificateRequestWithSpecialChars(
                "CN=test49CertificateRequestWithForbiddenCharsDefinedAsDefault" + rnd + ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test49CertificateRequestWithForbiddenCharsDefinedAsDefault" + rnd +   ",O=|/|/|/|A|/|/|/|/|/|,C=SE");
    }

    /**
     * Test to define some forbidden chars.
     */
    @Test
    public void test50CertificateRequestWithForbiddenCharsDefinedBogus() throws Exception {
        cesecoreConfigurationProxySession.setForbiddenCharacters("tset".toCharArray());
        try {
            testCertificateRequestWithSpecialChars(
                    "CN=test" +   ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                    "CN=////" + ",O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE");
        } finally {
            // we must remove this bogus settings otherwise next setupAdmin() will fail
            cesecoreConfigurationProxySession.setForbiddenCharacters(null);
        }
    }

    /**
     * Test that no forbidden chars work
     */
    @Test
    public void test51CertificateRequestWithNoForbiddenChars() throws Exception {
        final String testName = "test50CertificateRequestWithForbiddenCharsDefinedBogus";
        cesecoreConfigurationProxySession.setForbiddenCharacters("".toCharArray());
        // Using JDK8 \r is transformed into \n for some reason, expected will work if: O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE
        testCertificateRequestWithSpecialChars(
                "CN=test51CertificateRequestWithNoForbiddenChars" + testName +   ",O=|\n|\r|;|A|!|`|?|$|~|, C=SE",
                "CN=test51CertificateRequestWithNoForbiddenChars" + testName +   ",O=|\n|\r|\\;|A|!|`|?|$|~|,C=SE");
    }


    /**
     * Tests that the provided cardnumber is stored in the EndEntityInformation
     * and that when querying for EndEntityInformation the cardnumber is
     * returned.
     * @throws Exception in case of error
     */
    @Test
    public void test48CertificateRequestWithCardNumber() throws Exception {
        String userName = "wsRequestCardNumber" + new SecureRandom().nextLong();

        // Generate a CSR
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", DnComponents.stringToBcX500Name("CN=NOUSED"),
                keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        final String csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));

        // Set some user data
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword(PASSWORD);
        userData.setClearPwd(true);
        userData.setSubjectDN("CN=test" + secureRandom.nextLong() + ", UID=" + userName + ", O=Test, C=SE");
        userData.setCaName(getAdminCAName());
        userData.setEmail(null);
        userData.setSubjectAltName(null);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userData.setEndEntityProfileName("EMPTY");
        userData.setCertificateProfileName("ENDUSER");

        // Set the card number
        userData.setCardNumber("1234fa");

        // Issue a certificate
        CertificateResponse response = ejbcaraws.certificateRequest(userData, csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        assertNotNull("null response", response);

        // Check that the cardnumber was stored in the EndEntityInformation
        EndEntityInformation endEntity = endEntityAccessSession.findUser(intAdmin, userName);
        assertEquals("stored cardnumber ejb", "1234fa", endEntity.getCardNumber());

        // Check that the cardnumber is also available when querying using WS
        UserMatch criteria = new UserMatch();
        criteria.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        criteria.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        criteria.setMatchvalue(userName);
        UserDataVOWS user = ejbcaraws.findUser(criteria).get(0);
        assertEquals("stored cardnumber ws", "1234fa", user.getCardNumber());
    }

    @Test
    public void testGetCertificateProfile() throws Exception {
        String profilename = "TESTPROFILEFORGETPROFILECOMMAND";

        if(certificateProfileSession.getCertificateProfile(profilename) != null) {
            certificateProfileSession.removeCertificateProfile(intAdmin, profilename);
        }
        CertificateProfile profile = new CertificateProfile();
        profile.setAllowValidityOverride(true);
        profile.setAllowExtensionOverride(true);
        certificateProfileSession.addCertificateProfile(intAdmin, profilename, profile);
        int profileid = certificateProfileSession.getCertificateProfileId(profilename);

        try {
            final byte[] profilebytes = ejbcaraws.getProfile(profileid, "cp");
            final Map<?, ?> h;
            try (SecureXMLDecoder decoder = new SecureXMLDecoder(new java.io.ByteArrayInputStream(profilebytes))) {
                h = (Map<?, ?>) decoder.readObject();
            }

            // Check that the default data are different from the data in the profile we want to retrieve
            profile = new CertificateProfile();
            assertFalse(profile.getAllowValidityOverride());
            assertFalse(profile.getAllowExtensionOverride());

            // Load the data from the retrieved profile and verify that the data is correct
            profile.loadData(h);
            assertTrue(profile.getAllowValidityOverride());
            assertTrue(profile.getAllowExtensionOverride());

        } finally {
            certificateProfileSession.removeCertificateProfile(intAdmin, profilename);
        }
    }

    @Test
    public void testGetEndEntityProfile() throws Exception {
        String profilename = "TESTPROFILEFORGETPROFILECOMMAND";

        if(endEntityProfileSession.getEndEntityProfile(profilename) != null) {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profilename);
        }
        if(certificateProfileSession.getCertificateProfile(profilename) != null) {
            certificateProfileSession.removeCertificateProfile(intAdmin, profilename);
        }
        EndEntityProfile profile = new EndEntityProfile();
        profile.setPrinterName("TestPrinter");
        profile.addField(DnComponents.COMMONNAME);
        profile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        profile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
        endEntityProfileSession.addEndEntityProfile(intAdmin, profilename, profile);
        int profileid = endEntityProfileSession.getEndEntityProfileId(profilename);
        try {
            byte[] profilebytes = ejbcaraws.getProfile(profileid, "eep");
            final Map<?, ?> h;
            try (SecureXMLDecoder decoder = new SecureXMLDecoder(new java.io.ByteArrayInputStream(profilebytes))) {
                h = (Map<?, ?>)decoder.readObject();
            }

            // Check that the default data are different from the data in the profile we want to retrieve
            profile = new EndEntityProfile();
            assertFalse(StringUtils.equals("TestPrinter", profile.getPrinterName()));
            assertFalse(profile.getUse(EndEntityProfile.KEYRECOVERABLE, 0));

            // Load the data from the retrieved profile and verify that the data is correct
            profile.loadData(h);
            assertEquals("TestPrinter", profile.getPrinterName());
            assertTrue(profile.getUse(EndEntityProfile.KEYRECOVERABLE, 0));

        } finally {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profilename);
        }

    }

    @Test
    public void testGetProfileWithUnknownType() throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
        int profileid = 4711;
        try {
            ejbcaraws.getProfile(profileid, "foo");
            fail("Unknown type should have thrown an exception.");
        } catch(UnknownProfileTypeException_Exception e) {
            String expectedmsg = "Unknown profile type 'foo'. Recognized types are 'eep' for End Entity Profiles and 'cp' for Certificate Profiles";
            assertEquals(expectedmsg, e.getMessage());
        }
    }

    @Test
    public void test53CertificateRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(false, true,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "JurisdictionCountry=SE,JurisdictionLocality=jlocality,BusinessCategory=Private Organization,CN=rox" + rnd + ".primekey.se,SN=12345,OU=OU2,OU=OU1,O=PrimeKey,L=locality,ST=Sthlm,C=SE");
    }

    @Test
    public void test54SoftTokenRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(false, false,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "JurisdictionCountry=SE,JurisdictionLocality=jlocality,BusinessCategory=Private Organization,CN=rox" + rnd + ".primekey.se,SN=12345,OU=OU2,OU=OU1,O=PrimeKey,L=locality,ST=Sthlm,C=SE");
    }

    @Test
    public void test55CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, true,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JurisdictionCountry=SE,SN=12345,BusinessCategory=Private Organization");
    }

    @Test
    public void test56SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        final long rnd = Math.abs(secureRandom.nextLong());
        testCertificateRequestWithEeiDnOverride(true, false,
                "L=locality,OU=OU1,JURISDICTIONLOCALITY=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JURISDICTIONCOUNTRY=SE,SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se,C=SE,ST=Sthlm,OU=OU2,O=PrimeKey,JurisdictionCountry=SE,SN=12345,BusinessCategory=Private Organization");
    }

    @Test
    public void test57CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        cesecoreConfigurationProxySession.setForbiddenCharacters("\n\r;!\u0000%`?$~".toCharArray());
        final long rnd = Math.abs(secureRandom.nextLong());
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        // The multi-value RDN SN=12345+JurisdictionCountry=SE is now handled correctly
        // empty DN component is allowed (CN=) in the core API, but when using AllowDNOverrideByEndEntityInformation empties are remove in X509CA with DNFieldsUtil.removeAllEmpties
        // Special characters such as = + , (equals, plus, comma) must be escaped.
        testCertificateRequestWithEeiDnOverride(true, true,
                "L=locality,OU=OU1, JURISDICTIONLOCALITY= jlocality ,CN=,CN=rox" + rnd + ".primekey.se;C,ST=Sthlm\n,OU=OU2 ,O=PrimeKey,JURISDICTIONCOUNTRY=SE+SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se/C,ST=Sthlm/,OU=OU2,O=PrimeKey,SN=12345+JurisdictionCountry=SE,BusinessCategory=Private Organization");
    }

    @Test
    public void test58SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        cesecoreConfigurationProxySession.setForbiddenCharacters("\n\r;!\u0000%`?$~".toCharArray());
        final long rnd = Math.abs(secureRandom.nextLong());
        // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
        // The multi-value RDN SN=12345+JurisdictionCountry=SE is now handled correctly
        // empty DN component is allowed (CN=) in the core API, but when using AllowDNOverrideByEndEntityInformation empties are remove in X509CA with DNFieldsUtil.removeAllEmpties
        // Special characters such as = + , (equals, plus, comma) must be escaped.
        testCertificateRequestWithEeiDnOverride(true, false,
                "L=locality,OU=OU1, JURISDICTIONLOCALITY= jlocality ,CN=,CN=rox" + rnd + ".primekey.se;C,ST=Sthlm\n,OU=OU2 ,O=PrimeKey,JURISDICTIONCOUNTRY=SE+SN=12345,BUSINESSCATEGORY=Private Organization",
                "L=locality,OU=OU1,JurisdictionLocality=jlocality,CN=rox" + rnd + ".primekey.se/C,ST=Sthlm/,OU=OU2,O=PrimeKey,SN=12345+JurisdictionCountry=SE,BusinessCategory=Private Organization");
    }

    /* This is apparently allowed but puts the system in a world of pain, since other functions are not adapted to handle an empty subjectDN
    @Test
    public void test59CertificateRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(false, true, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test60CertificateRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(true, true, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test61SoftTokenRequestWithoutDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(false, false, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Test
    public void test62SoftTokenRequestWithDnOverrideFromEndEntityInformation() throws Exception {
        try {
            testCertificateRequestWithEeiDnOverride(true, false, "", "");
            fail("Was able to provide an empty subjectDN.");
        } catch (EjbcaException_Exception e) {
            log.error(e.getMessage(), e);
        }
    }
    */

    @Test
    public void test70CreateSoftCryptoToken() throws Exception {
        log.trace(">test70CreateSoftCryptoToken()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());

        String ctname = "NewTestCryptoTokenThroughWS";

        // Remove any residues from earlier test runs
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if (ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid);
        }

        try {
            List<KeyValuePair> cryptotokenProperties = new ArrayList<>();
            KeyValuePair allowExtract = new KeyValuePair();
            allowExtract.setKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY);
            allowExtract.setValue(Boolean.toString(false));
            cryptotokenProperties.add(allowExtract);

            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            assertNotNull("Creating a new SoftCryptoToken failed", ctid);
            CryptoTokenInfo token = cryptoTokenManagementSession.getCryptoTokenInfo(intAdmin, ctid);

            Properties ctproperties = token.getCryptoTokenProperties();
            assertEquals("Incorrect number of properties created in crypto token.", 2, ctproperties.keySet().size());
            assertEquals("SoftCryptoToken", token.getType());
            assertFalse(Boolean.getBoolean((String)token.getCryptoTokenProperties().get(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY)));
            assertTrue(token.isActive());
            cryptoTokenManagementSession.deactivate(intAdmin, ctid);
            assertFalse(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid));
            cryptoTokenManagementSession.activate(intAdmin, ctid, "1234".toCharArray());
            assertTrue(cryptoTokenManagementSession.isCryptoTokenStatusActive(intAdmin, ctid));
        } finally {
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            if (ctid != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid);
            }
        }
        log.trace("<test70CreateSoftCryptoToken()");
    }

    @Test
    public void test71GenerateCryptoTokenKeys() throws Exception {
        log.trace(">test71GenerateCryptoTokenKeys()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());

        String ctname = "NewTestCryptoTokenThroughWS";

        // Remove any residues from earlier test runs
        Integer ctid = cryptoTokenManagementSession.getIdFromName(ctname);
        if (ctid != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid);
        }

        try {
            ArrayList<KeyValuePair> cryptotokenProperties = new ArrayList<>();
            KeyValuePair allowExtract = new KeyValuePair();
            allowExtract.setKey(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY);
            allowExtract.setValue(Boolean.toString(false));
            cryptotokenProperties.add(allowExtract);

            ejbcaraws.createCryptoToken(ctname, "SoftCryptoToken", "1234", false, cryptotokenProperties);
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);

            String keyAlias = "testWSGeneratedKeys";
            ejbcaraws.generateCryptoTokenKeys(ctname, keyAlias, "RSA1024");
            List<String> keyAliases = cryptoTokenManagementSession.getKeyPairAliases(intAdmin, ctid);
            assertTrue(keyAliases.contains(keyAlias));
            KeyPairInfo keyInfo = cryptoTokenManagementSession.getKeyPairInfo(intAdmin, ctid, keyAlias);
            assertEquals("RSA", keyInfo.getKeyAlgorithm());
            assertEquals("1024", keyInfo.getKeySpecification());
        } finally {
            ctid = cryptoTokenManagementSession.getIdFromName(ctname);
            if (ctid != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, ctid);
            }
        }
        log.trace("<test71GenerateCryptoTokenKeys()");
    }

    @Test
    public void test72CreateCA() throws Exception {
        log.trace(">test72CreateCA()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        final String caName = "NewTestCAThroughWS";
        final String cryptoTokenName = caName + "CryptoToken";
        // Remove any residues from earlier test runs
        if (caSession.existsCa(caName)) {
            CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caName));
        }
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(intAdmin, cryptoTokenId);
        }
        try {
            // Create CryptoToken
            final List<KeyValuePair> cryptoTokenProperties = new ArrayList<>();
            cryptoTokenProperties.add(getKeyValuePair(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.FALSE.toString()));
            ejbcaraws.createCryptoToken(cryptoTokenName, "SoftCryptoToken", "1234", true, cryptoTokenProperties);
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            // Generate CA key pairs
            final String decKeyAlias = CAToken.SOFTPRIVATEDECKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, decKeyAlias, "RSA1024");
            final String signKeyAlias = CAToken.SOFTPRIVATESIGNKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, signKeyAlias, "RSA1024");
            final String testKeyAlias = "test72CreateCATestKey";
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, testKeyAlias, "secp256r1");
            // Construct the CAToken's properties
            final List<KeyValuePair> purposeKeyMapping = new ArrayList<>();
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, decKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, testKeyAlias));
            // Try to create a CA signed by an external CA. It should fail.
            try {
                ejbcaraws.createCA(caName, "CN="+caName, "x509", 3L, null, "SHA256WithRSA", CAInfo.SIGNEDBYEXTERNALCA, cryptoTokenName, purposeKeyMapping, null);
                fail("It was possible to create a CA signed by an external CA");
            } catch (EjbcaException_Exception e) {
                if (!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED.getInternalErrorCode())) {
                    throw e;
                }
            }
            // Try to create a CA that already exists. It should fail
            final String existingTestCA = "WSCreateCATestTestingExistingCA";
            CaTestCase.createTestCA(existingTestCA);
            try {
                ejbcaraws.createCA(existingTestCA, caSession.getCAInfo(intAdmin, existingTestCA).getSubjectDN(), "x509", 3L, null, "SHA256WithRSA",
                        CAInfo.SELFSIGNED, cryptoTokenName, purposeKeyMapping, null);
                fail("It was possible to create a CA even though the CA already exists");
            } catch (EjbcaException_Exception e) {
                if (!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.CA_ALREADY_EXISTS.getInternalErrorCode())) {
                    throw e;
                }
                CaTestCase.removeTestCA(existingTestCA);
            }
            
            // set some non-default settings
            List<KeyValuePair> caSettings = new ArrayList<>();
            add(caSettings, "certificateAiaDefaultCaIssuerUri", "http://www.example.com/600/cacerts");
            add(caSettings, "defaultCRLDistPoint", "http://www.example.com/600/cdp");
            add(caSettings, "defaultOCSPServiceLocator", "http://www.example.com/600/ocsp");
            add(caSettings, "useAuthorityKeyIdentifier", "true");
            add(caSettings, "deltaCRLPeriod", "0");
            add(caSettings, "doEnforceUniqueDistinguishedName", "false");
            add(caSettings, "doEnforceUniquePublicKeys", "false");
            add(caSettings, "generateCrlUponRevocation", "true");
            
            // Try to create a CA. It should succeed (Happy path test)
            ejbcaraws.createCA(caName, "CN="+caName, "x509", 3L, null, "SHA256WithRSA", CAInfo.SELFSIGNED, cryptoTokenName, purposeKeyMapping, caSettings);
            // Verify the new CA's parameters
            final CAInfo caInfo = caSession.getCAInfo(intAdmin, caName);
            assertNotNull(caInfo);
            assertEquals(caName, caInfo.getName());
            assertEquals("CN=" + caName, caInfo.getSubjectDN());
            assertEquals(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, caInfo.getCertificateProfileId());
            assertEquals(CAInfo.SELFSIGNED, caInfo.getSignedBy());
            assertEquals(CAInfo.CATYPE_X509, caInfo.getCAType());
            
            // confirm settings were set
            X509CAInfo x509CaInfo = (X509CAInfo) caInfo;
            assertNotNull(x509CaInfo);
            assertEquals(true, x509CaInfo.getUseAuthorityKeyIdentifier());
            assertEquals(0, x509CaInfo.getDeltaCRLPeriod());
            assertEquals(false, x509CaInfo.isDoEnforceUniqueDistinguishedName());
            assertEquals(false, x509CaInfo.isDoEnforceUniquePublicKeys());
            assertEquals(true, x509CaInfo.isGenerateCrlUponRevocation());
            assertEquals("http://www.example.com/600/cdp", x509CaInfo.getDefaultCRLDistPoint());
            assertEquals("http://www.example.com/600/ocsp", x509CaInfo.getDefaultOCSPServiceLocator());
            assertEquals(1, x509CaInfo.getCertificateAiaDefaultCaIssuerUri().size());
            assertEquals("http://www.example.com/600/cacerts", x509CaInfo.getCertificateAiaDefaultCaIssuerUri().get(0));
            
        } finally {
            if (caSession.existsCa(caName)) {
                CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caName));
            }
            cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            if (cryptoTokenId != null) {
                cryptoTokenManagementSession.deleteCryptoToken(intAdmin, cryptoTokenId);
            }
        }
        log.trace("<test72CreateCA()");
    }
    
    private void add(List<KeyValuePair> keyValuePairs, String key, String value) {
        KeyValuePair keyValuePair = new KeyValuePair();
        keyValuePair.setKey(key);
        keyValuePair.setValue(value);
        keyValuePairs.add(keyValuePair);
    }

    /**
     * Create an externally signed CA through WS
     * 
     */
    @Test
    public void testCreateExternallySignedCa() throws Exception {
        Assume.assumeTrue("Skipped on community edition", enterpriseEjbBridgeSession.isRunningEnterprise());
        //Create an external CA
        final String caName = "testCreateExternallySignedCa";
        final String profileName = "testCreateExternallySignedCa";
        final String caDn = "CN=" + caName;
        final String cryptoTokenName = "testCreateExternallySignedCa";
        int cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(intAdmin, cryptoTokenName);
        final String rootCaName = "ExternalCaRoot";
        X509CA rootCa = CaTestUtils.createActiveX509Ca(intAdmin, rootCaName, rootCaName, "CN="+rootCaName);
        try {
            // Generate CA key pairs
            final String decKeyAlias = CAToken.SOFTPRIVATEDECKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, decKeyAlias, "RSA1024");
            final String signKeyAlias = CAToken.SOFTPRIVATESIGNKEYALIAS;
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, signKeyAlias, "RSA1024");
            final String testKeyAlias = "testCreateExternallySignedCa";
            ejbcaraws.generateCryptoTokenKeys(cryptoTokenName, testKeyAlias, "RSA1024");
            final List<KeyValuePair> purposeKeyMapping = new ArrayList<>();
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, decKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signKeyAlias));
            purposeKeyMapping.add(getKeyValuePair(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, testKeyAlias));
            byte[] csr = ejbcaraws.createExternallySignedCa(caName, caDn, "x509", 3L, null, "SHA256WithRSA", cryptoTokenName, purposeKeyMapping,
                    null);
            //Verify that CA has been created
            CAInfo caInfo = caSession.getCAInfo(intAdmin, caName);
            assertNotNull("CA was not created.", caInfo);
            assertEquals("CA was not created as signed by external", CAInfo.SIGNEDBYEXTERNALCA, caInfo.getSignedBy());
            assertEquals("CA is not in state of awaiting certificate response", CAConstants.CA_WAITING_CERTIFICATE_RESPONSE, caInfo.getStatus());
            //Generate the certificate
            PKCS10RequestMessage msg = new PKCS10RequestMessage(csr);  
            EndEntityProfile endEntityProfile = new EndEntityProfile();
            endEntityProfile.setDefaultCertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
            endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA));
            endEntityProfile.setDefaultCA(rootCa.getCAId());
            endEntityProfile.setAvailableCAs(Arrays.asList(rootCa.getCAId()));
            int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, endEntityProfile);
            EndEntityInformation endEntityInformation = new EndEntityInformation(caName, caDn, rootCa.getCAId(), null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId,
                    CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, EndEntityConstants.TOKEN_USERGEN, null);
            endEntityInformation.setPassword("foo123");
            endEntityManagementSession.addUser(intAdmin, endEntityInformation, false);
            X509ResponseMessage response = (X509ResponseMessage) certificateCreateSession.createCertificate(intAdmin, endEntityInformation, msg,
                    X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate certificate =  (X509Certificate) response.getCertificate();
            //Since we're working with an "external" CA, remove the end entity and certificate from the database
            endEntityManagementSession.deleteUser(intAdmin, caName);
            internalCertificateStoreSession.removeCertificatesByUsername(caName);
            //Process the response
            List<byte[]> chain = new ArrayList<>();
            chain.add(rootCa.getCACertificate().getEncoded());
            ejbcaraws.caCertResponse(caName, certificate.getEncoded(), chain, "foo123");
            //Verify that the CA is now active
            caInfo = caSession.getCAInfo(intAdmin, caName);
            assertEquals("CA is not active as expected.", CAConstants.CA_ACTIVE, caInfo.getStatus());
        } finally {
            CaTestUtils.removeCa(intAdmin, cryptoTokenName, caName);
            CaTestUtils.removeCa(intAdmin, cryptoTokenName, rootCaName);
            CryptoTokenTestUtils.removeCryptoToken(intAdmin, cryptoTokenId);
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profileName);
            try {
            endEntityManagementSession.deleteUser(intAdmin, caName);
            } catch(NoSuchEndEntityException | CouldNotRemoveEndEntityException e) {
                //NOPMD Ignore
            }
            internalCertificateStoreSession.removeCertificatesByUsername(caName);
        }
    }

    private KeyValuePair getKeyValuePair(final String key, final String value) {
        final KeyValuePair keyValuePair = new KeyValuePair();
        keyValuePair.setKey(key);
        keyValuePair.setValue(value);
        return keyValuePair;
    }

    @Test
    public void test73ManageSubjectInRole() throws Exception {
        log.trace(">test73AddSubjectToRole()");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());

        String rolename = "TestWSNewAccessRole";
        String testAdminUsername = "newWsAdminUserName";

        // Remove any residues from earlier test runs
        final Role oldRole = roleSession.getRole(intAdmin, null, rolename);
        if (oldRole!=null) {
            roleSession.deleteRoleIdempotent(intAdmin, oldRole.getRoleId());
        }
        File fileHandle = null;
        try {
            CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
            assertNotNull("No CA with name " + getAdminCAName() + " was found.", cainfo);

            // Create/update the admin end entity and issue its certificate
            EndEntityInformation adminUser = endEntityAccessSession.findUser(intAdmin, testAdminUsername);
            if(adminUser == null) {
                adminUser = new EndEntityInformation();
                adminUser.setUsername(testAdminUsername);
                adminUser.setPassword("foo123");
                adminUser.setDN("CN="+testAdminUsername);
                adminUser.setCAId(cainfo.getCAId());
                adminUser.setEmail(null);
                adminUser.setSubjectAltName(null);
                adminUser.setStatus(EndEntityConstants.STATUS_NEW);
                adminUser.setTokenType(SecConst.TOKEN_SOFT_JKS);
                adminUser.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
                adminUser.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                adminUser.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
                log.info("Adding new user: "+adminUser.getUsername());
                endEntityManagementSession.addUser(intAdmin, adminUser, true);
            } else {
                adminUser.setStatus(EndEntityConstants.STATUS_NEW);
                adminUser.setPassword("foo123");
                log.info("Changing user: "+adminUser.getUsername());
                endEntityManagementSession.changeUser(intAdmin, adminUser, true);
            }
            fileHandle = BatchCreateTool.createUser(intAdmin, new File(P12_FOLDER_NAME), adminUser.getUsername());
            adminUser = endEntityAccessSession.findUser(intAdmin, testAdminUsername);

            // Create a new role
            log.info("Creating new role: "+rolename);
            final Role role = roleSession.persistRole(intAdmin, new Role(null, rolename, Collections.singletonList(StandardRules.ROLE_ROOT.resource()), null));
            List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(intAdmin, role.getRoleId());
            assertTrue("New role "+rolename+" should have been empty.", roleMembers.isEmpty());

            // Add adminUser to a non-existing role. It should fail
            try {
                ejbcaraws.addSubjectToRole("NoneExistingRole", getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(),
                        AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
                fail("Succeeded in adding subject to a non-existing role");
            } catch(EjbcaException_Exception e) {
                if(!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.ROLE_DOES_NOT_EXIST.getInternalErrorCode())) {
                    throw e;
                }
            }

            // Add adminUser to the new role. It should succeed
            ejbcaraws.addSubjectToRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(),
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            // Verify the admin data
            final Role roleAfterAdd = roleSession.getRole(intAdmin, null, rolename);
            final List<RoleMember> roleMembersAfterAdd = roleMemberSession.getRoleMembersByRoleId(intAdmin, roleAfterAdd.getRoleId());
            assertEquals("Failed to add subject to role.", 1, roleMembersAfterAdd.size());
            final RoleMember roleMember = roleMembersAfterAdd.get(0);
            assertEquals(cainfo.getCAId(), roleMember.getTokenIssuerId());
            assertEquals(X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue(), roleMember.getTokenMatchKey());
            assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
            assertEquals(adminUser.getCertificateDN(), roleMember.getTokenMatchValue());
            // Remove adminUser specified by a non-existing CA. It should fail
            try {
                ejbcaraws.removeSubjectFromRole(rolename, "NoneExistingCA", X500PrincipalAccessMatchValue.WITH_FULLDN.name(),
                        AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
                fail("Succeeded in adding subject to a non-existing role");
            } catch(EjbcaException_Exception e) {
                if(!e.getFaultInfo().getErrorCode().getInternalErrorCode().equals(ErrorCode.CA_NOT_EXISTS.getInternalErrorCode())) {
                    throw e;
                }
            }
            // Remove adminUser from the new role. It should succeed
            ejbcaraws.removeSubjectFromRole(rolename, getAdminCAName(), X500PrincipalAccessMatchValue.WITH_FULLDN.name(),
                    AccessMatchType.TYPE_EQUALCASE.name(), adminUser.getCertificateDN());
            final Role roleAfterRemove = roleSession.getRole(intAdmin, null, rolename);
            final List<RoleMember> roleMembersAfterRemove = roleMemberSession.getRoleMembersByRoleId(intAdmin, roleAfterRemove.getRoleId());
            assertTrue("Failed to remove subject to role.", roleMembersAfterRemove.isEmpty());
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, testAdminUsername, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
            final Role role = roleSession.getRole(intAdmin, null, rolename);
            if (role!=null) {
                roleSession.deleteRoleIdempotent(intAdmin, role.getRoleId());
            }
            if( fileHandle != null) {
                FileTools.delete(fileHandle);
            }
        }
        log.trace("<test73AddSubjectToRole()");
    }

    @Test
    public void test74GetExpiredCerts() throws Exception {
        log.trace(">test74GetExpiredCert()");
        getExpiredCerts();
        log.trace("<test74GetExpiredCert()");
    }

    /**
     * Tests a request without subjectDN.
     * @throws Exception in case of error
     */
    @Test
    public void test75CertificateRequestWithOnlyAltNames() throws Exception {
        final String username = "wsRequestOnlyAltNames" + new SecureRandom().nextLong();
        final String eeProfileName = username;
        // Generate a CSR
        final KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, DnComponents.stringToBcX500Name("CN=NOUSED"),
                keyPair.getPublic(), new DERSet(), keyPair.getPrivate(), null);
        final String b64csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));
        String fingerprint = null;
        try {
            // Setup an End Entity Profile that don't require any Subject DN and has a DNSName field
            final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
            endEntityProfile.setRequired(DnComponents.COMMONNAME, 0, false);
            endEntityProfileSession.addEndEntityProfile(intAdmin, eeProfileName, endEntityProfile);
            // Set some user data
            final String SUBJECT_DN = "";
            final String SUBJECT_AN = "dNSName="+username+".primekey.se";
            final UserDataVOWS userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(PASSWORD);
            userDataVOWS.setClearPwd(true);
            userDataVOWS.setSubjectDN(SUBJECT_DN);
            userDataVOWS.setCaName(getAdminCAName());
            userDataVOWS.setEmail(null);
            userDataVOWS.setSubjectAltName(SUBJECT_AN);
            userDataVOWS.setStatus(EndEntityConstants.STATUS_NEW);
            userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            userDataVOWS.setEndEntityProfileName(eeProfileName);
            userDataVOWS.setCertificateProfileName("ENDUSER");
            // Issue a certificate
            final CertificateResponse certificateResponse = ejbcaraws.certificateRequest(userDataVOWS, b64csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            assertNotNull("CertificateResponse was null.", certificateResponse);
            // Check that the Subject DN and AN was stored correctly in the certificate
            final X509Certificate x509Certificate = certificateResponse.getCertificate();
            fingerprint = CertTools.getFingerprintAsString(x509Certificate);
            log.debug(" Certificte SDN: " + CertTools.getSubjectDN(x509Certificate));
            log.debug(" Certificte SAN: " + DnComponents.getSubjectAlternativeName(x509Certificate));
            assertEquals("Unexpected Subject DN stored in certificate.", SUBJECT_DN, CertTools.getSubjectDN(x509Certificate));
            assertEquals("Unexpected Subject AN stored in certificate.", SUBJECT_AN, DnComponents.getSubjectAlternativeName(x509Certificate));
            // Check that the Subject DN and AN was stored correctly in the EE
            final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(intAdmin, username);
            log.debug(" End entity SDN: " + endEntityInformation.getDN());
            log.debug(" End entity SAN: " + endEntityInformation.getSubjectAltName());
            assertEquals("Unexpected Subject DN stored in end entity.", SUBJECT_DN, endEntityInformation.getDN());
            assertEquals("Unexpected Subject AN stored in end entity.", SUBJECT_AN, endEntityInformation.getSubjectAltName());
        } finally {
            if (fingerprint!=null) {
                // Make sure to delete the certificate since the default AdminCA wont have "Enforce unique DN: false", so next round works
                internalCertificateStoreSession.removeCertificate(fingerprint);
            }
            deleteUser(username);
            try {
                endEntityProfileSession.removeEndEntityProfile(intAdmin, eeProfileName);
            } catch (AuthorizationDeniedException e) {
                log.debug("Error during cleanup: " + e.getMessage());
            }
        }
    }


    @Test
    public void test76ImportAndUpdateExternalCvcaCaCertificate() throws Exception {
        log.trace(">test76ImportAndUpdateExternalCvcaCaCertificate");
        log.debug("Enterprise Edition: " + enterpriseEjbBridgeSession.isRunningEnterprise());
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());

        try {
            // A: Imports a CA certificate of an external CVCA (CVC certificate with at least C=${ISO-3166-2}, CN != null).
            log.debug("Test import a CA certificate of an external CVCA.");
            String caname = "Test-Import-CVCA";
            removeCaIfExists(caname);
            final byte[] importFile = readDerFile("external_cvca_certificate_for_import.der");
            ejbcaraws.importCaCert(caname, importFile);
            assertTrue("Imported CVCA must exists.", caSession.existsCa(caname));
            CAInfo cainfo = caSession.getCAInfo(intAdmin, caname);
            assertEquals("CVCA must be a CVC CA.", CAInfo.CATYPE_CVC, cainfo.getCAType());
            assertCertificateEquals("The imported CA certificate chain must match the CA certificate chain after import.", importFile, cainfo);

            // Exceptions: Import of the same CA again must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CVCA again (one time too much).");
            caname = "Test-Import-CVCA";
            try {
                ejbcaraws.importCaCert(caname, importFile);
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with name " + caname + " already exists.");
            }
            // Exceptions: Import of the same CA certificate again (with other name) must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CVCA again (with other name).");
            caname = "Test-Import-CVCA-new";
            removeCaIfExists(caname);
            try {
                ejbcaraws.importCaCert(caname, readPemFile("external_cvca_certificate_for_import.pem").getBytes());
                fail();
            } catch(Exception e) {
                final int caid = caSession.getCAInfo(intAdmin, "Test-Import-CVCA").getCAId();
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with id " + caid + " already exists.");
            }

            // B: Updates a CA certificate of an external CVCA (CVC certificate with at least C=${ISO-3166-2}, CN != null).
            log.debug("Test update a CA certificate of an external CVCA.");
            caname = "Test-Import-CVCA";
            final byte[] updateFile = readDerFile("external_cvca_certificate_for_update.der");
            ejbcaraws.updateCaCert(caname, updateFile);
            cainfo = caSession.getCAInfo(intAdmin, caname);
            assertCertificateEquals("The updated CA certificate chain must replace the existing CA certificate chain.", updateFile, cainfo);

            // Exceptions: Update of the same CA again must throw a CertificateImportException.
            log.debug("Test update a CA certificate of an external CVCA again (one time to much).");
            caname = "Test-Import-CVCA";
            try {
                ejbcaraws.updateCaCert(caname, updateFile);
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The CA certificate chain is already imported.");
            }

            // Exceptions: Import of technical invalid file must throw an EjbcaException with a CertificateParsingException.
            log.debug("Test import a CA certificate with an invalid PEM file.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, null);
            }
            // Exceptions: Import of a certificate file with an invalid certificate chain must throw an EjbcaException with a CertificateImportException.
            log.debug("Test import a CA certificate with an invalid PEM certificate chain.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate_chain.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The provided certificates does not form a full certificate chain.");
            }
        }
        finally { // Clean up.
            removeCaIfExists("Test-Import-CVCA");
        }
        log.trace("<test76ImportAndUpdateExternalCvcaCaCertificate");
    }

    @Test
    public void test77ImportAndUpdateExternalCscaCaCertificate() throws Exception {
        log.trace(">test77ImportAndUpdateExternalCscaCaCertificate");
        try {
            // A: Imports a CA certificate of an external CSCA (X.509 certificate with at least C=${ISO-3166-2}, CN != null and serialNumber != null).
            log.debug("Test import a CA certificate of an external CSCA.");
            String caname = "Test-Import-CSCA";
            removeCaIfExists(caname);

            final byte[] importFile = readPemFile("external_csca_certificate_for_import.pem").getBytes();
            ejbcaraws.importCaCert(caname, importFile);
            assertTrue("Imported CSCA must exists.", caSession.existsCa(caname));
            CAInfo cainfo = caSession.getCAInfo(intAdmin, caname);
            assertEquals("CSCA must be a X.509 CA.", CAInfo.CATYPE_X509, cainfo.getCAType());
            assertCertificateEquals("The imported CA certificate chain must match the existing CA certificate chain after import.", importFile, cainfo);

            // Exceptions: Import of the same CA again must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CSCA again (one time too much).");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.importCaCert(caname, readDerFile("external_csca_certificate_for_import.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with name " + caname + " already exists.");
            }
            // Exceptions: Import of the same CA certificate again (with other name) must throw a CAExistsException.
            log.debug("Test import a CA certificate of an external CSCA again (with other name).");
            caname = "Test-Import-CSCA-new";
            removeCaIfExists(caname);
            try {
                ejbcaraws.importCaCert(caname, readPemFile("external_csca_certificate_for_import.pem").getBytes());
                fail();
            } catch(Exception e) {
                final int caid = caSession.getCAInfo(intAdmin, "Test-Import-CSCA").getCAId();
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, "CA with id " + caid + " already exists.");
            }
            if(caSession.existsCa(caname)) {
                log.debug("Remove CA " + caname + " before test.");
                CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caname));
            }

            // B: Updates a CA certificate of an external CSCA (X.509 certificate with at least C=${ISO-3166-2}, CN != null and serialNumber != null).
            log.debug("Test update a CA certificate of an external CSCA.");
            caname = "Test-Import-CSCA";
            final byte[] updateFile = readDerFile("external_csca_certificate_for_update.der");
            ejbcaraws.updateCaCert(caname, updateFile);
            cainfo = caSession.getCAInfo(intAdmin, caname);
            assertCertificateEquals("The updated CA certificate chain must replace the existing CA certificate chain.", updateFile, cainfo);

            // Exceptions: Update of the same CA again must throw a CertificateImportException.
            log.debug("Test update a CA certificate of an external CSCA again (one time to much).");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.updateCaCert(caname, readDerFile("external_csca_certificate_for_update.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The CA certificate chain is already imported.");
            }
            // Exceptions: Update of a CA with a DN which does not match (except CSCA certificates with at least C=${ISO-3166-2}, CN != null and different serialNumber).
            log.debug("Test update a CA certificate of an external CA with different Subject-DN.");
            caname = "Test-Import-CSCA";
            try {
                ejbcaraws.updateCaCert(caname, readDerFile("external_cvca_certificate_for_update.der"));
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "Only able to update imported CA certificate if Subject DN of the leaf CA certificate is the same.");
            }

            // Exceptions: Import of technical invalid file must throw an EjbcaException with a CertificateParsingException.
            log.debug("Test import a CA certificate with an invalid PEM file.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.INTERNAL_ERROR, null);
            }
            // Exceptions: Import of a certificate file with an invalid certificate chain must throw an EjbcaException with a CertificateImportException.
            log.debug("Test import a CA certificate with an invalid PEM certificate chain.");
            try {
                ejbcaraws.importCaCert(caname, readPemFile("invalid_certificate_chain.pem").getBytes());
                fail();
            } catch(Exception e) {
                assertEjbcaException(e, ErrorCode.CERTIFICATE_IMPORT, "The provided certificates does not form a full certificate chain.");
            }
        }
        finally { // Clean up.
            removeCaIfExists("Test-Import-CSCA");
        }
        log.trace("<test77ImportAndUpdateExternalCscaCaCertificate");
    }
    
    /**
     * Creates a user with data in the ExtendedInformation object, in this case
     * a "CA/B Forum Organization Identifier" Certificate Extension.
     */
    @Test
    public void test78AddUserWithExtendedInformation() throws Exception {
        log.trace(">test78AddUserWithExtendedInformation");
        final String testUser = "ejbcawstest_extdata";
        final String testSubjectDn = "CN=" + testUser;
        final String testOrgIdent = "NTRUS+CA-123-456+789";
        deleteUser(testUser);
        try {
            // Create profiles with the certificate extension enabled
            int certificateProfileId = createCertificateProfile(WS_CERTPROF_EI);
            final CertificateProfile profile = certificateProfileSession.getCertificateProfile(certificateProfileId);
            profile.setUseCabfOrganizationIdentifier(true);
            certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, profile);
            createEndEndtityProfile(WS_EEPROF_EI, certificateProfileId, true);
            // Given
            final UserDataVOWS userData = new UserDataVOWS();
            userData.setUsername(testUser);
            userData.setPassword(PASSWORD);
            userData.setClearPwd(false);
            userData.setSubjectDN(testSubjectDn);
            userData.setCaName(getAdminCAName());
            userData.setEmail(null);
            userData.setSubjectAltName(null);
            userData.setStatus(EndEntityConstants.STATUS_NEW);
            userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            userData.setEndEntityProfileName(WS_EEPROF_EI);
            userData.setCertificateProfileName(WS_CERTPROF_EI);
            final List<ExtendedInformationWS> extendedInformation = new ArrayList<>();
            extendedInformation.add(new ExtendedInformationWS("cabforganizationidentifier", testOrgIdent));
            userData.setExtendedInformation(extendedInformation);
            // When
            ejbcaraws.editUser(userData);
            // Then
            final EndEntityInformation savedEndEntity = endEntityAccessSession.findUser(intAdmin, testUser);
            assertEquals("Wrong Subject DN was returned", testSubjectDn, savedEndEntity.getDN());
            final ExtendedInformation savedExtInfo = savedEndEntity.getExtendedInformation();
            assertNotNull("ExtendedInformation was null", savedExtInfo);
            assertEquals("CA/B Forum Organization Identifier was not set in ExtendedInformation", testOrgIdent,
                    savedExtInfo.getCabfOrganizationIdentifier());
        } finally {
            deleteUser(testUser);
            log.trace("<test78AddUserWithExtendedInformation");
        }
    }
    
    /**
     * Creates a user with data in the ExtendedInformation object, in this case
     * a "CA/B Forum Organization Identifier" Certificate Extension.
     * In this test, the certificate extension is not enabled in the Certificate Profiles,
     * so the request should fail.
     */
    @Test
    public void testAddUserWithUnconfiguredExtension() throws ApprovalException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, WaitingForApprovalException_Exception {
        log.trace(">testAddUserWithUnconfiguredExtension");
        final String testUser = "ejbcawstest_extdata";
        final String testSubjectDn = "CN=" + testUser;
        final String testOrgIdent = "NTRUS+CA-123-456+789";
        deleteUser(testUser);
        try {
            // Given
            final UserDataVOWS userData = new UserDataVOWS();
            userData.setUsername(testUser);
            userData.setPassword(PASSWORD);
            userData.setClearPwd(true);
            userData.setSubjectDN(testSubjectDn);
            userData.setCaName(getAdminCAName());
            userData.setEmail(null);
            userData.setSubjectAltName(null);
            userData.setStatus(EndEntityConstants.STATUS_NEW);
            userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            userData.setEndEntityProfileName("EMPTY");
            userData.setCertificateProfileName("SERVER");
            final List<ExtendedInformationWS> extendedInformation = new ArrayList<>();
            extendedInformation.add(new ExtendedInformationWS("cabforganizationidentifier", testOrgIdent)); // not enabled in Certificate Profile
            userData.setExtendedInformation(extendedInformation);
            // When
            ejbcaraws.editUser(userData);
            fail("Should throw EndEntityProfileValidationException");
        } catch (UserDoesntFullfillEndEntityProfile_Exception e) {
            // Expected
            assertEquals("org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException: Certificate Extension 'cabforganizationidentifier' is not allowed in Certificate Profile, but was present with value 'NTRUS+CA-123-456+789'", e.getMessage());
        } finally {
            deleteUser(testUser);
            log.trace("<testAddUserWithUnconfiguredExtension");
        }
    }
    
    @Test
    public void testCaRenewCertRequest() throws Exception {
        final String rootCaDn = "CN=testCaRenewCertRequestRoot";
        final String subCaDn = "CN=testCaRenewCertRequestSubCa";       
        X509CA root = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(intAdmin, rootCaDn);
        X509CA subCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(intAdmin, subCaDn, root.getCAId());  
        final String subCaName = DnComponents.getPartFromDN(subCaDn, "CN");
        List<byte[]> cachain = Arrays.asList(root.getCACertificate().getEncoded());
        try {
            byte[] csrBytes = ejbcaraws.caRenewCertRequest(subCaName, cachain, false, false, true, String.valueOf(CryptoTokenTestUtils.SOFT_TOKEN_PIN));
            PKCS10RequestMessage msg = new PKCS10RequestMessage(csrBytes);
            assertTrue("CSR was not correctly signed", msg.verify());
            assertEquals("Request does not have the correct request DN.", subCaDn, msg.getRequestDN());
        } finally {
            CaTestUtils.removeCa(intAdmin, root.getCAInfo());
            CaTestUtils.removeCa(intAdmin, subCa.getCAInfo());
        }
    }
    
    @Test
    public void testCaRenewCertRequestForNonExistantCa() throws Exception {
        final String rootCaDn = "CN=testCaRenewCertRequestRoot";
        final String subCaDn = "CN=NonExistentCa";       
        X509CA root = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(intAdmin, rootCaDn);
        final String subCaName = DnComponents.getPartFromDN(subCaDn, "CN");
        List<byte[]> cachain = Arrays.asList(root.getCACertificate().getEncoded());
        try {
            ejbcaraws.caRenewCertRequest(subCaName, cachain, false, false, true, String.valueOf(CryptoTokenTestUtils.SOFT_TOKEN_PIN));
            fail("CSR should not have been returned for a non-existant CA");
        } catch(CADoesntExistsException_Exception e) {
            // NOPMD
        } finally {
            CaTestUtils.removeCa(intAdmin, root.getCAInfo());
        }
    }
    
    @Test
    public void createCertificateWithSubjectDirAttrs() throws Exception {
        final String username = "EjbcaWSTest_createCertificateWithSubjectDirAttrs";
        final String profileName = "EjbcaWSTest_CertificateWithSubjectDirAttrs";
        final String subjectDn = "CN=createCertificateWithSubjectDirAttrs,OU=EjbcaWSSystemTest";
        final String subjectDirAttrs = "COUNTRYOFRESIDENCE=AU, COUNTRYOFRESIDENCE=FR, COUNTRYOFCITIZENSHIP=SE, COUNTRYOFCITIZENSHIP=DE, COUNTRYOFCITIZENSHIP=US";
        final UserDataVOWS userdata = new UserDataVOWS();
        userdata.setStatus(EndEntityConstants.STATUS_NEW);
        userdata.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userdata.setEndEntityProfileName(profileName);
        userdata.setCertificateProfileName(profileName);
        userdata.setCaName(getAdminCAName());
        userdata.setUsername(username);
        userdata.setSubjectDN(subjectDn);
        final List<ExtendedInformationWS> ei = new ArrayList<>();
        ei.add(new ExtendedInformationWS("subjectdirattributes", subjectDirAttrs));
        userdata.setExtendedInformation(ei);
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        try {
            // Create profiles with Subject Directory Attributes
            CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certProf.setUseSubjectDirAttributes(true);
            int certProfId = certificateProfileSession.addCertificateProfile(admin, profileName, certProf);
            EndEntityProfile eeProf = new EndEntityProfile();
            eeProf.addField("ORGANIZATIONALUNIT");
            eeProf.addField("COUNTRYOFCITIZENSHIP");
            eeProf.addField("COUNTRYOFCITIZENSHIP");
            eeProf.addField("COUNTRYOFCITIZENSHIP");
            eeProf.addField("COUNTRYOFRESIDENCE");
            eeProf.addField("COUNTRYOFRESIDENCE");
            eeProf.setAvailableCertificateProfileIds(Collections.singleton(certProfId));
            eeProf.setDefaultCertificateProfile(certProfId);
            eeProf.setAvailableCAs(Collections.singleton(SecConst.ALLCAS));
            endEntityProfileSession.addEndEntityProfile(admin, profileName, eeProf);
            // Issue the certificate
            final CertificateResponse resp = ejbcaraws.certificateRequest(userdata, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            final X509Certificate cert = resp.getCertificate();
            assertEquals(subjectDn, CertTools.getSubjectDN(cert));
            final String actualSubjectDirAttrs = SubjectDirAttrExtension.getSubjectDirectoryAttributes(cert);
            assertNotNull("Subject Directory Attributes was missing from certificate", actualSubjectDirAttrs);
            assertEquals(subjectDirAttrs, actualSubjectDirAttrs.toUpperCase(Locale.ROOT));
        } finally {
            deleteUser(username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            endEntityProfileSession.removeEndEntityProfile(admin, profileName);
            certificateProfileSession.removeCertificateProfile(admin, profileName);
        }
    }

    private void assertCertificateEquals(final String label, final byte[] left, final CAInfo caInfo)
            throws CertificateParsingException, CertificateEncodingException {
        final List<CertificateWrapper> leftSide = CertTools.bytesToListOfCertificateWrapperOrThrow(left);
        final List<CertificateWrapper> rightSide = CertTools.bytesToListOfCertificateWrapperOrThrow(
                caInfo.getCertificateChain().iterator().next().getEncoded());
        assertEquals(label, leftSide.get(0).getCertificate(), rightSide.get(0).getCertificate());

    }

    private void removeCaIfExists(final String caname ) throws Exception {
        if(caSession.existsCa(caname)) {
            log.debug("Remove CA " + caname + " after test.");
            CaTestUtils.removeCa(intAdmin, caSession.getCAInfo(intAdmin, caname));
        }
    }

    private void assertEjbcaException(final Exception exception, final ErrorCode errorCode, final String errorMessage) {
        assertTrue("EjbcaException expected.", exception instanceof EjbcaException_Exception);
        if (StringUtils.isNotEmpty(errorCode.getInternalErrorCode())) {
            assertEquals("Error code:",  errorCode.getInternalErrorCode(), ((EjbcaException_Exception) exception).getFaultInfo().getErrorCode().getInternalErrorCode());
        }
        if (StringUtils.isNotEmpty(errorMessage)) {
            assertEquals("Error message:", errorMessage, ((EjbcaException_Exception) exception).getMessage());
        }
    }

    private void testCertificateRequestWithEeiDnOverride(boolean allowDNOverrideByEndEntityInformation, boolean useCsr, String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
            certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
        }
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowDNOverrideByEndEntityInformation(allowDNOverrideByEndEntityInformation);
        certificateProfileSession.addCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME, profile);
        //This test will fail if EEP limitations are enabled
        GlobalConfiguration originalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableEndEntityProfileLimitations(false);
        globalConfigurationSession.saveConfiguration(intAdmin, globalConfiguration);
        String userName = "eeiDnOverride" + secureRandom.nextLong();
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword(PASSWORD);
        userData.setClearPwd(true);
        userData.setSubjectDN(requestedSubjectDN);
        userData.setCaName(getAdminCAName());
        userData.setEmail(null);
        userData.setSubjectAltName(null);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userData.setEndEntityProfileName("EMPTY");
        userData.setCertificateProfileName(WS_TEST_CERTIFICATE_PROFILE_NAME);
        final X509Certificate cert;
        try {
            if (useCsr) {
                KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
                PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA",
                        DnComponents.stringToBcX500Name("CN=NOUSED"), keys.getPublic(), new DERSet(), keys.getPrivate(), null);
                final String csr = new String(Base64.encode(pkcs10.toASN1Structure().getEncoded()));
                CertificateResponse response = ejbcaraws.certificateRequest(userData, csr, CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                        CertificateHelper.RESPONSETYPE_CERTIFICATE);
                cert = response.getCertificate();
            } else {
                KeyStore ksenv = ejbcaraws.softTokenRequest(userData, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
                assertNotNull(keyStore);
                Enumeration<String> en = keyStore.aliases();
                String alias = en.nextElement();
                if (!keyStore.isKeyEntry(alias)) {
                    alias = en.nextElement();
                }
                cert = (X509Certificate) keyStore.getCertificate(alias);
            }
            final List<Certificate> certificates = Collections.singletonList(cert);
            log.info(certificates.size() + " certs.\n" + new String(CertTools.getPemFromCertificateChain(certificates)));
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
            String resultingSubjectDN = CeSecoreNameStyle.INSTANCE.toString(x500name);
            log.debug("x500name:           " + resultingSubjectDN);
            assertEquals("Unexpected transformation.", expectedSubjectDN, resultingSubjectDN);
        } finally {
            deleteUser(userName);
            if (certificateProfileSession.getCertificateProfileId(WS_TEST_CERTIFICATE_PROFILE_NAME) != 0) {
                certificateProfileSession.removeCertificateProfile(intAdmin, WS_TEST_CERTIFICATE_PROFILE_NAME);
            }
            globalConfigurationSession.saveConfiguration(intAdmin, originalConfiguration);
        }
    }

    private void testCertificateRequestWithSpecialChars(String requestedSubjectDN, String expectedSubjectDN) throws Exception {
        String userName = "wsSpecialChars";
        deleteUser(userName);
        final UserDataVOWS userData = new UserDataVOWS();
        userData.setUsername(userName);
        userData.setPassword(PASSWORD);
        userData.setClearPwd(true);
        userData.setSubjectDN(requestedSubjectDN);
        userData.setCaName(getAdminCAName());
        userData.setEmail(null);
        userData.setSubjectAltName(null);
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userData.setEndEntityProfileName("EMPTY");
        userData.setCertificateProfileName("ENDUSER");

        KeyStore ksenv = ejbcaraws.softTokenRequest(userData, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
        assertNotNull(keyStore);
        Enumeration<String> en = keyStore.aliases();
        String alias = en.nextElement();
        if(!keyStore.isKeyEntry(alias)) {
            alias = en.nextElement();
        }
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        String resultingSubjectDN = cert.getSubjectDN().toString();
        // on RedHat 6.4 with OpenJDK-8 64-Bit '\r' symbol is automatically replaced with '\n'. So try to check again, if difference between expected and actual
        // is in that symbol then test succeeds, otherwise test fails
        try {
            assertEquals(requestedSubjectDN + " was transformed into " + resultingSubjectDN + " (not the expected " + expectedSubjectDN + ")", expectedSubjectDN,
                    resultingSubjectDN);
        } catch (AssertionError e){
            log.info(requestedSubjectDN + " was transformed into '" + resultingSubjectDN + "' (not the expected '" + expectedSubjectDN + "'). Re-checking if it was a \\r replaced by \\n that happens on some platforms.");
            expectedSubjectDN = StringEscapeUtils.escapeJava(expectedSubjectDN);
            requestedSubjectDN = StringEscapeUtils.escapeJava(requestedSubjectDN);
            resultingSubjectDN = StringEscapeUtils.escapeJava(resultingSubjectDN);
            resultingSubjectDN = resultingSubjectDN.replace("\\r", "\\n");
            expectedSubjectDN = expectedSubjectDN.replace("\\r", "\\n");
            assertEquals(requestedSubjectDN + " was transformed into '" + resultingSubjectDN + "' (not the expected '" + expectedSubjectDN + "')" , expectedSubjectDN,
                    resultingSubjectDN);
        } finally {
            deleteUser(userName);
        }
    }
    
    /**
     * Create a user a generate certificate.
     */
    private X509Certificate createUserAndCert(final String username, final int caID, final boolean deleteFirst) throws Exception {
        if (deleteFirst) {
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        }
        final EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        userdata.setPassword(PASSWORD);
        endEntityManagementSession.addUser(intAdmin, userdata, true);
        fileHandles.addAll(BatchCreateTool.createAllNew(intAdmin, new File(P12_FOLDER_NAME)));
        final Collection<Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
        assertEquals("Certificates for user with username " + username + " wasn't exactly one.", 1, userCerts.size());
        return (X509Certificate) userCerts.iterator().next();
    }

    /** Reads a PEM file by the class path. */
    private String readPemFile(final String filename) throws IOException {
        final InputStream stream = getClass().getResourceAsStream(filename);
        final StringWriter writer = new StringWriter();
        IOUtils.copy(stream, writer, StandardCharsets.UTF_8);
        IOUtils.closeQuietly(stream);
        return writer.toString();
    }

    /** Reads a DER file by the class path. */
    private byte[] readDerFile(final String filename) throws IOException {
        final InputStream stream = getClass().getResourceAsStream(filename);
        final byte[] data = new byte[stream.available()];
        stream.read(data);
        IOUtils.closeQuietly(stream);
        return data;
    }

    /** Creates an approvalProfile. Throws an exception, if it exists already. */
    private int createApprovalProfile(final ApprovalProfile profile, final boolean deleteIfExists) throws ApprovalProfileExistsException, AuthorizationDeniedException {
        final String name = profile.getProfileName();
        if (deleteIfExists) {
            final Map<Integer, String> existingApprovalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
            if (existingApprovalProfiles != null && existingApprovalProfiles.values().contains((name))) {
                for (Map.Entry<Integer, String> entry : existingApprovalProfiles.entrySet()) {
                    if (name.equals(entry.getValue())) {
                        approvalProfileSession.removeApprovalProfile(intAdmin, entry.getKey());
                        if (log.isDebugEnabled()) {
                            log.debug( "Removed approval profile '" + entry.getValue() + "' with ID " + entry.getKey() + ".");
                        }
                    }
                }
            }
        }
        final int id = approvalProfileSession.addApprovalProfile(intAdmin, profile);
        log.info( "Created approval profile '" + name + "' with ID " + id + ".");
        return id;
    }
    
    private void deleteUser(final String username) {
        try {
            endEntityManagementSession.deleteUser(intAdmin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        } catch (NoSuchEndEntityException e) {
            // NOPMD: Ignore
        } catch (AuthorizationDeniedException | CouldNotRemoveEndEntityException e) {
            log.warn("Error when deleting user ' " + username + "': " + e.getMessage(), e);
        }
    }
    
    private void createEndEndtityProfile(String profileName, int certificateProfileId, boolean useCabFOrgId) throws  AuthorizationDeniedException {
        // Create suitable EE prof
           try {
               EndEntityProfile profile = new EndEntityProfile();
               profile.addField(DnComponents.ORGANIZATION);
               profile.addField(DnComponents.COUNTRY);
               profile.addField(DnComponents.COMMONNAME);
               profile.addField(DnComponents.JURISDICTIONLOCALITY);
               profile.addField(DnComponents.JURISDICTIONSTATE);
               profile.addField(DnComponents.JURISDICTIONCOUNTRY);
               profile.addField(DnComponents.DATEOFBIRTH);
               profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
               profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, false); // not allowing clear text password is the most common option
               profile.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, true);
               profile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);         
               profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certificateProfileId));

               if(useCabFOrgId) {
                   profile.setCabfOrganizationIdentifierUsed(true);
               }
               
               if (this.endEntityProfileSession.getEndEntityProfile(profileName) == null) {
                   this.endEntityProfileSession.addEndEntityProfile(intAdmin, profileName, profile);
               }
           } catch (EndEntityProfileExistsException pee) {
               log.error("Error creating end entity profile: ", pee);
               throw new IllegalStateException("Can not create end entity profile");
           }
       }
    
    
}
