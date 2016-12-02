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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ejb.FinderException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import javax.xml.namespace.QName;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.PKMACValuesCalculator;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CVCRequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistoryProxySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.DummyCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.EndEntityProfileNotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ErrorCode;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.HardTokenExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.PinDataWS;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UnknownProfileTypeException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;


/**
 * 
 * @version $Id$
 */
public abstract class CommonEjbcaWS extends CaTestCase {

    private static final Logger log = Logger.getLogger(CommonEjbcaWS.class);

    protected static final String P12_FOLDER_NAME = "p12";
    private static final String TEST_ADMIN_USERNAME = "wstest";
    private static final String TEST_ADMIN_FILE = P12_FOLDER_NAME + "/" + TEST_ADMIN_USERNAME+".jks";
    protected static final String TEST_NONADMIN_USERNAME = "wsnonadmintest";
    protected static final String TEST_NONADMIN_FILE =  P12_FOLDER_NAME + "/" + TEST_NONADMIN_USERNAME + ".jks";
    protected static final String TEST_NONADMIN_CN = "CN="+TEST_NONADMIN_USERNAME;
    protected static final String PASSWORD = "foo123";
    
    protected EjbcaWS ejbcaraws;
    protected static String ADMIN_CA_NAME;

    protected final static AuthenticationToken intAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CommonEjbcaWS"));
    protected final String hostname;
    protected final String httpsPort;

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

    private static final String PUBLICKEY_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC/kSfVJ/hyq96xwRRwVdO0ltD\n"
            + "glRyKhVhA0OyI/4ux4a0NIxD4OVstfQmoyt/X7olMG29mZGpinQC6wuaaL0JJ9To\n"
            + "ejr41IwvDrkLKQKdY+mAJ8zUUWFWYqbcurTXrYJCYeG/ETAJZLfD4EKMNCd/lC/r\n" + "G4yg9pzLOMjNr2tQ4wIDAQAB";

    private static final String PUBLICKEY_PEM = "-----BEGIN PUBLIC KEY-----\n" + PUBLICKEY_BASE64 + "\n-----END PUBLIC KEY-----";

    private static final String BADCANAME = "BadCaName";

    protected static final String CA1_WSTESTUSER1 = "CA1_WSTESTUSER1";
    private static final String CA1_WSTESTUSER2 = "CA1_WSTESTUSER2";
    private static final String CA2_WSTESTUSER1 = "CA2_WSTESTUSER1";
    protected static final String CA1_WSTESTUSER1CVCRSA = "TstCVCRSA";
    protected static final String CA2_WSTESTUSER1CVCEC = "TstCVCEC";
    private static final String CA1 = "CA1";
    private static final String CA2 = "CA2";
    private static final String WS_EEPROF_EI = "WS_EEPROF_EI";
    private static final String WS_CERTPROF_EI = "WS_CERTPROF_EI";

    private static final String WSTESTPROFILE = "WSTESTPROFILE";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CertReqHistoryProxySessionRemote certReqHistorySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherProxySessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    public CommonEjbcaWS() {
        hostname = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        httpsPort = SystemTestsConfiguration.getRemotePortHttps(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS));
        log.debug("hostname="+hostname+ " httpsPort="+httpsPort);
    }

    protected static String getAdminCAName() {
        return ADMIN_CA_NAME;
    }
    
    protected static void adminBeforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        setAdminCAName();
    }
    
    protected static void setAdminCAName() {
        List<String> canames = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getActiveCANames(intAdmin);
        if(canames.contains("AdminCA1")) {
            ADMIN_CA_NAME = "AdminCA1";
        } else if(canames.contains("ManagementCA")) {
            ADMIN_CA_NAME = "ManagementCA";
        }
    }

    protected void adminSetUpAdmin() throws Exception {
        if ( !new File(TEST_ADMIN_FILE).exists() ) {
            log.error("Keystore file + '"+TEST_ADMIN_FILE+"' does not exist.");
            return;
        }
        
        System.setProperty("javax.net.ssl.trustStore", TEST_ADMIN_FILE);
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.keyStore", TEST_ADMIN_FILE);
        System.setProperty("javax.net.ssl.keyStorePassword", PASSWORD);
        
        createEjbcaWSPort("https://" + hostname + ":" + httpsPort + "/ejbca/ejbcaws/ejbcaws?wsdl");
    }
    
    private void createEjbcaWSPort(final String url) throws MalformedURLException {
        QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(url), qname);
        this.ejbcaraws = service.getEjbcaWSPort();        
    }

    protected static List<File> setupAccessRights(final String wsadminRoleName) throws CADoesntExistsException,
            AuthorizationDeniedException, EndEntityExistsException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException,
            RoleExistsException, RoleNotFoundException, UnrecoverableKeyException, InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateException, SignRequestSignatureException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException,
            InvalidKeySpecException, FinderException, IOException {
        AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        
        EndEntityInformation user1 = new EndEntityInformation();
        user1.setUsername(TEST_ADMIN_USERNAME);
        user1.setPassword(PASSWORD);
        user1.setDN("CN="+TEST_ADMIN_USERNAME);
        CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
        assertNotNull("No CA with name " + getAdminCAName() + " was found.", cainfo);
        user1.setCAId(cainfo.getCAId());
        user1.setEmail(null);
        user1.setSubjectAltName(null);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(SecConst.TOKEN_SOFT_JKS);
        user1.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
        user1.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        user1.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));

        if (!endEntityManagementSession.existsUser(TEST_ADMIN_USERNAME)) {
            log.info("Adding new user: "+user1.getUsername());
            endEntityManagementSession.addUser(intAdmin, user1, true);
        } else {
            log.info("Changing user: "+user1.getUsername());
            endEntityManagementSession.changeUser(intAdmin, user1, true);
        }
        boolean adminExists = false;
        RoleData role = roleAccessSession.findRole(wsadminRoleName);
        if (role == null) {
            log.info("Creating new role: "+wsadminRoleName);
            role = roleManagementSession.create(intAdmin, wsadminRoleName);
            final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRules.add(new AccessRuleData(wsadminRoleName, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
            role = roleManagementSession.addAccessRulesToRole(intAdmin, role, accessRules);
        }
        for (AccessUserAspectData accessUser : role.getAccessUsers().values()) {
            if (accessUser.getMatchValue().equals(TEST_ADMIN_USERNAME)) {
                adminExists = true;
            }
        }
        if (!adminExists) {
            log.info("Adding admin to role: "+wsadminRoleName);
            List<AccessUserAspectData> list = new ArrayList<AccessUserAspectData>();
            list.add(new AccessUserAspectData(wsadminRoleName, cainfo.getCAId(), X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                    TEST_ADMIN_USERNAME));
            roleManagementSession.addSubjectsToRole(intAdmin, role, list);
            accessControlSession.forceCacheExpire();
        } 
        EndEntityInformation user2 = new EndEntityInformation();
        user2.setUsername(TEST_NONADMIN_USERNAME);
        user2.setPassword(PASSWORD);
        user2.setDN(TEST_NONADMIN_CN);
        user2.setCAId(cainfo.getCAId());
        user2.setEmail(null);
        user2.setSubjectAltName(null);
        user2.setStatus(UserDataVOWS.STATUS_NEW);
        user2.setTokenType(SecConst.TOKEN_SOFT_JKS);
        user2.setEndEntityProfileId(SecConst.EMPTY_ENDENTITYPROFILE);
        user2.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        user2.setType(EndEntityTypes.ENDUSER.toEndEntityType());

        if (!endEntityManagementSession.existsUser(TEST_NONADMIN_USERNAME)) {
            log.debug("Adding new user: "+user2.getUsername());
            endEntityManagementSession.addUser(intAdmin, user2, true);
        } else {
            log.debug("Changing user: "+user2.getUsername());
            endEntityManagementSession.changeUser(intAdmin, user2, true);
        }
        List<File> fileHandles = new ArrayList<File>();
        File p12Directory = new File(P12_FOLDER_NAME);
        try {
            fileHandles.add(BatchCreateTool.createUser(intAdmin, p12Directory, user1.getUsername()));
            fileHandles.add(BatchCreateTool.createUser(intAdmin, p12Directory, user2.getUsername()));
        } catch (NoSuchEndEntityException e) {
            throw new IllegalStateException("End entity not created.", e);
        }
        return fileHandles;
    }

    private String getDN(String userName) {
        return "CN=" + userName + ",O=" + userName.charAt(userName.length() - 1) + "Test";
    }

    private String getReversedDN(String userName) {
        return "O=" + userName.charAt(userName.length() - 1) + "Test,CN=" + userName;
    }

    /** A simple host name verifier for passing HTTPS connections without verifying the hostname against the cert, 
     * used for simple testing.
     */
    class SimpleVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
    /** Getting SSL socket factory using the Admin cert created for client certificate authentication **/
    private SSLSocketFactory getSSLFactory() throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException,
    CertificateException, KeyManagementException {
        // Put the key and certs in the user keystore (if available)
        java.security.KeyStore ks = java.security.KeyStore.getInstance("jks");
        ks.load(new FileInputStream(TEST_ADMIN_FILE), PASSWORD.toCharArray());
        final KeyManagerFactory kmf;
        kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, PASSWORD.toCharArray());
        final KeyManager km[] = kmf.getKeyManagers();
        
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);
        final TrustManager tm[] = tmf.getTrustManagers();
        if ( km==null && tm==null ) {
            return (SSLSocketFactory)SSLSocketFactory.getDefault();
        }
        final SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(km, tm, null);
        return ctx.getSocketFactory();
    }
    /** Return a HttpsURLConnection for a GET, using client certificate authentication to the url. The url should be EJBCA client protected https port, i.e. 8443
     * @param url the URL to connect to, i.e. https://localhost:8443/ejbca/adminweb/index.jsp
     */
    protected HttpURLConnection getHttpsURLConnection(String url) throws IOException, UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        final HttpsURLConnection con;
        URL u = new URL(url);
        con = (HttpsURLConnection)u.openConnection();
        con.setHostnameVerifier(new SimpleVerifier());
        con.setSSLSocketFactory(getSSLFactory());
        con.setRequestMethod("GET");
        con.getDoOutput();
        con.connect();
        return con;
    }

    private void editUser(String userName, String caName) throws ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception, IllegalQueryException_Exception, EndEntityProfileNotFoundException_Exception {
        
   // Test to add a user.
        final UserDataVOWS user = new UserDataVOWS();
        user.setUsername(userName);
        user.setPassword(PASSWORD);
        user.setClearPwd(true);
        user.setSubjectDN("CN=" + userName);
        user.setCaName(caName);
        user.setEmail(null);
        user.setSubjectAltName(null);
        user.setStatus(UserDataVOWS.STATUS_NEW);
        user.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user.setEndEntityProfileName(WS_EEPROF_EI);
        user.setCertificateProfileName(WS_CERTPROF_EI);

        List<ExtendedInformationWS> ei = new ArrayList<ExtendedInformationWS>();
        ei.add(new ExtendedInformationWS(ExtendedInformation.CUSTOMDATA + ExtendedInformation.CUSTOM_REVOCATIONREASON, Integer
                .toString(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD)));
        ei.add(new ExtendedInformationWS(ExtendedInformation.SUBJECTDIRATTRIBUTES, "DATEOFBIRTH=19761123"));

        user.setExtendedInformation(ei);

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
        assertTrue(userdata.getCertificateProfileName().equals(WS_CERTPROF_EI));
        assertTrue(userdata.getEndEntityProfileName().equals(WS_EEPROF_EI));
        assertTrue(userdata.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_USERGENERATED));
        assertTrue(userdata.getStatus() == UserDataVOWS.STATUS_NEW);

        List<ExtendedInformationWS> userei = userdata.getExtendedInformation();
        assertNotNull(userei);
        // The extended information can contain other stuff as well
        boolean foundrevreason = false;
        boolean founddirattrs = false;
        for (ExtendedInformationWS item : userei) {
            if (StringUtils.equals(item.getName(), ExtendedInformation.CUSTOMDATA + ExtendedInformation.CUSTOM_REVOCATIONREASON)) {
                assertEquals(Integer.toString(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD), item.getValue());
                foundrevreason = true;
            }
            if (StringUtils.equals(item.getName(), ExtendedInformation.SUBJECTDIRATTRIBUTES)) {
                assertEquals("DATEOFBIRTH=19761123", item.getValue());
                founddirattrs = true;
            }
        }
        assertTrue(foundrevreason);
        assertTrue(founddirattrs);

        // Edit the user
        final String sDN = getDN(userName);
        userdata.setSubjectDN(sDN);
        ejbcaraws.editUser(userdata);
        List<UserDataVOWS> userdatas2 = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas2 != null);
        assertTrue(userdatas2.size() == 1);
        UserDataVOWS userdata2 = userdatas2.get(0);
        assertTrue(userdata2.getSubjectDN().equals(sDN));

        userei = userdata.getExtendedInformation();
        assertNotNull(userei);
        // The extended information can contain other stuff as well
        foundrevreason = false;
        founddirattrs = false;
        for (ExtendedInformationWS item : userei) {
            if (StringUtils.equals(item.getName(), ExtendedInformation.CUSTOMDATA + ExtendedInformation.CUSTOM_REVOCATIONREASON)) {
                assertEquals(Integer.toString(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD), item.getValue());
                foundrevreason = true;
            }
            if (StringUtils.equals(item.getName(), ExtendedInformation.SUBJECTDIRATTRIBUTES)) {
                assertEquals("DATEOFBIRTH=19761123", item.getValue());
                founddirattrs = true;
            }
        }
        assertTrue(foundrevreason);
        assertTrue(founddirattrs);

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

    protected void editUser() throws CADoesntExistsException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException, AuthorizationDeniedException, ApprovalException_Exception,
            AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception, IllegalQueryException_Exception,
            CertificateProfileExistsException, EndEntityProfileNotFoundException_Exception {
        createTestCA(CA1);
        createTestCA(CA2);
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
            profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
            profile.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, true);
            profile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            if ( this.certificateProfileSession.getCertificateProfileId(WS_CERTPROF_EI)==0 ) {
                final CertificateProfile certProfile = new CertificateProfile(CertificateConstants.CERTTYPE_ENDENTITY);
                this.certificateProfileSession.addCertificateProfile(intAdmin, WS_CERTPROF_EI, certProfile);
            }
            final int cpid = CommonEjbcaWS.this.certificateProfileSession.getCertificateProfileId(WS_CERTPROF_EI);
            profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cpid));
            if (this.endEntityProfileSession.getEndEntityProfile(WS_EEPROF_EI) == null) {
                this.endEntityProfileSession.addEndEntityProfile(intAdmin, WS_EEPROF_EI, profile);
            }
        } catch (EndEntityProfileExistsException pee) {
            log.error("Error creating end entity profile: ", pee);
            fail("Can not create end entity profile");
        }
        editUser(CA1_WSTESTUSER1, CA1);
        editUser(CA1_WSTESTUSER2, CA1);
        editUser(CA2_WSTESTUSER1, CA2);
    }

    protected void findUser() throws Exception {

        {// Nonexisting users should return null
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue("noneExsisting");
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertTrue(userdatas != null);
            assertTrue(userdatas.size() == 0);
        }
        {// Find an exising user
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(CA1_WSTESTUSER1);

            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertTrue(userdatas != null);
            assertEquals(1, userdatas.size());
        }
        {// Find by O
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_ORGANIZATION);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_BEGINSWITH);
            usermatch.setMatchvalue("2Te");
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertTrue(userdatas != null);
            assertEquals(1, userdatas.size());
            assertTrue(userdatas.get(0).getSubjectDN().equals(getDN(CA1_WSTESTUSER2)));
        }
        {// Find by subjectDN pattern
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_DN);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_CONTAINS);
            usermatch.setMatchvalue(CA1_WSTESTUSER1);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull(userdatas);
            assertEquals(1, userdatas.size());
            assertEquals(getDN(CA1_WSTESTUSER1), userdatas.get(0).getSubjectDN());
        }{
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_ENDENTITYPROFILE);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(WS_EEPROF_EI);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull(userdatas);
            assertEquals("not right number of users from end entity profile match.", 3, userdatas.size());
        }{
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_CERTIFICATEPROFILE);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(WS_CERTPROF_EI);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertNotNull(userdatas);
            assertEquals("not right number of users from certificate profile match.", 3, userdatas.size());
        }{
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_CA);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(CA1);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertTrue(userdatas != null);
            assertEquals("not right number of users from CA match.", 2, userdatas.size());
        }{
            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_TOKEN);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            final List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
            assertTrue(userdatas != null);
            assertTrue(userdatas.size() > 0);
        }
    }

    protected void generatePkcs10() throws Exception {

        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword(PASSWORD);
        user1.setClearPwd(true);
        user1.setSubjectDN(getDN(CA1_WSTESTUSER1));
        user1.setCaName(CA1);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName(WS_EEPROF_EI);
        user1.setCertificateProfileName(WS_CERTPROF_EI);
        ejbcaraws.editUser(user1);

        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

        PKCS10CertificationRequest pkcs10 = getP10Request();
        // Submit the request
        CertificateResponse certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);
        assertNotNull(certenv);
        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());
        assertNotNull(cert);
        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
        byte[] ext = cert.getExtensionValue("1.2.3.4");
        // Certificate profile did not allow extension override
        assertNull("no extension should exist", ext);
        // Allow extension override
        CertificateProfile profile = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
        profile.setAllowExtensionOverride(true);
        certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);
        // Now our extension should be possible to get in there
        try {
            ejbcaraws.editUser(user1);
            pkcs10 = getP10Request();
            certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            assertNotNull(certenv);
            cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());
            assertNotNull(cert);
            assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
            ext = cert.getExtensionValue("1.2.3.4");
            assertNotNull("there should be an extension", ext);
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(ext));
            try {
                DEROctetString oct = (DEROctetString) (asn1InputStream.readObject());
                assertEquals("Extension did not have the correct value", "foo123", (new String(oct.getOctets())).trim());
            } finally {
                asn1InputStream.close();
            }
        } finally {
            // restore
            profile.setAllowExtensionOverride(false);
            certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);            
        }
    }

    /**
     * Perform two WS certificate requests with different response-types: Certificate and PKCS#7. If the first one fails an error code will be
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
        final CertificateResponse pkcs7Response = ejbcaraws.certificateRequest(userdata, requestdata, requesttype, null,
                CertificateHelper.RESPONSETYPE_PKCS7);
        // Verify that the response is of the right type
        assertTrue(pkcs7Response.getResponseType().equals(CertificateHelper.RESPONSETYPE_PKCS7));
        // Verify that the PKCS#7 response contains a certificate
        CMSSignedData cmsSignedData = new CMSSignedData(CertificateHelper.getPKCS7(pkcs7Response.getData()));
        assertNotNull(cmsSignedData);
        Store certStore = cmsSignedData.getCertificates();
        assertTrue(certStore.getMatches(null).size() == 1);
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
        assertNotNull(userdatas);
        assertEquals(1, userdatas.size());
        userdatas.get(0).setTokenType(null);
        userdatas.get(0).setPassword(null);
        userdatas.get(0).setClearPwd(true);
        return userdatas.get(0);
    }

    /**
     * Generate a new key pair and return a B64 encoded PKCS#10 encoded certificate request for the keypair.
     */
    private String getP10() throws Exception {
        return new String(Base64.encode(getP10Request().getEncoded()));

    }
    private PKCS10CertificationRequest getP10Request() throws Exception {
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        // Make a PKCS10 request with extensions
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        // Add a custom extension (dummy)
        ASN1EncodableVector attr = new ASN1EncodableVector();
        attr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), false, new DEROctetString("foo123".getBytes()));
        Extensions exts = extgen.generate();
        attr.add(new DERSet(exts));
        attributes.add(new DERSequence(attr));
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                keys.getPublic(), new DERSet(attributes), keys.getPrivate(), null);
        return pkcs10;
    }

    /**
     * Test method for creating/editing a user a requesting a certificate in a single transaction.
     */
    protected void certificateRequest() throws Exception {

        final UserDataVOWS userData1 = getUserData(CA1_WSTESTUSER1);
        ErrorCode errorCode = certreqInternal(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10);
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

        userData1.setStatus(UserDataVOWS.STATUS_NEW);
        userData1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        userData1.setEndEntityProfileName(WS_EEPROF_EI);
        userData1.setCertificateProfileName(WS_CERTPROF_EI);
        ejbcaraws.editUser(userData1);
        CertificateResponse certificateResponse = ejbcaraws.certificateRequest(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
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
            certificateResponse = ejbcaraws.certificateRequest(userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            cert = certificateResponse.getCertificate();
            assertNotNull(cert);
            assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
            ext = cert.getExtensionValue("1.2.3.4");
            assertNotNull("there should be an extension", ext);
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(ext));
            try {
                DEROctetString oct = (DEROctetString) (asn1InputStream.readObject());
                assertEquals("Extension did not have the correct value", "foo123", (new String(oct.getOctets())).trim());
            } finally {
                asn1InputStream.close();
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
                certificateResponse = ejbcaraws.certificateRequest(userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                // Verify that the response is of the right type
                assertNotNull(certificateResponse);
                assertTrue(certificateResponse.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
                // Verify that the certificate in the response has the same Subject DN
                // as in the request.
                cert = certificateResponse.getCertificate();
                assertNotNull(cert);
                assertEquals("JurisdictionCountry=DE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,CN=EVTLSEJBCAWSTEST", CertTools.getSubjectDN(cert));
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
                fail("certificate request with EV TLS DN components failed with error code "+errorCode.getInternalErrorCode());
            }
        } finally {
            // Clean up immediately
            if (endEntityManagementSession.existsUser("EVTLSEJBCAWSTEST")) {
                endEntityManagementSession.deleteUser(admin, "EVTLSEJBCAWSTEST");
            }
            internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert));
        }
    }

    protected void enforcementOfUniquePublicKeys() throws Exception {

        AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        final UserDataVOWS ca1userData1 = getUserData(CA1_WSTESTUSER1);
        final UserDataVOWS ca1userData2 = getUserData(CA1_WSTESTUSER2);
        final UserDataVOWS ca2userData1 = getUserData(CA2_WSTESTUSER1);
        final String p10_1 = getP10();
        final String p10_2 = getP10();
        final CAInfo ca1Info = caSession.getCAInfo(admin, CA1);

        // make sure same keys for different users is prevented
        ca1Info.setDoEnforceUniquePublicKeys(true);
        caSession.editCA(admin, ca1Info);

        // fetching cert for new key on should be no problem
        assertNull(certreqInternal(ca1userData1, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // fetching cert for existing key for a user that does not have a
        // certificate for this key should be impossible
        final ErrorCode errorCode = certreqInternal(ca1userData2, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.cesecore.ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER.getInternalErrorCode(),
                errorCode.getInternalErrorCode());

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
        caAdminSessionRemote.editCA(admin, ca1Info);
        // fetching cert for existing key for a user that does not have a
        // certificate for this key is now permitted
        assertNull(certreqInternal(ca1userData2, p10_1, CertificateHelper.CERT_REQ_TYPE_PKCS10));
        // forbid same key for different users
        ca1Info.setDoEnforceUniquePublicKeys(true);
        caAdminSessionRemote.editCA(admin, ca1Info);
    }

    protected void enforcementOfUniqueSubjectDN() throws Exception {
        log.trace(">enforcementOfUniqueSubjectDN");
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        final UserDataVOWS ca1userData1 = getUserData(CA1_WSTESTUSER1);
        final UserDataVOWS ca1userData2 = getUserData(CA1_WSTESTUSER2);
        final UserDataVOWS ca2userData1 = getUserData(CA2_WSTESTUSER1);
        final CAInfo ca1Info = caSession.getCAInfo(admin, CA1);
        final int iRandom = SecureRandom.getInstance("SHA1PRNG").nextInt(); // to
        // make sure a new DN is used in next test
        final String subjectDN_A = "CN=EnforcementOfUniqueSubjectDN Test A " + iRandom;
        final String subjectDN_B = "CN=EnforcementOfUniqueSubjectDN Test B " + iRandom;

        // set same DN for all users
        editUser(ca1userData1, subjectDN_A);
        editUser(ca1userData2, subjectDN_A);
        editUser(ca2userData1, subjectDN_A);

        // make sure same DN for different users is prevented
        ca1Info.setDoEnforceUniqueDistinguishedName(true);
        caAdminSessionRemote.editCA(admin, ca1Info);

        // fetching first cert for a DN should be no problem
        assertNull(certreqInternal(ca1userData1, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));

        // fetching another cert for the same DN for a user that does not have a
        // certificate with this DN should fail
        final ErrorCode errorCode = certreqInternal(ca1userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10);
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.cesecore.ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER.getInternalErrorCode(),
                errorCode.getInternalErrorCode());

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
        caAdminSessionRemote.editCA(admin, ca1Info);
        // fetching cert for existing DN for a user that does not have a
        // certificate with this DN is now permitted
        assertNull(certreqInternal(ca1userData2, getP10(), CertificateHelper.CERT_REQ_TYPE_PKCS10));
        // forbid same DN for different users
        ca1Info.setDoEnforceUniqueDistinguishedName(true);
        caAdminSessionRemote.editCA(admin, ca1Info);

        // set back original DN for all users
        editUser(ca1userData1, getDN(CA1_WSTESTUSER1));
        editUser(ca1userData2, getDN(CA1_WSTESTUSER2));
        editUser(ca2userData1, getDN(CA2_WSTESTUSER1));
        log.trace("<enforcementOfUniqueSubjectDN");
    }

    protected void certificateRequestThrowAway() throws Exception {
        final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST-certificateRequestThrowAway"));
        final String username = "CA1_WSTESTUSER_ThrowAway";
        String certificateFingerprint = null;
        // Use throw away CA mode (don't store UserData, CertificateData or CertReqHistoryData)
        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, CA1);
        final boolean originalUseCertificateStorage = caInfo.isUseCertificateStorage();
        final boolean originalUseCertReqHistory = caInfo.isUseCertReqHistory();
        final boolean originalUseUserStorage = caInfo.isUseUserStorage();
        try {
            caInfo.setUseCertificateStorage(false);
            caInfo.setUseCertReqHistory(false);
            caInfo.setUseUserStorage(false);
            caSession.editCA(authenticationToken, caInfo);
            // Setup user data to make the request
            final UserDataVOWS userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(PASSWORD);
            userDataVOWS.setClearPwd(true);
            userDataVOWS.setSubjectDN("CN=" + username);
            userDataVOWS.setCaName(caInfo.getName());
            userDataVOWS.setEmail(null);
            userDataVOWS.setSubjectAltName(null);
            userDataVOWS.setStatus(UserDataVOWS.STATUS_NEW);
            userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            userDataVOWS.setEndEntityProfileName(WS_EEPROF_EI);
            userDataVOWS.setCertificateProfileName(WS_CERTPROF_EI);
            // Generate a certificate request
            final String pkcs10AsBase64 = getP10();
            // Request a certificate via the WS API
            final CertificateResponse certificateResponse;
            try {
                certificateResponse = ejbcaraws.certificateRequest(userDataVOWS, pkcs10AsBase64, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            } catch (EjbcaException_Exception e) {
                final ErrorCode errorCode = e.getFaultInfo().getErrorCode();
                log.info(errorCode.getInternalErrorCode(), e);
                fail("Throw away certificate request failed with error code " + errorCode);
                throw new Error("JUnit test should have bailed out before this happens.");
            }
            // Verify that the response is of the right type and that a certificate was issued correctly
            assertNotNull(certificateResponse);
            assertTrue(certificateResponse.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
            final X509Certificate x509Certificate = certificateResponse.getCertificate();
            assertNotNull(x509Certificate);
            assertTrue(x509Certificate.getSubjectDN().toString().equals(userDataVOWS.getSubjectDN()));
            certificateFingerprint = CertTools.getFingerprintAsString(x509Certificate);
            // Verify that no UserData was written to the database
            assertFalse("UserData was persisted dispite the CA being told not to store it.", endEntityManagementSession.existsUser(username));
            // Verify that no CertificateData was written to the database
            final java.security.cert.Certificate certificate = certificateStoreSession.findCertificateByFingerprint(certificateFingerprint);
            assertNull("CertificateData was persisted dispite the CA being told not to store it.", certificate);
            // Verify that no CertReqHistoryData was written to the database
            final List<CertReqHistory> certReqHistoryList = certReqHistorySession.retrieveCertReqHistory(username);
            assertEquals("CertReqHistoryData was persisted dispite the CA being told not to store it.", 0, certReqHistoryList.size());
        } finally {
            final CAInfo caInfoToRestore = caSession.getCAInfo(authenticationToken, CA1);
            caInfoToRestore.setUseCertificateStorage(originalUseCertificateStorage);
            caInfoToRestore.setUseCertReqHistory(originalUseCertReqHistory);
            caInfoToRestore.setUseUserStorage(originalUseUserStorage);
            caSession.editCA(authenticationToken, caInfoToRestore);
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(authenticationToken, username);
            }
            if (certificateFingerprint!=null && certificateStoreSession.findCertificateByFingerprint(certificateFingerprint)!=null) {
                internalCertStoreSession.removeCertificate(certificateFingerprint);
            }
            if (certReqHistorySession.retrieveCertReqHistory(username).size()>0) {
                certReqHistorySession.removeCertReqHistoryData(certificateFingerprint);
            }
        }
    }
    
    protected void certificateRequestDontStoreFullCert() throws Exception {
        final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST-certificateRequestDontStoreFullCert"));
        final String username = "CA1_WSTESTUSER_DontStoreFullCert";
        String certificateFingerprint = null;
        BigInteger certSerNo = null;
        // Disable storage of certificate in certificate profile
        final CertificateProfile certprof = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
        final boolean origStoreCertData = certprof.getStoreCertificateData();
        try {
            certprof.setStoreCertificateData(false);
            certificateProfileSession.changeCertificateProfile(authenticationToken, WS_CERTPROF_EI, certprof);
            // Setup user data to make the request
            final UserDataVOWS userDataVOWS = new UserDataVOWS();
            userDataVOWS.setUsername(username);
            userDataVOWS.setPassword(PASSWORD);
            userDataVOWS.setClearPwd(true);
            userDataVOWS.setSubjectDN("CN=" + username);
            userDataVOWS.setCaName(CA1);
            userDataVOWS.setEmail(null);
            userDataVOWS.setSubjectAltName(null);
            userDataVOWS.setStatus(UserDataVOWS.STATUS_NEW);
            userDataVOWS.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
            userDataVOWS.setEndEntityProfileName(WS_EEPROF_EI);
            userDataVOWS.setCertificateProfileName(WS_CERTPROF_EI);
            // Generate a certificate request
            final String pkcs10AsBase64 = getP10();
            // Request a certificate via the WS API
            final CertificateResponse certificateResponse;
            try {
                certificateResponse = ejbcaraws.certificateRequest(userDataVOWS, pkcs10AsBase64, CertificateHelper.CERT_REQ_TYPE_PKCS10, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            } catch (EjbcaException_Exception e) {
                final ErrorCode errorCode = e.getFaultInfo().getErrorCode();
                log.info(errorCode.getInternalErrorCode(), e);
                fail("Certificate request failed with error code " + errorCode);
                throw new Error("JUnit test should have bailed out before this happens.");
            }
            // Verify that the response is of the right type and that a certificate was issued correctly
            assertNotNull(certificateResponse);
            assertTrue(certificateResponse.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
            final X509Certificate x509Certificate = certificateResponse.getCertificate();
            assertNotNull(x509Certificate);
            assertTrue(x509Certificate.getSubjectDN().toString().equals(userDataVOWS.getSubjectDN()));
            certificateFingerprint = CertTools.getFingerprintAsString(x509Certificate);
            certSerNo = CertTools.getSerialNumber(x509Certificate);
            // The user, the CertificateData and the CertReqHistoryData should exist, but not the certificate itself.
            assertTrue("User wasn't created.", endEntityManagementSession.existsUser(username));
            final List<CertReqHistory> certReqHistoryList = certReqHistorySession.retrieveCertReqHistory(username);
            assertEquals("CertReqHistoryData should be created unless explicitly disabled.", 0, certReqHistoryList.size());
            final List<CertificateDataWrapper> certDataList = certificateStoreSession.getCertificateDataBySerno(certSerNo);
            assertEquals("No CertificateData entry was created.", 1, certDataList.size());
            final CertificateDataWrapper certData = certDataList.get(0);
            assertTrue("Wrong Subject DN in CertificateData", x509Certificate.getSubjectDN().toString().equals(userDataVOWS.getSubjectDN()));
            // Certificate itself should not exist
            assertNull("No certificate should exist.", certData.getCertificate());
            final java.security.cert.Certificate certificate = certificateStoreSession.findCertificateByFingerprint(certificateFingerprint);
            assertNull("No certificate should exist.", certificate);
            
            // Now try to revoke the certificate (to "on hold" status so we can test revocation again in the next step)
            ejbcaraws.revokeCert(CertTools.getIssuerDN(x509Certificate), CertTools.getSerialNumberAsString(x509Certificate), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            
            // Try to revoke the user
            ejbcaraws.revokeUser(username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, false);
        } finally {
            final CertificateProfile certprofToRestore = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
            certprofToRestore.setStoreCertificateData(origStoreCertData);
            certificateProfileSession.changeCertificateProfile(authenticationToken, WS_CERTPROF_EI, certprofToRestore);
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(authenticationToken, username);
            }
            if (certificateFingerprint!=null && certificateStoreSession.findCertificateByFingerprint(certificateFingerprint)!=null) {
                internalCertStoreSession.removeCertificate(certificateFingerprint);
            }
            if (certReqHistorySession.retrieveCertReqHistory(username).size()>0) {
                certReqHistorySession.removeCertReqHistoryData(certificateFingerprint);
            }
        }
    }

    protected void generateCrmf(boolean useProofOfPossession, boolean usePublicKeyMac, boolean useAuthInfoSender) throws Exception {
        final String EXTENSION_OID = "1.2.3.4";
        final String EXTENSION_CONTENT = "foo1234";
        // Edit our favorite test user
        final UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword(PASSWORD);
        user1.setClearPwd(true);
        user1.setSubjectDN(getDN(CA1_WSTESTUSER1));
        user1.setCaName(CA1);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName(WS_EEPROF_EI);
        user1.setCertificateProfileName(WS_CERTPROF_EI);
        ejbcaraws.editUser(user1);
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        final CAInfo caInfo = caSession.getCAInfo(admin, CA1);
        // Test happy path CRMF request without expectation of a returned extensions
        KeyPair keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        CertReqMsg req = createCrmfRequest(caInfo.getSubjectDN(), getDN(CA1_WSTESTUSER1), keyPair.getPublic(), keyPair.getPrivate(), EXTENSION_OID, EXTENSION_CONTENT, useProofOfPossession, usePublicKeyMac?PASSWORD:null, useAuthInfoSender);
        String reqstr = new String(Base64.encode(new CertReqMessages(req).getEncoded()));
        log.debug("CertReqMessages:\n"+reqstr);
        CertificateResponse certificateResponse = ejbcaraws.crmfRequest(CA1_WSTESTUSER1, PASSWORD, reqstr, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        assertNotNull("No certificate response from CRMF request.", certificateResponse);
        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certificateResponse.getData());
        assertNotNull("No certificate in response from CRMF request.", cert);
        log.info(cert.getSubjectDN().toString());
        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
        // Certificate profile did not allow extension override
        assertNull("No extension should exist in response certificate.", cert.getExtensionValue(EXTENSION_OID));
        // Allow extension override
        final CertificateProfile profile = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
        profile.setAllowExtensionOverride(true);
        certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);
        // Now our extension should be possible to get in there
        try {
            ejbcaraws.editUser(user1);
            keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            req = createCrmfRequest(caInfo.getSubjectDN(), getDN(CA1_WSTESTUSER1), keyPair.getPublic(), keyPair.getPrivate(), EXTENSION_OID, EXTENSION_CONTENT, useProofOfPossession, usePublicKeyMac?PASSWORD:null, useAuthInfoSender);
            reqstr = new String(Base64.encode(new CertReqMessages(req).getEncoded()));
            certificateResponse = ejbcaraws.crmfRequest(CA1_WSTESTUSER1, PASSWORD, reqstr, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
            assertNotNull("No certificate response from CRMF request.", certificateResponse);
            cert = (X509Certificate) CertificateHelper.getCertificate(certificateResponse.getData());
            assertNotNull("No certificate in response from CRMF request.", cert);
            assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
            final byte[] extensionValue = cert.getExtensionValue(EXTENSION_OID);
            assertNotNull("There should be an extension in the response certificate.", extensionValue);
            final DEROctetString extensionOctets = (DEROctetString)DEROctetString.fromByteArray(extensionValue);
            assertEquals("Extension did not have the correct value", EXTENSION_CONTENT, (new String(extensionOctets.getOctets())).trim());
        } finally {
            // restore
            profile.setAllowExtensionOverride(false);
            certificateProfileSession.changeCertificateProfile(admin, WS_CERTPROF_EI, profile);            
        }
        // Check that a bad proof of possession signature will lead to a failure
        if (useProofOfPossession) {
            ejbcaraws.editUser(user1);
            keyPair = KeyTools.genKeys("512", "RSA");
            final KeyPair anotherKeyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            req = createCrmfRequest(caInfo.getSubjectDN(), getDN(CA1_WSTESTUSER1), keyPair.getPublic(), anotherKeyPair.getPrivate(), EXTENSION_OID, EXTENSION_CONTENT, useProofOfPossession, usePublicKeyMac?PASSWORD:null, useAuthInfoSender);
            reqstr = new String(Base64.encode(new CertReqMessages(req).getEncoded()));
            log.debug("CertReqMessages:\n"+reqstr);
            try {
                ejbcaraws.crmfRequest(CA1_WSTESTUSER1, PASSWORD, reqstr, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                fail("CRMF request with bad PKMAC should fail with ErrorCode.BAD_REQUEST_SIGNATURE.");
            } catch (EjbcaException_Exception e) {
                assertEquals("Unexpected error.", org.cesecore.ErrorCode.BAD_REQUEST_SIGNATURE.getInternalErrorCode(), e.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
        }
        // Try when the PKMAC is created with the wrong enrollment code
        if (useProofOfPossession && usePublicKeyMac) {
            ejbcaraws.editUser(user1);
            keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            req = createCrmfRequest(caInfo.getSubjectDN(), getDN(CA1_WSTESTUSER1), keyPair.getPublic(), keyPair.getPrivate(), EXTENSION_OID, EXTENSION_CONTENT, true, "bar456", false);
            reqstr = new String(Base64.encode(new CertReqMessages(req).getEncoded()));
            log.debug("CertReqMessages:\n"+reqstr);
            try {
                ejbcaraws.crmfRequest(CA1_WSTESTUSER1, PASSWORD, reqstr, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
                fail("CRMF request with bad PKMAC should fail with ErrorCode.BAD_REQUEST_SIGNATURE.");
            } catch (EjbcaException_Exception e) {
                assertEquals("Unexpected error.", org.cesecore.ErrorCode.BAD_REQUEST_SIGNATURE.getInternalErrorCode(), e.getFaultInfo().getErrorCode().getInternalErrorCode());
            }
        }
    }

    private CertReqMsg createCrmfRequest(final String issuerDN, final String userDN, final PublicKey publicKey, final PrivateKey privateKey, final String extensionOid,
            final String extensionContent, final boolean useProofOfPossession, final String publicKeyMacPassword, final boolean useAuthInfoSender) throws
            IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CRMFException, OperatorCreationException {
        final CertificateRequestMessageBuilder crmb = new CertificateRequestMessageBuilder(BigInteger.valueOf(4L)); // ReqId = 4
        crmb.setIssuer(new X500Name(issuerDN));
        if (!useAuthInfoSender && publicKeyMacPassword==null) {
            crmb.setSubject(new X500Name(userDN));
        }
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        crmb.setPublicKey(subjectPublicKeyInfo);
        crmb.addExtension(new ASN1ObjectIdentifier(extensionOid), false, new DEROctetString(extensionContent.getBytes()));
        if (useProofOfPossession) {
            /*
             * RFC 4211: The certificate subject places its name in the Certificate
             * Template structure along with the public key.  In this case the
             * poposkInput field is omitted from the POPOSigningKey structure.
             * The signature field is computed over the DER-encoded certificate
             * template structure.
             */
            ContentSigner contentSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
            crmb.setProofOfPossessionSigningKeySigner(contentSigner);
            if (publicKeyMacPassword!=null) {
                /*
                 * RFC4211 4.1:
                 *  1. The certificate subject has not yet established an authenticated
                 *  identity with a CA/RA, but has a password and identity string
                 *  from the CA/RA.  In this case, the POPOSigningKeyInput structure
                 *  would be filled out using the publicKeyMAC choice for authInfo,
                 *  and the password and identity would be used to compute the
                 *  publicKeyMAC value.
                */
                final PKMACValuesCalculator pkmacValuesCalculator = new JcePKMACValuesCalculator().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                final PKMACBuilder pkmacBuilder = new PKMACBuilder(pkmacValuesCalculator);
                log.info("Creating PKMAC with password " + publicKeyMacPassword);
                crmb.setAuthInfoPKMAC(pkmacBuilder, publicKeyMacPassword.toCharArray());
            } else if (useAuthInfoSender) {
                /*
                 * 2. The CA/RA has established an authenticated identity for the
                 * certificate subject, but the requestor is not placing it into the
                 * certificate request.  In this case, the POPOSigningKeyInput
                 * structure would be filled out using the sender choice for
                 * authInfo.  The public key for the certificate being requested
                 * would be placed in both the POPOSigningKeyInput and the
                 * Certificate Template structures.  The signature field is computed
                 * over the DER-encoded POPOSigningKeyInput structure.
                 */
                crmb.setAuthInfoSender(new X500Name(userDN));
            } else {
                /*
                 * 3. The certificate subject places its name in the Certificate
                 * Template structure along with the public key.  In this case the
                 * poposkInput field is omitted from the POPOSigningKey structure.
                 * The signature field is computed over the DER-encoded certificate
                 * template structure.
                 */
                // NOOP
            }
        } else {
            crmb.setProofOfPossessionRaVerified();
        }
        final CertificateRequestMessage certificateRequestMessage = crmb.build();
        // Convert to expected format
        final CertReqMsg certReqMsg = CertReqMsg.getInstance(certificateRequestMessage.getEncoded());
        // Sanity check the created request
        if (useProofOfPossession && publicKeyMacPassword!=null) {
            final POPOSigningKey popoSigningKey = POPOSigningKey.getInstance(certReqMsg.getPopo().getObject());
            assertNotNull("PublicKeyMAC was null in request!", popoSigningKey.getPoposkInput().getPublicKeyMAC());
            assertNull("Subject should not be set.", certReqMsg.getCertReq().getCertTemplate().getSubject());
        }
        return certReqMsg;
    }
    
    protected void generateSpkac() throws Exception {

        // Edit our favorite test user
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword(PASSWORD);
        user1.setClearPwd(true);
        user1.setSubjectDN(getDN(CA1_WSTESTUSER1));
        user1.setCaName(CA1);
        user1.setStatus(UserDataVOWS.STATUS_NEW);
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        user1.setEndEntityProfileName("EMPTY");
        user1.setCertificateProfileName("ENDUSER");
        ejbcaraws.editUser(user1);

        CertificateResponse certenv = ejbcaraws.spkacRequest(CA1_WSTESTUSER1, PASSWORD, SPCAK, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);

        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);

        assertEquals(getDN(CA1_WSTESTUSER1), cert.getSubjectDN().toString());
    }

    protected void generatePkcs12() throws Exception {
        log.trace(">generatePkcs12");
        boolean exceptionThrown = false;
        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, PASSWORD, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        assertNotNull(userdatas);
        assertEquals(1, userdatas.size());
        userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        userdatas.get(0).setSubjectDN(getDN(CA1_WSTESTUSER1));
        ejbcaraws.editUser(userdatas.get(0));

        exceptionThrown = false;
        try {
            ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, PASSWORD, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        Enumeration<String> en = ks.aliases();
        String alias = en.nextElement();
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
        log.trace("<generatePkcs12");
    }

    protected void findCerts() throws Exception {

        // First find all certs
        final P12TestUser p12TestUser = new P12TestUser();
        final java.security.cert.Certificate gencert = p12TestUser.getCertificate(null);

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

        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);

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
            assertTrue(false);
        }catch(AlreadyRevokedException_Exception e){}

    }

    protected void revokeCertBackdated() throws Exception {

        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate(null);

        final String issuerdn = cert.getIssuerDN().toString();
        final String serno = cert.getSerialNumber().toString(16);
        final String sDate = "2012-06-07T23:55:59+02:00";

        final CertificateProfile certProfile = this.certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
        certProfile.setAllowBackdatedRevocation(false);
        this.certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, certProfile);
        try {
            this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, sDate);
            assertTrue(false);
        } catch (RevokeBackDateNotAllowedForProfileException_Exception e) {
            // do nothing
        }
        certProfile.setAllowBackdatedRevocation(true);
        this.certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, certProfile);
        this.ejbcaraws.revokeCertBackdated(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, sDate);
        final RevokeStatus revokestatus = this.ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        final Date realRevokeDate  = revokestatus.getRevocationDate().toGregorianCalendar().getTime();
        final Date expectedRevokeDate;
        try {
            expectedRevokeDate = DatatypeConverter.parseDateTime(sDate).getTime();
        } catch (IllegalArgumentException e) {
            assertTrue("Not a valid ISO8601 date revocation date", false);
            return;
        }
        assertEquals("Revocation date not the expected.", expectedRevokeDate, realRevokeDate);
    }

    protected void revokeToken() throws Exception {

        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert1 = p12TestUser.getCertificate("12345678");
        final X509Certificate cert2 = p12TestUser.getCertificate("12345678");

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

    private class P12TestUser {
        final private List<UserDataVOWS> userdatas;
        public P12TestUser() throws Exception {
            UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
            usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(CA1_WSTESTUSER1);
            this.userdatas = CommonEjbcaWS.this.ejbcaraws.findUser(usermatch);
            assertTrue(this.userdatas != null);
            assertTrue(this.userdatas.size() == 1);
            this.userdatas.get(0).setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
            this.userdatas.get(0).setEndEntityProfileName(WS_EEPROF_EI);
            this.userdatas.get(0).setCertificateProfileName(WS_CERTPROF_EI);
        }
        public X509Certificate getCertificate(String hardTokenSN) throws Exception {
            this.userdatas.get(0).setStatus(UserDataVOWS.STATUS_NEW);
            this.userdatas.get(0).setPassword(PASSWORD);
            this.userdatas.get(0).setClearPwd(true);
            CommonEjbcaWS.this.ejbcaraws.editUser(userdatas.get(0));
            final KeyStore ksenv;
            try {
                ksenv = CommonEjbcaWS.this.ejbcaraws.pkcs12Req(CA1_WSTESTUSER1, PASSWORD, hardTokenSN, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
            } catch (EjbcaException_Exception e) {
                assertTrue(e.getMessage(), false);
                return null;
            }
            java.security.KeyStore ks = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);

            assertNotNull(ks);
            final Enumeration<String> en = ks.aliases();
            final String alias = en.nextElement();
            final X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
            assertEquals("Returned certificates SubjectDN '" + CertTools.getSubjectDN(cert) + "' is not requested '" + getDN(CA1_WSTESTUSER1) + "'", CertTools.getSubjectDN(cert), getDN(CA1_WSTESTUSER1));
            return cert;
        }
    }

    protected void checkRevokeStatus() throws Exception {

        // Create a new user and certificate
        final P12TestUser p12TestUser = new P12TestUser();
        final X509Certificate cert = p12TestUser.getCertificate("12345678");
        String issuerdn = cert.getIssuerDN().toString();
        String serno = cert.getSerialNumber().toString(16);
        // Newly issues, certificate is not revoked
        RevokeStatus revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.NOT_REVOKED);
        // Revoke the certificate
        ejbcaraws.revokeCert(issuerdn, serno, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
        // Revocation status should match the revocation
        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, serno);
        assertNotNull(revokestatus);
        assertTrue(revokestatus.getReason() == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
        assertTrue(revokestatus.getCertificateSN().equals(serno));
        assertTrue(revokestatus.getIssuerDN().equals(issuerdn));
        assertNotNull(revokestatus.getRevocationDate());
        // A non existing certificate should return null
        revokestatus = ejbcaraws.checkRevokationStatus(issuerdn, BigInteger.valueOf(123456L).toString(16));
        assertNull(revokestatus);
    }

    protected void utf8EditUser() throws Exception {

        // Test to add a user.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername(CA1_WSTESTUSER1);
        user1.setPassword(PASSWORD);
        user1.setClearPwd(true);
        user1.setSubjectDN("CN=WSÅÄÖÜåäöüè");
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
        assertTrue(userdata.getSubjectDN().equals("CN=WSÅÄÖÜåäöüè"));
        // Compare with unicode encoded chars as well to ensure file encoding was not messed up
        assertTrue(userdata.getSubjectDN().equals("CN=WS\u00C5\u00C4\u00D6\u00DC\u00E5\u00E4\u00F6\u00FC\u00E8"));

    }

    protected void revokeUser() throws Exception {

        // Revoke and delete
        ejbcaraws.revokeUser(CA1_WSTESTUSER1, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, true);

        UserMatch usermatch = new UserMatch();
        usermatch.setMatchwith(UserMatch.MATCH_WITH_USERNAME);
        usermatch.setMatchtype(UserMatch.MATCH_TYPE_EQUALS);
        usermatch.setMatchvalue(CA1_WSTESTUSER1);
        List<UserDataVOWS> userdatas = ejbcaraws.findUser(usermatch);
        assertTrue(userdatas != null);
        assertTrue(userdatas.size() == 0);

    }

    protected void genTokenCertificates(boolean onlyOnce) throws Exception {

        GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean originalProfileSetting = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(false);
        globalConfigurationSession.saveConfiguration(intAdmin, gc);
        try {
            if (certificateProfileSession.getCertificateProfileId(WSTESTPROFILE) != 0) {
                certificateProfileSession.removeCertificateProfile(intAdmin, WSTESTPROFILE);
            }
            {
                final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                profile.setAllowValidityOverride(true);
                certificateProfileSession.addCertificateProfile(intAdmin, WSTESTPROFILE, profile);
            }
            // first a simple test
            UserDataVOWS tokenUser1 = new UserDataVOWS();
            tokenUser1.setUsername("WSTESTTOKENUSER1");
            tokenUser1.setPassword(PASSWORD);
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
            PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                    basickeys.getPublic(), new DERSet(), basickeys.getPrivate(), null);

            ArrayList<TokenCertificateRequestWS> requests = new ArrayList<TokenCertificateRequestWS>();
            TokenCertificateRequestWS tokenCertReqWS = new TokenCertificateRequestWS();
            tokenCertReqWS.setCAName(getAdminCAName());
            tokenCertReqWS.setCertificateProfileName(WSTESTPROFILE);
            tokenCertReqWS.setValidityIdDays("1");
            tokenCertReqWS.setPkcs10Data(basicpkcs10.getEncoded());
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
            java.security.KeyStore realKeyStore = KeyStoreHelper.getKeyStore(keyStore.getKeystoreData(), HardTokenConstants.TOKENTYPE_PKCS12, PASSWORD);
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

        } finally {
            certificateProfileSession.removeCertificateProfile(intAdmin, WSTESTPROFILE);
            gc.setEnableEndEntityProfileLimitations(originalProfileSetting);
            globalConfigurationSession.saveConfiguration(intAdmin, gc);
        }

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
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_INFO, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null,
                "Message 1 generated from WS test Script");
        ejbcaraws.customLog(IEjbcaWS.CUSTOMLOG_LEVEL_ERROR, "Test", getAdminCAName(), "WSTESTTOKENUSER1", null,
                "Message 1 generated from WS test Script");
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
        userdatas.get(0).setPassword(PASSWORD);
        userdatas.get(0).setClearPwd(true);
        ejbcaraws.editUser(userdatas.get(0));

        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                keys.getPublic(), new DERSet(), keys.getPrivate(), null);

        CertificateResponse certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                CertificateHelper.RESPONSETYPE_CERTIFICATE);

        assertNotNull(certenv);
        assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
        X509Certificate cert = (X509Certificate) CertificateHelper.getCertificate(certenv.getData());

        assertNotNull(cert);
        assertTrue(cert.getSubjectDN().toString().equals(getDN(CA1_WSTESTUSER1)));

        ejbcaraws.editUser(userdatas.get(0));
        certenv = ejbcaraws.pkcs10Request(CA1_WSTESTUSER1, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                CertificateHelper.RESPONSETYPE_PKCS7);
        assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_PKCS7));
        CMSSignedData cmsSignedData = new CMSSignedData(CertificateHelper.getPKCS7(certenv.getData()));
        assertTrue(cmsSignedData != null);

        Store certStore = cmsSignedData.getCertificates();
        assertTrue(certStore.getMatches(null).size() == 1);

    }

    protected void getEndEntityProfileFromID() throws Exception {

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
            try {
                ejbcaraws.getProfile(profileid, "ccp");
            } catch(UnknownProfileTypeException_Exception e) {
                String expectedmsg = "Unknown profile type 'ccp'. Recognized types are 'eep' for End Entity Profiles and 'cp' for Certificate Profiles";
                assertEquals(expectedmsg, e.getMessage());
            }
        
            try {
                ejbcaraws.getProfile(profileid, "cp");
            } catch(EjbcaException_Exception e) {
                String expectedmsg = "Could not find certificate profile with ID '" + profileid + "' in the database.";
                assertEquals(expectedmsg, e.getMessage());
            }
        
            byte[] profilebytes = ejbcaraws.getProfile(profileid, "eep");
            java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(profilebytes));
            final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
            decoder.close();
        
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

    } // test52GetProfileFromID
    
    protected void getCertificateProfileFromID() throws Exception {

        String profilename = "TESTPROFILEFORGETPROFILECOMMAND";
        
        if(endEntityProfileSession.getEndEntityProfile(profilename) != null) {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, profilename);
        }
        if(certificateProfileSession.getCertificateProfile(profilename) != null) {
            certificateProfileSession.removeCertificateProfile(intAdmin, profilename);
        }
        CertificateProfile profile = new CertificateProfile();
        profile.setAllowValidityOverride(true);
        profile.setAllowExtensionOverride(true);
        certificateProfileSession.addCertificateProfile(intAdmin, profilename, profile);
        int profileid = certificateProfileSession.getCertificateProfileId(profilename);

        try {
        
        try {
            ejbcaraws.getProfile(profileid, "eep");
        } catch(EjbcaException_Exception e) {
            String expectedmsg = "Could not find end entity profile with ID '" + profileid + "' in the database.";
            assertEquals(expectedmsg, e.getMessage());
        }
        
        byte[] profilebytes = ejbcaraws.getProfile(profileid, "cp");
        java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(profilebytes));
        final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
        decoder.close();
        
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

    } // test52GetProfileFromID

    protected void getAvailableCAsInProfile() throws Exception {

        int id = endEntityProfileSession.getEndEntityProfileId("KEYRECOVERY");
        log.info("id: " + id);
        // First try to get something that does not exist, it should return array with size 0, not throw an exception
        List<NameAndId> cas = ejbcaraws.getAvailableCAsInProfile(000222);
        assertEquals(0, cas.size());
        // Now find the real one instead
        cas = ejbcaraws.getAvailableCAsInProfile(id);
        assertNotNull(cas);
        // This profile only has ALLCAS available, so this list will be empty
        assertTrue(cas.size() == 0);

        // TODO: make a test that actually returns something

    } // test24GetAvailableCAsInProfile
    
    protected void getAvailableCertificateProfiles() throws Exception {

        int id = endEntityProfileSession.getEndEntityProfileId("KEYRECOVERY");
        // First try to get something that does not exist, it should return array with size 0, not throw an exception
        List<NameAndId> profs = ejbcaraws.getAvailableCertificateProfiles(000222);
        assertEquals(0, profs.size());
        // Now find the real one instead
        profs = ejbcaraws.getAvailableCertificateProfiles(id);

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

    protected void createAndGetCRL() throws Exception {
        final String caname = getAdminCAName();
        final CAInfo caInfo = caSession.getCAInfo(intAdmin, caname);
        final long originalDeltaCRLPeriod = caInfo.getDeltaCRLPeriod();
        try {
            // Disable delta CRLs
            caInfo.setDeltaCRLPeriod(0);
            caSession.editCA(intAdmin, caInfo);
            // Create a new full CRL, to have well defined starting order
            ejbcaraws.createCRL(caname);
            // This will throw exception if it fails
            int crlNumberBefore = getLatestCRLNumber(caname, false);
            log.info("crlNumberBefore: " + crlNumberBefore);
            // Generate a new full CRL
            ejbcaraws.createCRL(caname);
            // After generation the CRL number should have increased by one
            final int fullCrlNumberAfter1 = getLatestCRLNumber(caname, false);
            log.info("fullCrlNumberAfter1: " + fullCrlNumberAfter1);
            assertEquals("CRL number of newly generated CRL should be exactly one more than for the previous CRL.", crlNumberBefore+1, fullCrlNumberAfter1);
            // Enable delta CRLs
            caInfo.setDeltaCRLPeriod(30L);
            caSession.editCA(intAdmin, caInfo);
            // Generate a new full CRL and a delta CRL
            ejbcaraws.createCRL(caname);
            // Verify that the generated CRLs have the expected numbering
            final int fullCrlNumberAfter2 = getLatestCRLNumber(caname, false);
            final int deltaCrlNumberAfter2 = getLatestCRLNumber(caname, true);
            log.info("fullCrlNumberAfter2: " + fullCrlNumberAfter2 + " deltaCrlNumberAfter2: " + deltaCrlNumberAfter2);
            assertEquals("CRL number of newly generated CRL should be exactly one more than for the previous CRL.", fullCrlNumberAfter1+1, fullCrlNumberAfter2);
            assertEquals("CRL number of newly generated delta CRL should be exactly two more than for the the full CRL.", fullCrlNumberAfter2+1, deltaCrlNumberAfter2);
        } finally {
            final CAInfo caInfoToRestore = caSession.getCAInfo(intAdmin, caname);
            caInfoToRestore.setDeltaCRLPeriod(originalDeltaCRLPeriod);
            caSession.editCA(intAdmin, caInfoToRestore);
        }
    }

    private int getLatestCRLNumber(final String caName, final boolean delta) throws CADoesntExistsException_Exception, EjbcaException_Exception, CRLException {
        final byte[] crlBytes = ejbcaraws.getLatestCRL(caName, delta);
        final X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
        final BigInteger crlNumber = CrlExtensions.getCrlNumber(crl);
        log.info("getLatestCRLNumber for " + caName + " delta="+delta + " crlNumber=" + crlNumber.intValue());
        return crlNumber.intValue();
    }

    protected void ejbcaVersion() throws Exception {
        final String version = ejbcaraws.getEjbcaVersion();
        // We don't know which specific version we are testing
        final String expectedSubString = "EJBCA 6.7";
        assertTrue("Wrong version: "+version + " (expected to contain " + expectedSubString + ")", version.contains(expectedSubString)); 
    }

    protected void getLastCertChain() throws Exception {
        log.trace(">getLastCertChain");
        List<Certificate> foundcerts = ejbcaraws.getLastCertChain(CA1_WSTESTUSER1);
        assertTrue(foundcerts != null);
        assertTrue(foundcerts.size() > 1);
        log.debug("foundcerts.size: " + foundcerts.size());
        java.security.cert.Certificate cacert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(
                foundcerts.size() - 1).getCertificateData());
        assertTrue("(What we expected to be) the CA certificate was not self signed.", CertTools.isSelfSigned(cacert));
        java.security.cert.Certificate cert = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(0)
                .getCertificateData());
        log.debug("CA cert's SubjectDN: " + CertTools.getSubjectDN(cacert));
        log.debug("Cert's IssuerDN: " + CertTools.getIssuerDN(cert));
        log.debug("Cert's SubjectDN: " + CertTools.getSubjectDN(cert));
        assertEquals(getDN(CA1_WSTESTUSER1) + " is not " + CertTools.getSubjectDN(cert), getDN(CA1_WSTESTUSER1), CertTools.getSubjectDN(cert));
        for (int i = 1; i < foundcerts.size(); i++) {
            java.security.cert.Certificate cert2 = (java.security.cert.Certificate) CertificateHelper.getCertificate(foundcerts.get(i)
                    .getCertificateData());
            cert.verify(cert2.getPublicKey()); // will throw if verification
            // fails
            cert = cert2;
        }
        // Test if the last available CA chain matches the one we got for this user
        final List<Certificate> caChain = ejbcaraws.getLastCAChain(CA1);
        assertEquals("CA chain was not of expected length", 1, caChain.size());
        final String userChainCaFingerprint = CertTools.getFingerprintAsString(cacert);
        final String caChainCaFingerprint = CertTools.getFingerprintAsString(CertificateHelper.getCertificate(caChain.get(caChain.size() - 1)
                .getCertificateData()));
        assertEquals("Same CA certificate in user certificate chain and CA certificate chain", caChainCaFingerprint, userChainCaFingerprint);
        // Test that and empty chain is returned for non-existing users
        String randomuser = genRandomUserName();
        List<Certificate> foundnocerts = ejbcaraws.getLastCertChain(randomuser);
        assertTrue(foundnocerts != null);
        assertTrue(foundnocerts.size() == 0);
        log.trace("<getLastCertChain");
    }
    
    protected void getExpiredCerts() throws Exception {
        String testUsername = "testUserForExpirationTime";
        String testCaName = "testCaForExpirationTime";
        
        if(endEntityManagementSession.existsUser(testUsername)) {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, testUsername, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
        }
        if(caSession.existsCa(testCaName)) {
            caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, testCaName).getCAId());
        }
        
        java.security.cert.Certificate cert1 = null;
        java.security.cert.Certificate cert2 = null;
        try {
            
            // ------------------------------------------------------------------------------- //
            // Create the end entity and certificate profiles that allow extension ovveride    //
            // ------------------------------------------------------------------------------- //
            CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(WS_CERTPROF_EI);
            if ( certProfile == null ) {
                certProfile = new CertificateProfile(CertificateConstants.CERTTYPE_ENDENTITY);
                certProfile.setAllowValidityOverride(true);
                certificateProfileSession.addCertificateProfile(intAdmin, WS_CERTPROF_EI, certProfile);
            } else {
                certProfile.setAllowValidityOverride(true);
                certificateProfileSession.changeCertificateProfile(intAdmin, WS_CERTPROF_EI, certProfile);
            }
            int cpid = certificateProfileSession.getCertificateProfileId(WS_CERTPROF_EI);
            EndEntityProfile eeprofile = endEntityProfileSession.getEndEntityProfile(WS_EEPROF_EI);
            if(eeprofile == null) {
                eeprofile = new EndEntityProfile(true);
                eeprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cpid));
                this.endEntityProfileSession.addEndEntityProfile(intAdmin, WS_EEPROF_EI, eeprofile);
            } else {
                eeprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cpid));
                this.endEntityProfileSession.changeEndEntityProfile(intAdmin, WS_EEPROF_EI, eeprofile);
            }
            
            // ------------------------------------------------------------------------------------ //
            // Test ejbcaraws.getCertificatesByExpirationTime() by creating an end entity           //
            // and issue it a certificate by ManagementCA.                                          //
            // Expected results: return of all certificates that will expire within the specified   //
            // number of days, including the certificate we just issued                             //
            // ------------------------------------------------------------------------------------ //
            KeyPair key = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            CAInfo cainfo = caSession.getCAInfo(intAdmin, getAdminCAName());
            assertNotNull("No CA with name " + getAdminCAName() + " was found.", cainfo);
             
            // Create/update an end entity and issue its certificate
            EndEntityInformation adminUser = endEntityAccessSession.findUser(intAdmin, testUsername);
            if(adminUser == null) {
                adminUser = new EndEntityInformation();
                adminUser.setUsername(testUsername);
                adminUser.setPassword("foo123");
                adminUser.setDN("CN="+testUsername);
                adminUser.setCAId(cainfo.getCAId());
                adminUser.setEmail(null);
                adminUser.setSubjectAltName(null);
                adminUser.setStatus(UserDataVOWS.STATUS_NEW);
                adminUser.setTokenType(SecConst.TOKEN_SOFT_JKS);
                adminUser.setEndEntityProfileId(endEntityProfileSession.getEndEntityProfileId(WS_EEPROF_EI));
                adminUser.setCertificateProfileId(cpid);
                adminUser.setType(new EndEntityType(EndEntityTypes.ENDUSER, EndEntityTypes.ADMINISTRATOR));
                log.info("Adding new user: "+adminUser.getUsername());
                endEntityManagementSession.addUser(intAdmin, adminUser, true);
            } else {
                adminUser.setStatus(UserDataVOWS.STATUS_NEW);
                adminUser.setPassword("foo123");
                log.info("Changing user: "+adminUser.getUsername());
                endEntityManagementSession.changeUser(intAdmin, adminUser, true);
            }
            Date certNotAfterDate = new Date((new Date()).getTime() + (12 * 60 * 60 * 1000)); // cert will expire in 12 hours from now
            signSession.createCertificate(intAdmin, testUsername, "foo123",   new PublicKeyWrapper(key.getPublic()), KeyUsage.cRLSign, new Date(), certNotAfterDate);
            
            List<java.security.cert.Certificate> genCerts = certificateStoreSession.findCertificatesBySubject("CN="+testUsername);
            assertEquals("More than one certificate with subjectDN 'CN=" + testUsername + "' was found. Maybe test clean up should be fixed.", 1, genCerts.size());
            cert1 = genCerts.get(0);
            assertEquals(CertificateStatus.OK, certificateStoreSession.getStatus(CertTools.getIssuerDN(cert1), CertTools.getSerialNumber(cert1)));
            
            Date testDate = new Date((new Date()).getTime() + (24 * 60 * 60 * 1000)); // 1 day from now
            assertTrue(CertTools.getNotAfter(cert1).before(testDate));
            
            List<Certificate> certs = ejbcaraws.getCertificatesByExpirationTime(1, 1000); // get certs that will expire in 1 day
            log.debug("Found " + certs.size() + " certificates that will expire within one day");
            assertTrue(certs.size() > 0);
            boolean certfound = false;
            Iterator<Certificate> itr = certs.iterator();
            while(itr.hasNext()) {
            	Certificate expirewscert = (Certificate) itr.next();
                java.security.cert.Certificate expirecert = 
                                (java.security.cert.Certificate) CertificateHelper.getCertificate(expirewscert.getCertificateData());
                if(StringUtils.equalsIgnoreCase(CertTools.getSubjectDN(cert1), CertTools.getSubjectDN(expirecert))) {
                    certfound = true;
                    break;
                }
            }
            assertTrue(certfound);
            
            
            // ---------------------------------------------------------------------------------------- //
            // Test ejbcaraws.getCertificatesByExpirationTimeAndIssuer() by modifying the               //
            // end entity above to issue it another certificate by another CA (testCaForExpirationTime) //
            // 1. Return all certs that will expire within the specific number of days and are issued   //
            //    by testCaForExpirationTime. Verify that the certificate issued by ManagementCA above  //
            //    is not among the returned certificates                                                //
            // 2. Return all certs that will expire within the specific number of days and are issued   //
            //    by ManagementCA. Verify that the certificate issued by testCaForExpirationTime        //
            //    is not among the returned certificates                                                //
            // ---------------------------------------------------------------------------------------- //
            CaTestCase.createTestCA(testCaName);
            assertTrue("Failed to create test CA: " + testCaName, caSession.existsCa(testCaName));
            cainfo = caSession.getCAInfo(intAdmin, testCaName);
            adminUser.setCAId(cainfo.getCAId());
            adminUser.setStatus(UserDataVOWS.STATUS_NEW);
            adminUser.setPassword("foo123");
            log.info("Changing user: "+adminUser.getUsername());
            endEntityManagementSession.changeUser(intAdmin, adminUser, true);
            signSession.createCertificate(intAdmin, testUsername, "foo123",   new PublicKeyWrapper(key.getPublic()), KeyUsage.cRLSign, new Date(), certNotAfterDate);
            
            genCerts = certificateStoreSession.findCertificatesBySubject("CN="+testUsername);
            assertEquals("Failed to issue another certificate for user " + testUsername, 2, genCerts.size());
            cert2 = genCerts.get(0);
            if(!CertTools.getIssuerDN(cert2).equalsIgnoreCase(cainfo.getSubjectDN())) {
                cert2 = genCerts.get(1);
            }
            assertEquals(CertificateStatus.OK, certificateStoreSession.getStatus(CertTools.getIssuerDN(cert2), CertTools.getSerialNumber(cert2)));
            assertTrue(CertTools.getNotAfter(cert2).before(testDate));
            
            // get certs that will expire in 1 day and were issued by testCaForExpirationTime
            certs = ejbcaraws.getCertificatesByExpirationTimeAndIssuer(1, cainfo.getSubjectDN(), 1000); 
            log.debug("Found " + certs.size() + " certificates that will expire within one day and are issued by " + cainfo.getSubjectDN());
            assertTrue(certs.size() > 0);
            boolean foundcert1 = false;
            boolean foundcert2 = false;
            for(Certificate expirewscert : certs) {
                java.security.cert.Certificate expirecert = (java.security.cert.Certificate) CertificateHelper.getCertificate(expirewscert.getCertificateData());
                if(StringUtils.equalsIgnoreCase(CertTools.getSubjectDN(cert1), CertTools.getSubjectDN(expirecert)) && StringUtils.equalsIgnoreCase(CertTools.getIssuerDN(cert1), CertTools.getIssuerDN(expirecert))) {
                    foundcert1 = true;
                }
                if(StringUtils.equalsIgnoreCase(CertTools.getSubjectDN(cert2), CertTools.getSubjectDN(expirecert)) && StringUtils.equalsIgnoreCase(CertTools.getIssuerDN(cert2), CertTools.getIssuerDN(expirecert))) {
                    foundcert2 = true;
                }
            }
            assertFalse(foundcert1);
            assertTrue(foundcert2);
            
            // get certs that will expire in 1 day and were issued by ManagementCA
            certs = ejbcaraws.getCertificatesByExpirationTimeAndIssuer(1, caSession.getCAInfo(intAdmin, getAdminCAName()).getSubjectDN(), 1000); // get certs that will expire in 1 day
            log.debug("Found " + certs.size() + " certificates that will expire within one day and are issued by " + cainfo.getSubjectDN());
            assertTrue(certs.size() > 0);
            foundcert1 = false;
            foundcert2 = false;
            for(Certificate expirewscert : certs) {
                java.security.cert.Certificate expirecert = (java.security.cert.Certificate) CertificateHelper.getCertificate(expirewscert.getCertificateData());
                if(StringUtils.equalsIgnoreCase(CertTools.getSubjectDN(cert1), CertTools.getSubjectDN(expirecert)) && StringUtils.equalsIgnoreCase(CertTools.getIssuerDN(cert1), CertTools.getIssuerDN(expirecert))) {
                    foundcert1 = true;
                }
                if(StringUtils.equalsIgnoreCase(CertTools.getSubjectDN(cert2), CertTools.getSubjectDN(expirecert)) && StringUtils.equalsIgnoreCase(CertTools.getIssuerDN(cert2), CertTools.getIssuerDN(expirecert))) {
                    foundcert2 = true;
                }
            }
            assertTrue(foundcert1);
            assertFalse(foundcert2);
            
        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(intAdmin, testUsername, RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN);
            } catch (NotFoundException e) { /* The test probably failed before creating the end entity */ }
            
            if(cert1 != null) {
                internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert1));
            }
            if(cert2 != null) {
                internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(cert2));
            }
            try {
                caSession.removeCA(intAdmin, caSession.getCAInfo(intAdmin, testCaName).getCAId());
            } catch (CADoesntExistsException e) {
                log.debug("Clean up failed: " + e.getMessage());
            }
            endEntityProfileSession.removeEndEntityProfile(intAdmin, WS_EEPROF_EI);
            certificateProfileSession.removeCertificateProfile(intAdmin, WS_CERTPROF_EI);
        }
    }

    protected void isAuthorized(boolean authorized) throws Exception {
        // This is a superadmin keystore, improve in the future
        if (authorized) {
            assertTrue(ejbcaraws.isAuthorized(StandardRules.ROLE_ROOT.resource()));
        } else {
            assertFalse(ejbcaraws.isAuthorized(StandardRules.ROLE_ROOT.resource()));            
        }
    }

    protected void errorOnEditUser() throws Exception {

        // Test to add a user.
        UserDataVOWS user1 = new UserDataVOWS();
        user1.setUsername("WSTESTUSER29");
        user1.setPassword(PASSWORD);
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
        assertEquals(errorCode.getInternalErrorCode(), org.cesecore.ErrorCode.CA_NOT_EXISTS.getInternalErrorCode());

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
        assertEquals(errorCode.getInternalErrorCode(), org.cesecore.ErrorCode.EE_PROFILE_NOT_EXISTS.getInternalErrorCode());

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
        assertEquals(errorCode.getInternalErrorCode(), org.cesecore.ErrorCode.CERT_PROFILE_NOT_EXISTS.getInternalErrorCode());

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
        assertEquals(errorCode.getInternalErrorCode(), org.cesecore.ErrorCode.UNKOWN_TOKEN_TYPE.getInternalErrorCode());
    }

    protected void errorOnGeneratePkcs10() throws Exception {
        log.trace(">errorOnGeneratePkcs10");
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
        ErrorCode errorCode = null;
        // ///// Check Error.LOGIN_ERROR ///////
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CertTools.stringToBcX500Name("CN=WSTESTUSER30"),
                keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        try {
            ejbcaraws.pkcs10Request("WSTESTUSER30", PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.cesecore.ErrorCode.LOGIN_ERROR.getInternalErrorCode(), errorCode.getInternalErrorCode());
        errorCode = null;
        // ///// Check Error.USER_WRONG_STATUS ///////
        user1.setStatus(EndEntityConstants.STATUS_REVOKED);
        ejbcaraws.editUser(user1);
        pkcs10 = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CertTools.stringToBcX500Name("CN=WSTESTUSER30"),
                keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        try {
            ejbcaraws.pkcs10Request("WSTESTUSER30", "foo1234", new String(Base64.encode(pkcs10.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            errorCode = e.getFaultInfo().getErrorCode();
        }
        assertNotNull("error code should not be null", errorCode);
        assertEquals(org.cesecore.ErrorCode.USER_WRONG_STATUS.getInternalErrorCode(), errorCode.getInternalErrorCode());
        // PKCS#10 signed by a different key than the public key in the request (Proof Of Possession fail)
        user1.setStatus(EndEntityConstants.STATUS_NEW);
        ejbcaraws.editUser(user1);
        final KeyPair anotherKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        pkcs10 = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CertTools.stringToBcX500Name("CN=WSTESTUSER30"),
                keys.getPublic(), new DERSet(), anotherKeyPair.getPrivate(), null);
        log.info("About to request wrongly signed PKCS#10...");
        try {
            ejbcaraws.pkcs10Request("WSTESTUSER30", "foo1234", new String(Base64.encode(pkcs10.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
            fail("PKCS#10 signed with wrong key should fail Proof Of Possession check.");
        } catch (EjbcaException_Exception e) {
            log.info(e.getMessage(), e);
            errorCode = e.getFaultInfo().getErrorCode();
            assertEquals(org.cesecore.ErrorCode.BAD_REQUEST_SIGNATURE.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        log.trace("<errorOnGeneratePkcs10");
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
            assertEquals(org.cesecore.ErrorCode.BAD_USER_TOKEN_TYPE.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        assertNotNull(errorCode);
        errorCode = null;
        // restore correct token type
        user1.setTokenType(UserDataVOWS.TOKEN_TYPE_P12);
        ejbcaraws.editUser(user1);

        // Should failed because of the bad password
        try {
            ejbcaraws.pkcs12Req("WSTESTUSER31", PASSWORD, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception ex) {
            errorCode = ex.getFaultInfo().getErrorCode();
            assertEquals(org.cesecore.ErrorCode.LOGIN_ERROR.getInternalErrorCode(), errorCode.getInternalErrorCode());
        }
        assertNotNull(errorCode);
        errorCode = null;

        // insert wrong status
        user1.setStatus(EndEntityConstants.STATUS_REVOKED);
        ejbcaraws.editUser(user1);

        // Should failed because certificate already exists.
        try {
            ejbcaraws.pkcs12Req("WSTESTUSER31", "foo1234", null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (EjbcaException_Exception ex) {
            errorCode = ex.getFaultInfo().getErrorCode();
            assertEquals(org.cesecore.ErrorCode.USER_WRONG_STATUS.getInternalErrorCode(), errorCode.getInternalErrorCode());
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
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        try {
            assertEquals(-4, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            final CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(DummyCustomPublisher.class.getName());
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherSession.addPublisher(admin, PUBLISHER_NAME, publisher);
            assertEquals(0, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            final int publisherID = publisherSession.getPublisherId(PUBLISHER_NAME);
            publisherQueueSession.addQueueData(publisherID, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
            assertEquals(1, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            publisherQueueSession.addQueueData(publisherID, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
            assertEquals(2, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            publisherQueueSession.removeQueueData(((PublisherQueueData) publisherQueueSession.getPendingEntriesForPublisher(publisherID).iterator()
                    .next()).getPk());
            assertEquals(1, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
            publisherQueueSession.removeQueueData(((PublisherQueueData) publisherQueueSession.getPendingEntriesForPublisher(publisherID).iterator()
                    .next()).getPk());
            assertEquals(0, ejbcaraws.getPublisherQueueLength(PUBLISHER_NAME));
        } catch (EjbcaException_Exception e) {
            assertTrue(e.getMessage(), false);
        } finally {
            publisherSession.removePublisher(admin, PUBLISHER_NAME);
        }
    }

    protected void caMakeRequestAndFindCA(String caname, CardVerifiableCertificate cvcacert) throws Exception {
        /*
         * Test making a certificate request from a DVCA without giving the certificate chain to the CVCA. If the CVCA is imported in the database as an external CA the CVCA
         * certificate should be found automatically (by CAAdminSessionBean.makeRequest).
         */
        byte[] request = ejbcaraws.caRenewCertRequest(caname, new ArrayList<byte[]>(), false, false, false, null);
        // make the mandatory junit checks...
        assertNotNull(request);
        CVCRequestMessage cvcreq = RequestMessageUtils.genCVCRequestMessage(request);
        assertNotNull(cvcreq);
        CAInfo dvinfo = caSession.getCAInfo(intAdmin, caname);
        assertEquals(dvinfo.getSubjectDN(), cvcreq.getRequestDN());
        CVCObject obj = CertificateParser.parseCVCObject(request);
        // System.out.println(obj.getAsText());
        // We should have created an authenticated request signed by the old certificate
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) obj;
        CVCertificate cert = authreq.getRequest();
        // The request should be targeted for the CVCA, i.e. ca_ref in request should be the same as the CVCAs ref
        String cvcaref = cvcacert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated();
        String caref = cert.getCertificateBody().getAuthorityReference().getConcatenated();
        // In this first case however, we did not have any CVCA certificate, so the CA_ref will then simply be the DV's own ref
        assertEquals(caref, caref);

        // Now we have to import the CVCA certificate as an external CA, and do it again, then it should find the CVCA certificate
        Collection<java.security.cert.Certificate> cvcacerts = new ArrayList<java.security.cert.Certificate>();
        cvcacerts.add(cvcacert);
        caAdminSessionRemote.importCACertificate(intAdmin, "WSTESTCVCAIMPORTED", EJBTools.wrapCertCollection(cvcacerts));
        request = ejbcaraws.caRenewCertRequest(caname, new ArrayList<byte[]>(), false, false, false, null);
        assertNotNull(request);
        obj = CertificateParser.parseCVCObject(request);
        authreq = (CVCAuthenticatedRequest) obj;
        cert = authreq.getRequest();
        // The request should be targeted for the CVCA, i.e. ca_ref in request should be the same as the CVCAs ref
        caref = cert.getCertificateBody().getAuthorityReference().getConcatenated();
        assertEquals(cvcaref, caref);
    } // caMakeRequestAndFindCA

    protected static void cleanUpAdmins(final String wsadminRoleName) throws Exception {
        AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
        EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        
            // Remove from role
        RoleData role = roleAccessSession.findRole(wsadminRoleName);
        if (role != null) {
            roleManagementSession.remove(intAdmin, role);
            accessControlSession.forceCacheExpire();
        }
        if (endEntityManagementSession.existsUser(TEST_ADMIN_USERNAME)) {
            // Remove user
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_ADMIN_USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }
        // Remove role
        if (endEntityManagementSession.existsUser(TEST_ADMIN_USERNAME)) {
            // Remove user
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_ADMIN_USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }
        if (endEntityManagementSession.existsUser(TEST_NONADMIN_USERNAME)) {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_NONADMIN_USERNAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }
        if (new File(TEST_ADMIN_FILE).exists()) {
            new File(TEST_ADMIN_FILE).delete();
        }
        if (new File(TEST_NONADMIN_FILE).exists()) {
            new File(TEST_NONADMIN_FILE).delete();
        }

        // Remove test user's ignore errors, because it probably is because the user does not exist.
        // possibly because some of the tests failed.
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER1, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER2, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, CA2_WSTESTUSER1, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, CA1_WSTESTUSER1CVCRSA, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, CA2_WSTESTUSER1CVCEC, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, "WSTESTUSERKEYREC1", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, "WSTESTUSER30", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, "WSTESTUSER31", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        // Remove Key recovery end entity profile
        try {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, "KEYRECOVERY");
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            removeTestCA(CA1);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            removeTestCA(CA2);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, WS_EEPROF_EI);
        } catch (Exception e) {
            // NOPMD: ignore
        }
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        certificateProfileSession.removeCertificateProfile(intAdmin, WS_CERTPROF_EI);
    } // cleanUpAdmins

}
