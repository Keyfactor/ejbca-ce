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

package org.ejbca.core.protocol.xkms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBElement;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.xkms.client.XKMSInvoker;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.Before;
import org.junit.Test;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.AuthenticationType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.NotBoundAuthenticationType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrototypeKeyBindingType;
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;
import org.w3._2002._03.xkms_.UseKeyWithType;

/**
 * To Run this test, there must be a CA with DN
 * "CN=AdminCA1,O=EJBCA Sample,C=SE", and it must have XKMS service enabled.
 * Also you have to enable XKMS in conf/xkms.properties.
 * 
 * @author Philip Vendil 2006 sep 27
 * 
 * @version $Id$
 */

public class XKMSKRSSTest {

    private final static Logger log = Logger.getLogger(XKMSKRSSTest.class);

    private final static String HTTPPORT = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class).getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP, "8080");

    private final static XKMSInvoker xKMSInvoker = new XKMSInvoker("http://localhost:" + HTTPPORT + "/ejbca/xkms/xkms", null);

    private final static ObjectFactory xKMSObjectFactory = new ObjectFactory();
    private final static org.w3._2000._09.xmldsig_.ObjectFactory sigFactory = new org.w3._2000._09.xmldsig_.ObjectFactory();

    private final static String baseUsername;

    private final static AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private final static String username1;
    private final static String username2;
    private final static String username3;

    private final static String issuerdn = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private final static int caid = issuerdn.hashCode();

    private final static String dn1;
    private final static String dn2;
    private final static String dn3;

    private final static KeyPair keys1;
    private final static KeyPair keys3;

    private static Certificate cert1;
    private static Certificate cert2;

    private final static String certprofilename1;
    private final static String certprofilename2;
    private final static String endentityprofilename;

    private GlobalConfiguration orgGlobalConfig;
	private static CAInfo orgCaInfo;

    private final static DocumentBuilderFactory dbf;
    private final static Random ran;

    private ApprovalExecutionSessionRemote approvalExecutionSession = InterfaceCache.getApprovalExecutionSession();
    private ApprovalSessionRemote approvalSession = InterfaceCache.getApprovalSession();
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityAccessSessionRemote endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private KeyRecoverySessionRemote keyRecoverySession = InterfaceCache.getKeyRecoverySession();
    private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    static {
        org.apache.xml.security.Init.init();
        try {
            CryptoProviderTools.installBCProviderIfNotAvailable();
            ran = new Random();
            baseUsername = "xkmstestuser" + (ran.nextInt() % 1000) + "-";

            certprofilename1 = "XKMSTESTSIGN" + baseUsername;
            certprofilename2 = "XKMSTESTEXCHANDENC" + baseUsername;
            endentityprofilename = "XKMSTESTPROFILE" + baseUsername;

            

            username1 = baseUsername + '1';
            dn1 = "C=SE, O=AnaTom, CN=" + username1;
            username2 = baseUsername + '2';
            dn2 = "C=SE, O=AnaTom, CN=" + username2;
            username3 = baseUsername + '3';
            dn3 = "C=SE, O=AnaTom, CN=" + username3;

            keys1 = genKeys();
            keys3 = genKeys();
            org.apache.xml.security.Init.init();

            // JAXBContext jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");
            // Marshaller marshaller = XKMSUtil.getNamespacePrefixMappedMarshaller(jAXBContext);
            dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // Unmarshaller unmarshaller = jAXBContext.createUnmarshaller();

        } catch (Exception e) {
            log.error("Error initializing RequestAbstractTypeResponseGenerator", e);
            throw new Error(e);
        }
    }

    @Before
    public void setUp() throws CADoesntExistsException, AuthorizationDeniedException {
        orgGlobalConfig = globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        orgCaInfo = caSession.getCAInfo(administrator, "AdminCA1");
    }
    
	@Test
    public void test00SetupDatabase() throws Exception {

        final CAInfo caInfo = caSession.getCAInfo(administrator, "AdminCA1");
        // make sure same keys for different users is prevented
        caInfo.setDoEnforceUniquePublicKeys(true);
        // make sure same DN for different users is prevented
        caInfo.setDoEnforceUniqueDistinguishedName(true);
        caAdminSession.editCA(administrator, caInfo);

        final GlobalConfiguration newGlobalConfig = globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        newGlobalConfig.setEnableKeyRecovery(true);
        globalConfigurationSession.saveGlobalConfigurationRemote(administrator, newGlobalConfig);

        // Setup with two new Certificate profiles.
        CertificateProfile profile1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile1.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, false);
        profile1.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        profile1.setKeyUsage(CertificateConstants.NONREPUDIATION, true);

        CertificateProfile profile2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile2.setKeyUsage(CertificateConstants.DATAENCIPHERMENT, true);

        certificateProfileSession.addCertificateProfile(administrator, certprofilename1, profile1);
        certificateProfileSession.addCertificateProfile(administrator, certprofilename2, profile2);

        final int profile1Id = certificateProfileSession.getCertificateProfileId(certprofilename1);
        final int profile2Id = certificateProfileSession.getCertificateProfileId(certprofilename2);

        final EndEntityProfile endentityprofile = new EndEntityProfile(true);

        endentityprofile.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);
        endentityprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + profile1Id + ";" + profile2Id);

        endentityprofile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);

        endEntityProfileSession.addEndEntityProfile(administrator, endentityprofilename, endentityprofile);
        final int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(administrator, endentityprofilename);

        final String pwd = "foo123";
        final int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
        addUser(username1, dn1);

        final int type = SecConst.USER_ENDUSER | SecConst.USER_KEYRECOVERABLE;
        final int token = SecConst.TOKEN_SOFT_P12;

        {
            final String subjectaltname2 = "RFC822NAME=" + username2 + "@foo.se,UNIFORMRESOURCEIDENTIFIER=http://www.test.com/" + username2
                    + ",IPADDRESS=10.0.0.1,DNSNAME=" + username2 + ".test.com";
            final String email2 = username2 + "@foo.se";
            if (endEntityAccessSession.findUser(administrator, username2) != null) {
                log.info("User already exists in the database.");
            } else {
                userAdminSession.addUser(administrator, username2, pwd, CertTools.stringToBCDNString(dn2), subjectaltname2, email2, false,
                        endEntityProfileId, profile1Id, type, token, hardtokenissuerid, caid);
            }
            userAdminSession.setClearTextPassword(administrator, username2, pwd);
        }

        {
            String subjectaltname3 = "RFC822NAME=" + username3 + "@foo.se";
            String email3 = username3 + "@foo.se";
            if (endEntityAccessSession.findUser(administrator, username3) != null) {
                log.info("User already exists in the database.");
            } else {
                userAdminSession.addUser(administrator, username3, pwd, CertTools.stringToBCDNString(dn3), subjectaltname3, email3, false,
                        endEntityProfileId, profile2Id, type, token, hardtokenissuerid, caid);
            }
            userAdminSession.setClearTextPassword(administrator, username3, pwd);
        }

    }

    private void addUser(String userName, String dn) throws Exception {
        final String pwd = "foo123";
        final int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
        {
            final int type = SecConst.USER_ENDUSER;
            final int token = SecConst.TOKEN_SOFT_BROWSERGEN;
            final int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            final String subjectaltname1 = "RFC822NAME=" + userName + "@foo.se";
            final String email1 = userName + "@foo.se";
            if (endEntityAccessSession.findUser(administrator, userName) != null) {
                log.info("User already exists in the database.");
            } else {
                userAdminSession.addUser(administrator, userName, pwd, CertTools.stringToBCDNString(dn), subjectaltname1, email1, false,
                        endEntityProfileSession.getEndEntityProfileId(administrator, endentityprofilename), certificatetypeid, type, token,
                        hardtokenissuerid, caid);
            }
            userAdminSession.setClearTextPassword(administrator, userName, pwd);
        }

    }

	@Test
    public void test01SimpleRegistration() throws Exception {
        cert1 = simpleRegistration(dn1, false);
    }

    private Certificate simpleRegistration(String dn, boolean willFail) throws Exception {

        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("600");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys1.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys1.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeIdentifier", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first, "ISO8859-1"), false, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2)
                .getEncoded();
        prototypeKeyBindingType.setRevocationCodeIdentifier(second);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys1.getPrivate(), prototypeKeyBindingType
                .getId());
        if (willFail) {
            assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_RECIEVER));
            assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_FAILURE));
            return null;
        }
        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

        assertTrue(registerResultType.getKeyBinding().size() == 1);
        KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
        assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);

        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
        assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
        Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
        while (iter2.hasNext()) {
            JAXBElement next = (JAXBElement) iter2.next();
            assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
            byte[] encoded = (byte[]) next.getValue();
            Certificate nextCert = CertTools.getCertfromByteArray(encoded);

            assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn))
                    || CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(issuerdn)));
            if (CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn))) {
                assertTrue(Arrays.equals(keys1.getPublic().getEncoded(), nextCert.getPublicKey().getEncoded()));
                return nextCert;
            }
        }
        return null;
    }

	@Test
    public void test02ServerGenRegistration() throws Exception {
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("601");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn2);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);

        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId1234", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first, "ISO8859-1"), false, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2)
                .getEncoded();
        prototypeKeyBindingType.setRevocationCodeIdentifier(second);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", null, prototypeKeyBindingType.getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

        assertTrue(registerResultType.getKeyBinding().size() == 1);
        KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
        assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);

        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
        assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
        Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();

        while (iter2.hasNext()) {
            JAXBElement next = (JAXBElement) iter2.next();
            assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
            byte[] encoded = (byte[]) next.getValue();
            Certificate nextCert = CertTools.getCertfromByteArray(encoded);

            assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn2)));
            if (CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn2))) {
                cert2 = nextCert;

            }
        }

        assertTrue(registerResultType.getPrivateKey() != null);
        PrivateKey privateKey = XKMSUtil.getPrivateKeyFromEncryptedXML(registerResultType.getPrivateKey(), "foo123");

        X509Certificate testCert = CertTools.genSelfCert("CN=sdf", 12, null, privateKey, cert2.getPublicKey(), "SHA1WithRSA", false);
        testCert.verify(cert2.getPublicKey());

    }

	@Test
    public void test03RegisterWithWrongDN() throws Exception {
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("602");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier("CN=wrong");

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys3.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys3.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys3.getPrivate(), prototypeKeyBindingType
                .getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

    }

	@Test
    public void test04RegisterWithWrongStatus() throws Exception {
        KeyPair keys = genKeys();
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("603");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn1);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", keys.getPrivate(), prototypeKeyBindingType
                .getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));

    }

	@Test
    public void test05RegisterWithWrongPassword() throws Exception {
        KeyPair keys = genKeys();
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("604");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo124", keys.getPrivate(), prototypeKeyBindingType
                .getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));

    }

	@Test
    public void test06RegisterWithNoPOP() throws Exception {
        KeyPair keys = genKeys();
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("605");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", null, prototypeKeyBindingType.getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(registerResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_POPREQUIRED));

    }

	@Test
    public void test07RegisterWithBasicAuthentication() throws Exception {
        KeyPair keys = genKeys();
        RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
        registerRequestType.setId("606");

        UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
        useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
        useKeyWithType.setIdentifier(dn3);

        registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        RSAKeyValueType rsaKeyValueType = sigFactory.createRSAKeyValueType();
        rsaKeyValueType.setExponent(((RSAPublicKey) keys.getPublic()).getPublicExponent().toByteArray());
        rsaKeyValueType.setModulus(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
        JAXBElement<RSAKeyValueType> rsaKeyValue = sigFactory.createRSAKeyValue(rsaKeyValueType);
        keyInfoType.getContent().add(rsaKeyValue);
        PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
        prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
        prototypeKeyBindingType.setKeyInfo(keyInfoType);
        prototypeKeyBindingType.setId("100231");
        registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("foo123".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        registerRequestType.setAuthentication(authenticationType);

        RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, null, keys.getPrivate(), prototypeKeyBindingType.getId());

        assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));

        assertTrue(registerResultType.getKeyBinding().size() == 1);
        KeyBindingType keyBindingType = registerResultType.getKeyBinding().get(0);
        assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);

    }

	@Test
    public void test08SimpleReissue() throws Exception {
        simpleReissue(username1, dn1);
        simpleReissue(username1, dn1); // could be repeated any number of times
    }

    public void simpleReissue(String userName, String dn) throws Exception {
        userAdminSession.setUserStatus(administrator, userName, 10);
        userAdminSession.setClearTextPassword(administrator, userName, "ReissuePassword");
        ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
        reissueRequestType.setId("607");

        reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);

        ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());

        assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(reissueResultType.getResultMinor() == null);

        assertTrue(reissueResultType.getKeyBinding().size() == 1);
        keyBindingType = reissueResultType.getKeyBinding().get(0);
        assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);

        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
        assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
        Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
        while (iter2.hasNext()) {
            JAXBElement next = (JAXBElement) iter2.next();
            assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
            byte[] encoded = (byte[]) next.getValue();
            Certificate nextCert = CertTools.getCertfromByteArray(encoded);

            assertTrue(CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(dn))
                    || CertTools.stringToBCDNString(CertTools.getSubjectDN(nextCert)).equals(CertTools.stringToBCDNString(issuerdn)));
            if (CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn))) {
                assertTrue(Arrays.equals(keys1.getPublic().getEncoded(), nextCert.getPublicKey().getEncoded()));
                assertFalse(CertTools.getSerialNumber(cert1).equals(CertTools.getSerialNumber(nextCert)));
            }
        }
    }

	@Test
    public void test09ReissueWrongPassword() throws Exception {
        userAdminSession.setUserStatus(administrator, username1, 10);
        userAdminSession.setClearTextPassword(administrator, username1, "ReissuePassword");
        ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
        reissueRequestType.setId("608");

        reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("Wrong".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);

        ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());

        assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));

    }

	@Test
    public void test10ReissueWrongStatus() throws Exception {
        userAdminSession.setUserStatus(administrator, username1, 40);
        userAdminSession.setClearTextPassword(administrator, username1, "ReissuePassword");
        ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
        reissueRequestType.setId("609");

        reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);

        ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());

        assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));
    }

	@Test
    public void test11ReissueWrongCert() throws Exception {

        userAdminSession.setUserStatus(administrator, username1, 10);
        userAdminSession.setClearTextPassword(administrator, username1, "ReissuePassword");
        ReissueRequestType reissueRequestType = xKMSObjectFactory.createReissueRequestType();
        reissueRequestType.setId("610");

        reissueRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(Constants.getUserCert().getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123122");
        reissueRequestType.setReissueKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("ReissuePassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        reissueRequestType.setAuthentication(authenticationType);

        ReissueResultType reissueResultType = xKMSInvoker.reissue(reissueRequestType, null, null, null, keys1.getPrivate(), keyBindingType.getId());

        assertTrue(reissueResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(reissueResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));
    }

	@Test
    public void test12SimpleRecover() throws Exception {
        userAdminSession.prepareForKeyRecovery(administrator, username2, endEntityProfileSession.getEndEntityProfileId(administrator, endentityprofilename), cert2);
        userAdminSession.setClearTextPassword(administrator, username2, "RerecoverPassword");
        RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
        recoverRequestType.setId("700");

        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);

        RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null, keyBindingType.getId());

        assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(recoverResultType.getResultMinor() == null);

        assertTrue(recoverResultType.getKeyBinding().size() == 1);
        keyBindingType = recoverResultType.getKeyBinding().get(0);
        assertTrue(keyBindingType.getStatus().getValidReason().size() == 4);

        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
        assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 2);
        Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();

        while (iter2.hasNext()) {
            JAXBElement next = (JAXBElement) iter2.next();
            assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
            byte[] encoded = (byte[]) next.getValue();
            Certificate nextCert = CertTools.getCertfromByteArray(encoded);

            if (CertTools.getSubjectDN(nextCert).equals(CertTools.stringToBCDNString(dn2))) {
                cert2 = nextCert;

            }
        }

        assertTrue(recoverResultType.getPrivateKey() != null);
        PrivateKey privateKey = XKMSUtil.getPrivateKeyFromEncryptedXML(recoverResultType.getPrivateKey(), "RerecoverPassword");

        X509Certificate testCert = CertTools.genSelfCert("CN=sdf", 12, null, privateKey, cert2.getPublicKey(), "SHA1WithRSA", false);
        testCert.verify(cert2.getPublicKey());

    }

	@Test
    public void test13RecoverWrongPassword() throws Exception {
        userAdminSession.prepareForKeyRecovery(administrator, username2, endEntityProfileSession.getEndEntityProfileId(administrator, endentityprofilename), cert2);
        userAdminSession.setClearTextPassword(administrator, username2, "RerecoverPassword");
        RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
        recoverRequestType.setId("701");

        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("Wrong".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);

        RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null, keyBindingType.getId());

        assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));

    }

	@Test
    public void test14RecoverWrongStatus() throws Exception {
        userAdminSession.setUserStatus(administrator, username2, 10);
        userAdminSession.setClearTextPassword(administrator, username2, "RerecoverPassword");
        RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
        recoverRequestType.setId("702");

        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);

        RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null, keyBindingType.getId());

        assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));

    }

	@Test
    public void test15RecoverWrongCert() throws Exception {
        userAdminSession.setUserStatus(administrator, username2, UserDataConstants.STATUS_KEYRECOVERY);
        userAdminSession.setClearTextPassword(administrator, username2, "RerecoverPassword");
        RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
        recoverRequestType.setId("703");

        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(Constants.getUserCert().getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);

        RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null, keyBindingType.getId());

        assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOMATCH));

    }

	@Test
   public void test16CertNotMarked() throws Exception {
        keyRecoverySession.unmarkUser(administrator, username2);
        userAdminSession.setUserStatus(administrator, username2, 40);
        userAdminSession.setClearTextPassword(administrator, username2, "RerecoverPassword");
        RecoverRequestType recoverRequestType = xKMSObjectFactory.createRecoverRequestType();
        recoverRequestType.setId("704");

        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CHAIN);
        recoverRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_PRIVATEKEY);

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        recoverRequestType.setRecoverKeyBinding(keyBindingType);

        AuthenticationType authenticationType = xKMSObjectFactory.createAuthenticationType();
        NotBoundAuthenticationType notBoundAuthenticationType = xKMSObjectFactory.createNotBoundAuthenticationType();
        notBoundAuthenticationType.setProtocol("NOTUSED");
        notBoundAuthenticationType.setValue("RerecoverPassword".getBytes());
        authenticationType.setNotBoundAuthentication(notBoundAuthenticationType);
        recoverRequestType.setAuthentication(authenticationType);

        RecoverResultType recoverResultType = xKMSInvoker.recover(recoverRequestType, null, null, null, keyBindingType.getId());

        assertTrue(recoverResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(recoverResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));

    }

	@Test
    public void test17SimpleRevoke() throws Exception {
        RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
        revokeRequestType.setId("800");

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert1.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeIdentifier", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);

        RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());

        assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
        assertTrue(revokeResultType.getResultMinor() == null);

    }

	@Test
    public void test18RevokeWrongPassword() throws Exception {
        RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
        revokeRequestType.setId("801");

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);

        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("Wrong", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);

        RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());

        assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_NOAUTHENTICATION));
    }

	@Test
    public void test19RevokeWithResult() throws Exception {
        RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
        revokeRequestType.setId("802");

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);

        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId1234", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);

        RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());

        assertEquals(XKMSConstants.RESULTMAJOR_SUCCESS, revokeResultType.getResultMajor());
        assertNull(revokeResultType.getResultMinor());

        assertTrue(revokeResultType.getKeyBinding().size() == 1);
        keyBindingType = revokeResultType.getKeyBinding().get(0);
//        for (String s : keyBindingType.getStatus().getValidReason()) {
//        	log.debug("ValidReason: " + s);
//        }
        // All Values: http://www.w3.org/2002/03/xkms#IssuerTrust, RevocationStatus, ValidityInterval, Signature
        // Should be: http://www.w3.org/2002/03/xkms#ValidityInterval, IssuerTrust, Signature
        assertEquals("Wrong number of ValidReason in KeyBinding: ", 3, keyBindingType.getStatus().getValidReason().size());	// TODO: Was 3 in EJBCA 3.11?? Why has this changed?
        assertEquals("Wrong number of InvalidReason in KeyBinding: ", 1, keyBindingType.getStatus().getInvalidReason().size());	// TODO: Was 1 in EJBCA 3.11?? Why has this changed?

        JAXBElement<X509DataType> jAXBX509Data = (JAXBElement<X509DataType>) keyBindingType.getKeyInfo().getContent().get(0);
        assertTrue(jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().size() == 1);
        Iterator<Object> iter2 = jAXBX509Data.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();

        while (iter2.hasNext()) {
            JAXBElement next = (JAXBElement) iter2.next();
            assertTrue(next.getName().getLocalPart().equals("X509Certificate"));
            byte[] encoded = (byte[]) next.getValue();
            Certificate nextCert = CertTools.getCertfromByteArray(encoded);

            assertEquals(CertTools.stringToBCDNString(dn2), CertTools.getSubjectDN(nextCert));

        }
    }

	@Test
    public void test20RevokeAlreadyRevoked() throws Exception {
        RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
        revokeRequestType.setId("804");

        X509DataType x509DataType = sigFactory.createX509DataType();
        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert2.getEncoded()));
        KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
        keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));

        KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
        keyBindingType.setKeyInfo(keyInfoType);
        keyBindingType.setId("100123123422");
        revokeRequestType.setRevokeKeyBinding(keyBindingType);

        revokeRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);

        byte[] first = XKMSUtil.getSecretKeyFromPassphrase("UsersRevokationCodeId1234", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
        revokeRequestType.setRevocationCode(first);

        RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());

        assertTrue(revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SENDER));
        assertTrue(revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));
    }

	@Test
    public void test21RevocationApprovals() throws Exception {
        final String APPROVINGADMINNAME = "superadmin";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        String randomPostfix = Integer.toString(ran.nextInt(999999));
        String caname = "xkmsRevocationCA" + randomPostfix;
        String username = "xkmsRevocationUser" + randomPostfix;
        int caID = -1;
        try {
            caID = RevocationApprovalTest.createApprovalCA(administrator, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession, caSession);
            X509Certificate adminCert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(APPROVINGADMINNAME).iterator()
                    .next();
            Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(adminCert);
            Set<X500Principal> principals = new HashSet<X500Principal>();
            principals.add(adminCert.getSubjectX500Principal());
            AuthenticationToken approvingAdmin = new TestX509CertificateAuthenticationToken(principals, credentials);
            // Admin approvingAdmin = new Admin(adminCert, APPROVINGADMINNAME, null);
            try {
                // Create new user
                EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                        SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
                userdata.setPassword("foo123");
                userAdminSession.addUser(administrator, userdata, true);
                // Register user
                RegisterRequestType registerRequestType = xKMSObjectFactory.createRegisterRequestType();
                registerRequestType.setId("806");
                UseKeyWithType useKeyWithType = xKMSObjectFactory.createUseKeyWithType();
                useKeyWithType.setApplication(XKMSConstants.USEKEYWITH_PKIX);
                useKeyWithType.setIdentifier("CN=" + username);
                registerRequestType.getRespondWith().add(XKMSConstants.RESPONDWITH_X509CERT);
                PrototypeKeyBindingType prototypeKeyBindingType = xKMSObjectFactory.createPrototypeKeyBindingType();
                prototypeKeyBindingType.getUseKeyWith().add(useKeyWithType);
                prototypeKeyBindingType.setId("424242");
                registerRequestType.setPrototypeKeyBinding(prototypeKeyBindingType);
                byte[] first = XKMSUtil.getSecretKeyFromPassphrase("foo123", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
                byte[] second = XKMSUtil.getSecretKeyFromPassphrase(new String(first, "ISO8859-1"), false, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS2)
                        .getEncoded();
                prototypeKeyBindingType.setRevocationCodeIdentifier(second);
                RegisterResultType registerResultType = xKMSInvoker.register(registerRequestType, null, null, "foo123", null, prototypeKeyBindingType.getId());
                assertTrue(registerResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
                // Get user's certificate
                Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
                assertTrue(userCerts.size() == 1);
                Certificate cert = userCerts.iterator().next();
                // Revoke via XKMS and verify response
                RevokeRequestType revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
                revokeRequestType.setId("808");
                X509DataType x509DataType = sigFactory.createX509DataType();
                x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
                KeyInfoType keyInfoType = sigFactory.createKeyInfoType();
                keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
                KeyBindingType keyBindingType = xKMSObjectFactory.createKeyBindingType();
                keyBindingType.setKeyInfo(keyInfoType);
                keyBindingType.setId("424242");
                revokeRequestType.setRevokeKeyBinding(keyBindingType);
                first = XKMSUtil.getSecretKeyFromPassphrase("foo123", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
                revokeRequestType.setRevocationCode(first);
                RevokeResultType revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());
                assertTrue(ERRORNOTSENTFORAPPROVAL, revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_SUCCESS));
                assertTrue(ERRORNOTSENTFORAPPROVAL, revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_INCOMPLETE));
                // Try to revoke via XKMS and verify failure
                revokeRequestType = xKMSObjectFactory.createRevokeRequestType();
                revokeRequestType.setId("810");
                x509DataType = sigFactory.createX509DataType();
                x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
                keyInfoType = sigFactory.createKeyInfoType();
                keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
                keyBindingType = xKMSObjectFactory.createKeyBindingType();
                keyBindingType.setKeyInfo(keyInfoType);
                keyBindingType.setId("424242");
                revokeRequestType.setRevokeKeyBinding(keyBindingType);
                first = XKMSUtil.getSecretKeyFromPassphrase("foo123", true, 20, XKMSUtil.KEY_REVOCATIONCODEIDENTIFIER_PASS1).getEncoded();
                revokeRequestType.setRevocationCode(first);
                revokeResultType = xKMSInvoker.revoke(revokeRequestType, null, null, null, keyBindingType.getId());
                assertTrue(ERRORNOTSENTFORAPPROVAL, revokeResultType.getResultMajor().equals(XKMSConstants.RESULTMAJOR_RECIEVER));
                assertTrue(ERRORNOTSENTFORAPPROVAL, revokeResultType.getResultMinor().equals(XKMSConstants.RESULTMINOR_REFUSED));
                // Approve revocation and verify success
                approveRevocation(administrator, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                        ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, caID);
                // Try to reactivate user
            } finally {
                userAdminSession.deleteUser(administrator, username);
            }
        } finally {
            // Nuke CA
            try {
                caAdminSession.revokeCA(administrator, caID, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } finally {
                caSession.removeCA(administrator, caID);
            }
        }
    } // test21RevocationApprovals

	@Test
    public void test22SimpleRegistrationSameKeyDifferentUsers() throws Exception {
        final String usernameX = baseUsername + 'X';
        final String dnX = "C=SE, O=AnaTom, CN=" + usernameX;
        addUser(usernameX, dnX);
        simpleRegistration(dnX, true);
        userAdminSession.deleteUser(administrator, usernameX);
    }

	@Test
   public void test23SimpleRegistrationSameSubjcectDifferentUsers() throws Exception {
        userAdminSession.deleteUser(administrator, username1);
        final String usernameX = baseUsername + 'X';
        addUser(usernameX, dn1);
        simpleRegistration(dn1, true);
        userAdminSession.deleteUser(administrator, usernameX);
    }

	@Test
    public void test99CleanDatabase() throws Exception {
    	AuthenticationToken administrator = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        userAdminSession.deleteUser(administrator, username2);
        userAdminSession.deleteUser(administrator, username3);

        endEntityProfileSession.removeEndEntityProfile(administrator, endentityprofilename);

        certificateProfileSession.removeCertificateProfile(administrator, certprofilename1);
        certificateProfileSession.removeCertificateProfile(administrator, certprofilename2);

        globalConfigurationSession.saveGlobalConfigurationRemote(administrator, orgGlobalConfig);
        caAdminSession.editCA(administrator, orgCaInfo);
    }

    private static KeyPair genKeys() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(1024);
        log.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" + ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());

        return rsaKeys;
    } // genKeys
    
    /**
     *      Find all certificates for a user and approve any outstanding revocation. 
     */
    public int approveRevocation(AuthenticationToken internalAdmin, AuthenticationToken approvingAdmin, String username, int reason, int approvalType,
                    CertificateStoreSessionRemote certificateStoreSession, ApprovalSessionRemote approvalSession, int approvalCAID) throws Exception {
        Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
        Iterator<Certificate> i = userCerts.iterator();
        int approvedRevocations = 0;
        while ( i.hasNext() ) {
            Certificate cert = i.next();
            String issuerDN = CertTools.getIssuerDN(cert);
            BigInteger serialNumber = CertTools.getSerialNumber(cert);
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
                if ( (reason != RevokedCertInfo.NOT_REVOKED && !isRevoked )
                            || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked) )  {
                            int approvalID;
                            if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN);
                            } else {
                                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null);
                            }
                            Query q = new Query(Query.TYPE_APPROVALQUERY);
                            q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                            ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId="+approvalCAID, "(endEntityProfileId="+SecConst.EMPTY_ENDENTITYPROFILE+")").get(0));
                            Approval approval = new Approval("Approved during testing.");
                            approvalExecutionSession.approve(approvingAdmin, approvalID, approval, globalConfigurationSession.getCachedGlobalConfiguration(internalAdmin));
                            approvalData = (ApprovalDataVO) approvalSession.findApprovalDataVO(internalAdmin, approvalID).iterator().next();
                            assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                    CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
                            assertEquals(status.revocationReason, reason);
                            approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
                    approvedRevocations++;
                }
        }
        return approvedRevocations;
    } // approveRevocation
}
