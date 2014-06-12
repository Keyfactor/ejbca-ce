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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This will test the different cmp authentication modules.
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthenticationModulesTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(AuthenticationModulesTest.class);

    private static final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthenticationModulesTest"));

    private static final String USERNAME = "authModuleTestUser";
    private static final String USER_DN = "CN=" + USERNAME + ",O=PrimeKey Solutions AB,C=SE,UID=foo123";
    private static final String issuerDN = "CN=TestCA";
    private byte[] nonce;
    private byte[] transid;
    private int caid;
    private Certificate cacert;
    private CA testx509ca;
    private CmpConfiguration cmpConfiguration;
    private String configAlias;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityProfileSession eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private CertificateStoreSession certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private AccessControlSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        
        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
     
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        caid = testx509ca.getCAId();
        cacert = testx509ca.getCACertificate();
        caSession.addCA(ADMIN, testx509ca);

        configAlias = "AuthenticationModuleTstConfAlias";
        
        cmpConfiguration.addAlias(configAlias);
        cmpConfiguration.setRAEEProfile(configAlias, "EMPTY");
        cmpConfiguration.setRACertProfile(configAlias, "ENDUSER");
        cmpConfiguration.setRACAName(configAlias, "TestCA");
        cmpConfiguration.setExtractUsernameComponent(configAlias, "CN");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        cmpConfiguration.removeAlias(configAlias);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(ADMIN, caid);
    }

    @Test
    public void test01HMACModule() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException,
            InvalidAlgorithmParameterException, CADoesntExistsException, AuthorizationDeniedException {

        log.trace(">test01HMACModule()");
        
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        assertFalse("caid is 0", (caid == 0));
        assertNotNull("cacert is null", cacert);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        // Using the CMP RA Authentication secret 
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule(ADMIN, "-", configAlias, cmpConfiguration, 
                                caSession.getCAInfo(ADMIN, caid), eeAccessSession);
        boolean ret = hmac.verifyOrExtract(req, null);
        assertTrue("Authentication using HMAC faied", ret);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", "foo123", hmac.getAuthenticationString());
        
        log.trace("<test01HMACModule()");
    }

    @Test
    public void test03HMACCrmfReq() throws Exception {
        
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123");
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setResponseProtection(configAlias, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(USER_DN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
    }

    @Test
    public void test04HMACRevReq() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        
        final String revUserDN = "CN=cmprevuser1,C=SE";
        final String revUsername = "cmprevuser1";
        String fingerprint = null;
        try {

            Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(revUserDN, issuerDN);
            log.debug("Found " + certs.size() + " certificates for userDN \"" + USER_DN + "\"");
            Certificate cert = null, tmp = null;
            Iterator<Certificate> itr = certs.iterator();
            while (itr.hasNext()) {
                tmp = itr.next();
                if (!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                    cert = tmp;
                    break;
                }
            }
            if (cert == null) {
                createUser(revUsername, revUserDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
                cert = signSession.createCertificate(ADMIN, revUsername, "foo123", admkeys.getPublic());
            }
            assertNotNull("No certificate to revoke.", cert);

            fingerprint = CertTools.getFingerprintAsString(cert); // to be able to remove

            PKIMessage msg = genRevReq(issuerDN, revUserDN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false, null, null);
            assertNotNull("Generating RevocationRequest failed.", msg);
            PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, revUserDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            if (eeAccessSession.findUser(ADMIN, revUsername) != null) {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, revUsername, ReasonFlags.unused);
            }
            internalCertStoreSession.removeCertificate(fingerprint);
        }

    }

    @Test
    public void test05EECrmfReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        final String testUserDN = "CN=cmptestuser5,C=SE";
        final String testUsername = "cmptestuser5";
        String fingerprint = null;
        String fingerprint2 = null;
        AuthenticationToken admToken = null;
        Certificate admCert = null;
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
            assertNotNull("Generating CrmfRequest failed.", msg);

            KeyPair admkeys = KeyTools.genKeys("512", "RSA");
            admToken = createAdminToken(admkeys, testUsername, testUserDN, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            admCert = getCertFromCredentials(admToken);
            fingerprint = CertTools.getFingerprintAsString(admCert);
            
            CMPCertificate[] extraCert = getCMPCert(admCert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(admCert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert2 = checkCmpCertRepMessage(testUserDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert2);
            fingerprint2 = CertTools.getFingerprintAsString(cert2);
        } finally {
            removeAuthenticationToken(admToken, admCert, testUsername); // also removes testUsername
            internalCertStoreSession.removeCertificate(fingerprint);
            internalCertStoreSession.removeCertificate(fingerprint2);
        }
    }

    @Test
    public void test06EERevReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(USER_DN, issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + USER_DN + "\"");
        Certificate cert = null, tmp = null;
        Iterator<Certificate> itr = certs.iterator();
        while (itr.hasNext()) {
            tmp = itr.next();
            if (!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        if (cert == null) {
            createUser("cmprevuser1", "CN=cmprevuser1,C=SE", "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
            cert = signSession.createCertificate(ADMIN, "cmprevuser1", "foo123", admkeys.getPublic());
        }
        assertNotNull("No certificate to revoke.", cert);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genRevReq(issuerDN, USER_DN, CertTools.getSerialNumber(cert), cacert, nonce, transid, false, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);

        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test07EERevReqWithUnknownCA() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        Collection<Certificate> certs = certStoreSession.findCertificatesBySubjectAndIssuer(USER_DN, issuerDN);
        log.debug("Found " + certs.size() + " certificates for userDN \"" + USER_DN + "\"");
        Certificate cert = null, tmp = null;
        Iterator<Certificate> itr = certs.iterator();
        while (itr.hasNext()) {
            tmp = itr.next();
            if (!certStoreSession.isRevoked(issuerDN, CertTools.getSerialNumber(tmp))) {
                cert = tmp;
                break;
            }
        }
        final String userName = "cmprevuser1";
        if (cert == null) {
            createUser(userName, "CN="+ userName + ",C=SE", "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
            cert = signSession.createCertificate(ADMIN, "cmprevuser1", "foo123", admkeys.getPublic());
        }
        try {
        assertNotNull("No certificate to revoke.", cert);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genRevReq("CN=cmprevuser1,C=SE", USER_DN, CertTools.getSerialNumber(cert), cert, nonce, transid, false, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, "CN=cmprevuser1,C=SE", USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertEquals("Revocation request succeeded", RevokedCertInfo.NOT_REVOKED, revStatus);
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(asn1InputStream.readObject());
            assertNotNull(respObject);

            PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrMsg = "CA with DN 'C=SE,CN=cmprevuser1' is unknown";
            assertEquals(expectedErrMsg, errMsg);
            removeAuthenticationToken(adminToken, admCert, adminName);
        } finally {
            asn1InputStream.close();
        }
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, userName);
        }
    }

    @Test
    public void test08EECrmfReqMultipleAuthModules() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        String modules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
        String parameters = "foo123" + ";" + "TestCA";
        cmpConfiguration.setAuthenticationModule(configAlias, modules);
        cmpConfiguration.setAuthenticationParameters(configAlias, parameters);
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        //********************************************
        final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
        sig.initVerify(admCert.getPublicKey());
        sig.update(CmpMessageHelper.getProtectedBytes(msg));
        boolean verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //********************************************

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
        Certificate cert2 = checkCmpCertRepMessage(USER_DN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("CrmfRequest did not return a certificate", cert2);

        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test09HMACCrmfReqMultipleAuthenticationModules() throws Exception {
        final String pbeSecret = "foo123hmac";
        String modules = CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE + ";"
                + CmpConfiguration.AUTHMODULE_HMAC;
        String parameters = "-;TestCA;" + pbeSecret;
        cmpConfiguration.setAuthenticationModule(configAlias, modules);
        cmpConfiguration.setAuthenticationParameters(configAlias, parameters);
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setResponseProtection(configAlias, "pbe");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, pbeSecret, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        // We configured PBE response protection above, so make sure it's correct
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, pbeSecret, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(USER_DN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), configAlias, ADMIN, caSession, eeAccessSession, certStoreSession,
                authorizationSession, eeProfileSession, null, endEntityManagementSession, cmpConfiguration);
        ICMPAuthenticationModule authmodule = verifier.getUsedAuthenticationModule(req, null, false);
        assertEquals(CmpConfiguration.AUTHMODULE_HMAC, authmodule.getName());
    }

    @Test
    public void test10HMACCrmfReqWrongAuthenticationModule() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_DN_PART_PWD);
        cmpConfiguration.setAuthenticationParameters(configAlias, "UID");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123hmac", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "The authentication module 'DnPartPwd' cannot be used in RA mode";
            assertEquals(expectedErrMsg, errMsg);
        } finally {
            inputStream.close();
        }
    }

    @Test
    public void test11EECrmfCheckAdminAuthorization() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestUnauthorizedAdmin";
        createUser(adminName, "CN=" + adminName + ",C=SE", "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        KeyPair admkeys = KeyTools.genKeys("512", "RSA");
        Certificate admCert = signSession.createCertificate(ADMIN, adminName, "foo123", admkeys.getPublic());
        CMPCertificate[] extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            assertEquals("'CN=cmpTestUnauthorizedAdmin,C=SE' is not an authorized administrator.", errMsg);
        } finally {
            inputStream.close();
        }

    }

    @Test
    public void test12EECrmfNotCheckAdmin() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setOmitVerificationsInECC(configAlias, true);
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate[] extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        //********************************************
        final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
        sig.initVerify(admCert.getPublicKey());
        sig.update(CmpMessageHelper.getProtectedBytes(msg));
        boolean verified = sig.verify(msg.getProtection().getBytes());
        assertTrue("Signing the message failed.", verified);
        //********************************************

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrmsg = "Omitting some verifications can only be accepted in RA mode and when the CMP request has already been authenticated, for example, through the use of NestedMessageContent";
            assertEquals(expectedErrmsg, errMsg);
        } finally {
            inputStream.close();
        }
        removeAuthenticationToken(adminToken, admCert, adminName);
        
    }

    @Test
    public void test13CrmfReqClientModeHMAC() throws Exception {
        String clientPassword = "foo123client";

        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, clientPassword);
        cmpConfiguration.setRAMode(configAlias, false);
        cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        cmpConfiguration.setResponseProtection(configAlias, "signature");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
        X500Name reqissuer = ir.toCertReqMsgArray()[0].getCertReq().getCertTemplate().getIssuer();
        assertNotNull("reqissuer is null", reqissuer);

        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue()
                .intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        // 
        // Try a request with no issuerDN in the certTemplate
        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            PKIMessage msgNoIssuer = genCertReq(null, clientDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest with no issuer failed.", msgNoIssuer);
            PKIMessage reqNoIssuer = protectPKIMessage(msgNoIssuer, false, clientPassword, "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
            ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
            DEROutputStream out2 = new DEROutputStream(bao2);
            out2.writeObject(reqNoIssuer);
            byte[] ba2 = bao2.toByteArray();
            // Send request and receive response
            byte[] respNoIssuer = sendCmpHttp(ba2, 200, configAlias);
            checkCmpResponseGeneral(respNoIssuer, issuerDN, clientDN, cacert, reqNoIssuer.getHeader().getSenderNonce().getOctets(), reqNoIssuer
                    .getHeader().getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            ir = (CertReqMessages) reqNoIssuer.getBody().getContent();
            Certificate cert2 = checkCmpCertRepMessage(clientDN, cacert, respNoIssuer, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("Crmf request did not return a certificate", cert2);

            // Send a confirm message to the CA
            String hash = CertTools.getFingerprintAsString(cert2);
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            PKIMessage confirm = genCertConfirm(USER_DN, cacert, nonce, transid, hash, reqId);
            PKIMessage protectedConfirm = protectPKIMessage(confirm, false, clientPassword, null, 567);
            assertNotNull(protectedConfirm);
            ByteArrayOutputStream bao3 = new ByteArrayOutputStream();
            DEROutputStream out3 = new DEROutputStream(bao3);
            out3.writeObject(protectedConfirm);
            byte[] ba3 = bao3.toByteArray();
            // Send request and receive response
            byte[] resp3 = sendCmpHttp(ba3, 200, configAlias);
            checkCmpResponseGeneral(resp3, issuerDN, USER_DN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(USER_DN, cacert, resp3);
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, clientUsername);
        }
    }

    @Test
    public void test14HMACModuleInClientMode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException, InvalidAlgorithmParameterException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException, java.lang.Exception {

        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";

        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
            assertNotNull("Protecting PKIMessage failed", req);

            HMACAuthenticationModule hmac = new HMACAuthenticationModule(ADMIN, "-", configAlias, cmpConfiguration, caSession.getCAInfo(ADMIN, caid),
                    eeAccessSession);
            hmac.verifyOrExtract(req, null);
            assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
            assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());

            // Test the same but without issuerDN in the request
            msg = genCertReq(null, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
            assertNotNull("Protecting PKIMessage failed", req);
            hmac.verifyOrExtract(req, null);
            assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
            assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, clientUsername);
        }
    }

    @Test
    public void test15CrmfReqClientModeRegToken() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
        cmpConfiguration.setAuthenticationParameters(configAlias, "-");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch (Exception e) {
        }
        createUser(clientUsername, clientDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue()
                    .intValue());
            assertNotNull("Crmf request did not return a certificate", cert1);
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, clientUsername);
        }
    }

    @Test
    public void test16CrmfReqClientModeMultipleModules() throws Exception {
        String authmodules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
        
        cmpConfiguration.setAuthenticationModule(configAlias, authmodules);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123hmac;-");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";

        createUser(clientUsername, clientDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue()
                    .intValue());
            assertNotNull("Crmf request did not return a certificate", cert1);

            VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), configAlias, ADMIN, caSession, eeAccessSession,
                    certStoreSession, authorizationSession, eeProfileSession, null, endEntityManagementSession, cmpConfiguration);

            ICMPAuthenticationModule authmodule = verifier.getUsedAuthenticationModule(msg, null, false);
            assertEquals(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, authmodule.getName());
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, clientUsername);
        }
    }

    @Test
    public void test17HMACCrmfReqClientModeHMACInvalidPassword() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123client");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch (Exception e) {
        }
        createUser(clientUsername, clientDN, "foo123ee", true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
            assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

            ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            try {
                PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
                assertNotNull(respObject);

                PKIBody body = respObject.getBody();
                assertEquals(23, body.getType());
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                String expectedErrMsg = "Authentication failed for message. clientTestUser.";
                assertEquals(expectedErrMsg, errMsg);
            } finally {
                inputStream.close();
            }
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, clientUsername);
        }
    }

    /** Test CMP initial request against EJBCA CMP in client mode (operationmode=normal) using End Entity certificate signature authentication, 
     * i.e. the request is signed by a certificate of the same end entity making the request, and this signature is used for authenticating the end entity.
     * Test:
     * - Request signed by a fake certificate, i.e. one that is not in the database (FAIL)
     * - Request signed by a certificate that beloongs to another user (FAIL)
     * - Request signed by a proper certificate but where user status is not NEW (FAIL)
     * - Request signed by a proper, but revoked certificate (FAIL)
     * - A working request signed by a proper, unrevoked certificate and user status is NEW (SUCCESS)
     * 
     * @throws Exception on some errors
     */
    @Test
    public void test18CrmfReqClientModeEESignature() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "-");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        final String testUserDN = "CN=cmptestuser16,C=SE";
        final String testUsername = "cmptestuser16";
        final String otherUserDN = "CN=cmptestotheruser16,C=SE";
        final String otherUsername = "cmptestotheruser16";
        String fingerprint = null;
        String fingerprint2 = null;
        String fingerprint3 = null;
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            KeyPair fakeKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            createUser(testUsername, testUserDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            // A real certificate that can be used to sign the message
            Certificate cert = signSession.createCertificate(ADMIN, testUsername, "foo123", keys.getPublic());
            fingerprint = CertTools.getFingerprintAsString(cert);
            // A fake certificate that should not be valid
            Certificate fakeCert = CertTools.genSelfCert(testUserDN, 30, null, fakeKeys.getPrivate(), fakeKeys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);

            // Step 1 sign with fake certificate, should not be valid as end entity authentication
            {
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
                assertNotNull("Generating CrmfRequest failed.", msg);
                CMPCertificate[] extraCert = getCMPCert(fakeCert);
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, fakeKeys.getPrivate(), pAlg.getAlgorithm().getId(),"BC");
                assertNotNull(msg);
                //******************************************''''''
                final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
                sig.initVerify(fakeCert.getPublicKey());
                sig.update(CmpMessageHelper.getProtectedBytes(msg));
                boolean verified = sig.verify(msg.getProtection().getBytes());
                assertTrue("Signing the message failed.", verified);
                //***************************************************

                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, configAlias);
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                        .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
                PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
                try {
                    assertNotNull(respObject);
                    PKIBody body = respObject.getBody();
                    assertEquals(23, body.getType());
                    ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                    String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                    String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
                    assertEquals(expectedErrMsg, errMsg);
                } finally {
                    inputStream.close();
                }
            }
            // Step 2, sign the request with a certificate that does not belong to the user
            {
                KeyPair otherKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                createUser(otherUsername, otherUserDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                // A real certificate that can be used to sign the message
                Certificate othercert = signSession.createCertificate(ADMIN, otherUsername, "foo123", otherKeys.getPublic());
                fingerprint2 = CertTools.getFingerprintAsString(cert);
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
                assertNotNull("Generating CrmfRequest failed.", msg);
                CMPCertificate[] extraCert = getCMPCert(othercert);
                msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, otherKeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
                assertNotNull(msg);
                //******************************************''''''
                final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
                sig.initVerify(othercert.getPublicKey());
                sig.update(CmpMessageHelper.getProtectedBytes(msg));
                boolean verified = sig.verify(msg.getProtection().getBytes());
                assertTrue("Signing the message failed.", verified);
                //***************************************************

                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(msg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, configAlias);
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                        .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
                try {
                    PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
                    assertNotNull(respObject);
                    PKIBody body = respObject.getBody();
                    assertEquals(23, body.getType());
                    ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                    String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                    String expectedErrMsg = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"
                            + testUsername + "'";
                    assertEquals(expectedErrMsg, errMsg);
                } finally {
                    inputStream.close();
                }
            }

            // Step 3 sign with the real certificate, but user status is not NEW
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            CMPCertificate[] extraCert = getCMPCert(cert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(cert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            // This should have failed
            ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
            try {
                PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
                assertNotNull(respObject);
                PKIBody body = respObject.getBody();
                assertEquals(23, body.getType());
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                String expectedErrMsg = "Got request with status GENERATED (40), NEW, FAILED or INPROCESS required: cmptestuser16.";
                assertEquals(expectedErrMsg, errMsg);

                // Step 4 now set status to NEW, and a clear text password, then it should finally work
                createUser(testUsername, testUserDN, "randompasswordhere", true, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                        CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                // Send request and receive response
                final byte[] resp2 = sendCmpHttp(ba, 200, configAlias);
                CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
                Certificate cert2 = checkCmpCertRepMessage(testUserDN, cacert, resp2, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                        .getValue().intValue());
                assertNotNull("CrmfRequest did not return a certificate", cert2);
                fingerprint3 = CertTools.getFingerprintAsString(cert2);

                // Step 5, revoke the certificate and try again
                {
                    certStoreSession.setRevokeStatus(ADMIN, cert, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, null);
                    final byte[] resp3 = sendCmpHttp(ba, 200, configAlias);
                    // This should have failed
                    checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                            .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                    ASN1InputStream inputStream3 = new ASN1InputStream(new ByteArrayInputStream(resp3));
                    try {
                        PKIMessage respObject3 = PKIMessage.getInstance(inputStream3.readObject());
                        assertNotNull(respObject);
                        PKIBody body3 = respObject3.getBody();
                        assertEquals(23, body3.getType());
                        err = (ErrorMsgContent) body3.getContent();
                        String errMsg3 = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                        String expectedErrMsg3 = "The certificate attached to the PKIMessage in the extraCert field is not active.";
                        assertEquals(expectedErrMsg3, errMsg3);
                    } finally {
                        inputStream3.close();
                    }
                }
            } finally {
                inputStream.close();
            }

        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, testUsername, ReasonFlags.unused);
            } catch (Exception e) {
            }

            try {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, otherUsername, ReasonFlags.unused);
            } catch (Exception e) {
            }

            internalCertStoreSession.removeCertificate(fingerprint);
            internalCertStoreSession.removeCertificate(fingerprint2);
            internalCertStoreSession.removeCertificate(fingerprint3);
        }
    }

    /**
     * Test the error message returned when CMP request missing a PBE protection in RA mode (operationmode=ra) and HMAC authentication is configured. 
     * 
     * @throws Exception on some errors
     */
    @Test
    public void test19NoHMACAuthentication() throws Exception {

        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123");
        cmpConfiguration.setRAMode(configAlias, true);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "PKI Message is not athenticated properly. No HMAC protection was found.";
            assertEquals(expectedErrMsg, errMsg);
        } finally {
            inputStream.close();
        }
    }

    /**
     * Test the error message returned when CMP request missing a signature in RA mode (operationmode=ra) and EndEntityCertificate authentication is configured. 
     * 
     * @throws Exception on some errors
     */
    @Test
    public void test20NoEECAuthentication() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
        PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "PKI Message is not athenticated properly. No PKI protection is found.";
        assertEquals(expectedErrMsg, errMsg);
        } finally { 
            inputStream.close();
        }
    }
    
    /**
     * Tests that EndEntityAuthentication module can be successfully used in client mode when the end entity's password is not stored in clear text.
     * 
     * @throws Exception
     */
    @Test
    public void test21CrmfRequestClientModeEECNotClearPassword() throws Exception {
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "-");
        cmpConfiguration.setRAMode(configAlias, false);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        
        final String testUserDN = "CN=cmptestuser21,C=SE";
        final String testUsername = "cmptestuser21";
        String fingerprint = null;
        String fingerprint2 = null;
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);

            createUser(testUsername, testUserDN, "foo123", false, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            Certificate cert = signSession.createCertificate(ADMIN, testUsername, "foo123", keys.getPublic());
            fingerprint = CertTools.getFingerprintAsString(cert);
            
            //Edit the status of the user to NEW
            createUser(testUsername, testUserDN, "foo123", false, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            CMPCertificate[] extraCert = getCMPCert(cert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);
            //******************************************''''''
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(cert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            boolean verified = sig.verify(msg.getProtection().getBytes());
            assertTrue("Signing the message failed.", verified);
            //***************************************************

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            final byte[] ba = bao.toByteArray();
            
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, configAlias);
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert2 = checkCmpCertRepMessage(testUserDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert2);
            fingerprint2 = CertTools.getFingerprintAsString(cert2);
        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, testUsername, ReasonFlags.unused);
            } catch (Exception e) {
            }

            internalCertStoreSession.removeCertificate(fingerprint);
            internalCertStoreSession.removeCertificate(fingerprint2);
        }
    }

    /**
     * Tests the possibility to use different signature algorithms in CMP requests and responses if protection algorithm 
     * is specified.
     * 
     * A CMP request is sent to a CA that uses ECDSA with SHA256 as signature and encryption algorithms:
     * 
     * 1. Send a CRMF request signed using ECDSA with SHA256 algorithm and expects a response signed by the same algorithm
     * 2. Send a CMP Confirm message without protection. The response is expected to be signed using ECDSA (because that's the CA's key algorithm)
     *    and SHA1 (because that's the default digest algorithm)
     * 3. Sends a CMP Revocation request signed using ECDSA with SHA256 and expects a response signed by the same algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test22EECAuthWithSHA256AndECDSA() throws Exception {
        log.trace(">test22EECAuthWithSHA256AndECDSA()");
        
        //-------------- Set the necessary configurations
        cmpConfiguration.setRAEEProfile(configAlias, "ECDSAEEP");
        cmpConfiguration.setRACertProfile(configAlias, "ECDSACP");
        cmpConfiguration.setCMPDefaultCA(configAlias, "CmpECDSATestCA");
        cmpConfiguration.setRACAName(configAlias, "CmpECDSATestCA");
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        cmpConfiguration.setRANameGenParams(configAlias, "CN");
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "CmpECDSATestCA");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        
       
        removeTestCA("CmpECDSATestCA");
        try{
            CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            int cryptoTokenId = cryptoTokenManagementSession.getIdFromName("CmpECDSATestCA");
            CryptoTokenTestUtils.removeCryptoToken(ADMIN, cryptoTokenId);
        } catch(Exception e) {}
        
        
        //---------------------- Create the test CA
        // Create catoken
        
        String ecdsaCADN = "CN=CmpECDSATestCA";
        String keyspec = "prime256v1";
        
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, "foo123".toCharArray(), true, false, ecdsaCADN, keyspec);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<ExtendedCAServiceInfo>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(ecdsaCADN, "CN");
        X509CAInfo ecdsaCaInfo = new X509CAInfo(ecdsaCADN, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                3650, CAInfo.SELFSIGNED, null, catoken);
        ecdsaCaInfo.setExtendedCAServiceInfos(extendedCaServices);
        X509CA ecdsaCA = new X509CA(ecdsaCaInfo);
        ecdsaCA.setCAToken(catoken);
        // A CA certificate
        Collection<Certificate> cachain = new ArrayList<Certificate>();     
        
        
        final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        //final String keyalg = AlgorithmTools.getKeyAlgorithm(publicKey);
        String sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(cryptoTokenId, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        X509Certificate ecdsaCaCert = CertTools.genSelfCertForPurpose(ecdsaCADN, 10L, "1.1.1.1", privateKey, publicKey, sigalg, true, keyusage, true);
        assertNotNull(ecdsaCaCert);
        cachain.add(ecdsaCaCert);
        ecdsaCA.setCertificateChain(cachain);
        caSession.addCA(ADMIN, ecdsaCA);

        //-------------- Create the EndEntityProfile and the CertificateProfile
        List<Integer> availableCAs = new ArrayList<Integer>();
        availableCAs.add(ecdsaCA.getCAId());
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        cp.setAvailableCAs(availableCAs);
        try {
            certProfileSession.addCertificateProfile(ADMIN, "ECDSACP", cp);
        } catch (CertificateProfileExistsException e) {
        }
        int cpId = certProfileSession.getCertificateProfileId("ECDSACP");

        // Configure an EndEntity profile (CmpRA) with allow CN, O, C in DN
        // and rfc822Name (uncheck 'Use entity e-mail field' and check
        // 'Modifyable'), MS UPN in altNames in the end entity profile.
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
        eep.setValue(EndEntityProfile.DEFAULTCA, 0, "" + ecdsaCA.getCAId());
        eep.setValue(EndEntityProfile.AVAILCAS, 0, "" + ecdsaCA.getCAId());
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field
        // from "email" data
        try {
            eeProfileSession.addEndEntityProfile(ADMIN, "ECDSAEEP", eep);
        } catch (EndEntityProfileExistsException e) {
        }
        int eepId = eeProfileSession.getEndEntityProfileId("ECDSAEEP");
        
        
        //---------------- Send a CMP initialization request
        AuthenticationToken admToken = null;
        final String testAdminDN = "CN=cmptestadmin,C=SE";
        final String testAdminName = "cmptestadmin";
        X509Certificate admCert = null;
        String fp=null, fp2=null;
        try {
            KeyPair keys = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECDSA);
        
            String userDN = "CN=cmpecdsauser";
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier( X9ObjectIdentifiers.ecdsa_with_SHA256 );
            PKIMessage req = genCertReq(ecdsaCaInfo.getSubjectDN(), userDN, keys, ecdsaCaCert, nonce, transid, false, null, null, null, null, pAlg, null);
            createUser(testAdminName, testAdminDN, "foo123", true, ecdsaCaInfo.getCAId(), eepId, cpId);
            KeyPair admkeys = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECDSA);
            admToken = createAdminToken(admkeys, testAdminName, testAdminDN, ecdsaCA.getCAId(), eepId, cpId);
            admCert = getCertFromCredentials(admToken);
            fp = CertTools.getFingerprintAsString(admCert);
        
            CMPCertificate[] extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), AlgorithmTools.getDigestFromSigAlg(pAlg.getAlgorithm().getId()), "BC");//CMSSignedGenerator.DIGEST_SHA256
            assertNotNull(req);
        
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, ecdsaCaInfo.getSubjectDN(), userDN, ecdsaCaCert, nonce, transid, true, null, X9ObjectIdentifiers.ecdsa_with_SHA256.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, ecdsaCaCert, resp, reqId);
            fp2 = CertTools.getFingerprintAsString(cert);
        
            
            // ------------------- Send a CMP confirm message
            String hash = "foo123";
            PKIMessage confirm = genCertConfirm(userDN, ecdsaCaCert, nonce, transid, hash, reqId);
            assertNotNull(confirm);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(confirm);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, configAlias);
            
            //Since pAlg was not set in the ConfirmationRequest, the default DigestAlgorithm (SHA1) will be used
            checkCmpResponseGeneral(resp, ecdsaCaInfo.getSubjectDN(), userDN, ecdsaCaCert, nonce, transid, true, null, X9ObjectIdentifiers.ecdsa_with_SHA1.getId());
            checkCmpPKIConfirmMessage(userDN, ecdsaCaCert, resp);

            //-------------------------  Send a CMP revocation request
            PKIMessage rev = genRevReq(ecdsaCaInfo.getSubjectDN(), userDN, cert.getSerialNumber(), ecdsaCaCert, nonce, transid, true, pAlg, null);
            assertNotNull(rev);
            rev = CmpMessageHelper.buildCertBasedPKIProtection(rev, extraCert, admkeys.getPrivate(), AlgorithmTools.getDigestFromSigAlg(pAlg.getAlgorithm().getId()), "BC");
            assertNotNull(rev);

            ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(rev);
            byte[] barev = baorev.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, configAlias);
            checkCmpResponseGeneral(resp, ecdsaCaInfo.getSubjectDN(), userDN, ecdsaCaCert, nonce, transid, true, null, X9ObjectIdentifiers.ecdsa_with_SHA256.getId());
            int revStatus = checkRevokeStatus(ecdsaCaInfo.getSubjectDN(), CertTools.getSerialNumber(cert));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
            
        } finally {
            try {
                removeAuthenticationToken(admToken, admCert, testAdminName);
            } catch (Exception e) {
                //NOPMD: Ignore
            }
            try {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, "cmpecdsauser", ReasonFlags.unused);
            } catch (Exception e) {
                //NOPMD: Ignore
            }
            internalCertStoreSession.removeCertificate(fp);
            internalCertStoreSession.removeCertificate(fp2);
            eeProfileSession.removeEndEntityProfile(ADMIN, "ECDSAEEP");
            certProfileSession.removeCertificateProfile(ADMIN, "ECDSACP");

            removeTestCA("CmpECDSATestCA");
        }
        log.trace("<test22EECAuthWithSHA256AndECDSA()");

    }

    /**
     * Tests the possibility to use different signature algorithms in CMP requests and responses.
     * 
     * A CRMF request, signed using ECDSA with SHA1, is sent to a CA that uses RSA with SHA256 as signature algorithm.
     * The expected response is signed by RSA with SHA1.
     * 
     * @throws Exception
     */
    @Test
    public void test23EECAuthWithRSAandECDSA() throws Exception {
        log.trace(">test23EECAuthWithRSAandECDSA()");
        
        //-------------- Set the necessary configurations

        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        cmpConfiguration.setRANameGenParams(configAlias, "CN");
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        cmpConfiguration.setAuthenticationParameters(configAlias, "TestCA");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);
        
        //---------------- Send a CMP initialization request
        AuthenticationToken admToken = null;
        final String testAdminDN = "CN=cmptestadmin,C=SE";
        final String testAdminName = "cmptestadmin";
        X509Certificate admCert = null;
        String fp=null, fp2=null;
        try {
            KeyPair keys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        
            String userDN = "CN=cmpmixuser";
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA1);
            PKIMessage req = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
        
            createUser(testAdminName, testAdminDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            KeyPair admkeys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
            admToken = createAdminToken(admkeys, testAdminName, testAdminDN, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            admCert = getCertFromCredentials(admToken);
            fp = CertTools.getFingerprintAsString(admCert);
        
            CMPCertificate[] extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1, "BC");
            assertNotNull(req);
        
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, configAlias);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            fp2 = CertTools.getFingerprintAsString(cert);
        
        } finally {
            removeAuthenticationToken(admToken, admCert, testAdminName);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, "cmpmixuser", ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fp);
            internalCertStoreSession.removeCertificate(fp2);
        }
        log.trace("<test23EECAuthWithRSAandECDSA()");
    }

    /**
     * Sending a Crmf Request in RA mode. The request is authenticated using HMAC and is expected to contain the EndEntityProfile 'EMPTY' in the KeyId field.
     * The request should fail because specifying 'EMPTY' or 'ENDUSER' as the KeyId is not allowed in combination with RA mode and HMAC authentication module 
     * 
     * The test is only done for HMAC and not EndEntityCertificate because in the later, the use of profiles can be restricted through Administrator privileges.
     * Other authentication modules are not used in RA mode
     * 
     * @throws Exception
     */
    @Test
    public void test24HMACUnacceptedKeyId() throws Exception {
        
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "foo123hmac");
        cmpConfiguration.setRAEEProfile(configAlias, "KeyId");
        cmpConfiguration.setRACertProfile(configAlias, "ProfileDefault");
        cmpConfiguration.setRACAName(configAlias, "TestCA");
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration, Configuration.CMPConfigID);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123hmac", "EMPTY", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            assertNotNull(respObject);

            final PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            final String expectedErrMsg = "Unaccepted KeyId 'EMPTY' in CMP request";
            assertEquals(expectedErrMsg, errMsg);
        } finally {
            inputStream.close();
        }
    }

    
    @AfterClass
    public static void restoreConf() {
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        try {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, USERNAME, ReasonFlags.unused);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, "cmpTestUnauthorizedAdmin", ReasonFlags.keyCompromise);
        } catch (Exception e) {
        }

    }
   
    private CMPCertificate[] getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        CMPCertificate[] res = {new CMPCertificate(c)};
        return res;
    }

    private EndEntityInformation createUser(String username, String subjectDN, String password, boolean clearpassword, int caid, int eepid, int cpid) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException, Exception {

        EndEntityInformation user = new EndEntityInformation(username, subjectDN, caid, null, username + "@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                eepid, cpid, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword(password);
        try {
            endEntityManagementSession.addUser(ADMIN, username, password, subjectDN, "rfc822name=" + username + "@primekey.se", username + "@primekey.se",
                    clearpassword, eepid, cpid, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0,
                    caid);
            log.debug("created user: " + username);
        } catch (Exception e) {
            log.debug("User " + username + " already exists. Setting the user status to NEW");
            endEntityManagementSession.changeUser(ADMIN, user, clearpassword);
            endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        return user;

    }

    private X509Certificate getCertFromCredentials(AuthenticationToken authToken) {
        X509Certificate certificate = null;
        Set<?> inputcreds = authToken.getCredentials();
        if (inputcreds != null) {
            for (Object object : inputcreds) {
                if (object instanceof X509Certificate) {
                    certificate = (X509Certificate) object;
                }
            }
        }
        return certificate;
    }

    private AuthenticationToken createAdminToken(KeyPair keys, String name, String dn, int caid, int eepid, int cpid) throws RoleExistsException, RoleNotFoundException,
            CreateException, AuthorizationDeniedException {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(dn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        AuthenticationToken token = createTokenWithCert(name, subject, keys, caid, eepid, cpid);
        assertNotNull(token);
        X509Certificate cert = (X509Certificate) token.getCredentials().iterator().next();
        assertNotNull(cert);
        
        // Initialize the role mgmt system with this role that is allowed to edit roles

        String roleName = "Super Administrator Role";
        RoleData roledata = roleAccessSessionRemote.findRole(roleName);
        // Create a user aspect that matches the authentication token, and add that to the role.
        List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(roleName, CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN")));
        roleManagementSession.addSubjectsToRole(ADMIN, roledata, accessUsers);

        return token;
    }

    private AuthenticationToken createTokenWithCert(String adminName, AuthenticationSubject subject, KeyPair keys, int caid, int eepid, int cpid) {

        // A small check if we have added a "fail" credential to the subject.
        // If we have we will return null, so we can test authentication failure.
        Set<?> usercredentials = subject.getCredentials();
        if ((usercredentials != null) && (usercredentials.size() > 0)) {
            Object o = usercredentials.iterator().next();
            if (o instanceof String) {
                String str = (String) o;
                if (StringUtils.equals("fail", str)) {
                    return null;
                }
            }
        }

        X509Certificate certificate = null;
        // If we have a certificate as input, use that, otherwise generate a self signed certificate
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();

        // If there was no certificate input, create a self signed
        String dn = "C=SE,O=Test,CN=Test"; // default
        // If we have created a subject with an X500Principal we will use this DN to create the dummy certificate.
        if (subject != null) {
            Set<Principal> principals = subject.getPrincipals();
            if ((principals != null) && (principals.size() > 0)) {
                Principal p = principals.iterator().next();
                if (p instanceof X500Principal) {
                    X500Principal xp = (X500Principal) p;
                    dn = xp.getName();
                }
            }
        }

        try {
            createUser(adminName, dn, "foo123", true, caid, eepid, cpid);
        } catch (AuthorizationDeniedException e1) {
            throw new CertificateCreationException("Error encountered when creating admin user", e1);
        } catch (UserDoesntFullfillEndEntityProfile e1) {
            throw new CertificateCreationException("Error encountered when creating admin user", e1);
        } catch (WaitingForApprovalException e1) {
            throw new CertificateCreationException("Error encountered when creating admin user", e1);
        } catch (EjbcaException e1) {
            throw new CertificateCreationException("Error encountered when creating admin user", e1);
        } catch (Exception e1) {
            throw new CertificateCreationException("Error encountered when creating admin user", e1);
        }

        try {
            certificate = (X509Certificate) signSession.createCertificate(ADMIN, adminName, "foo123", keys.getPublic());
        } catch (ObjectNotFoundException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CADoesntExistsException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (EjbcaException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (AuthorizationDeniedException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        } catch (CesecoreException e) {
            throw new CertificateCreationException("Error encountered when creating certificate", e);
        }

        assertNotNull(certificate);
        
        // Add the credentials and new principal
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        // We cannot use the X509CertificateAuthenticationToken here, since it can only be used internally in a JVM.
        AuthenticationToken result = new TestX509CertificateAuthenticationToken(principals, credentials);
        assertNotNull(result);
        return result;
    }

    private void removeAuthenticationToken(AuthenticationToken authToken, Certificate cert, String adminName) throws RoleNotFoundException,
            AuthorizationDeniedException, ApprovalException, NotFoundException, WaitingForApprovalException, RemoveException {
        String rolename = "Super Administrator Role";

        RoleData roledata = roleAccessSessionRemote.findRole("Super Administrator Role");
        if (roledata != null) {
            List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
            accessUsers.add(new AccessUserAspectData(rolename, CertTools.getIssuerDN(cert).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASEINS, CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN")));

            roleManagementSession.removeSubjectsFromRole(ADMIN, roledata, accessUsers);
        }

        endEntityManagementSession.revokeAndDeleteUser(ADMIN, adminName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

}
