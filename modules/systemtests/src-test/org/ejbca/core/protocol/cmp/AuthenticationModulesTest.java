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
import java.security.KeyFactory;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
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
import org.bouncycastle.asn1.cmp.CertRepMessage;
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
import org.cesecore.certificates.ca.CaSessionTest;
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
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
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

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityProfileSession eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private ConfigurationSessionRemote confSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateStoreSession certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private AccessControlSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();

        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
     
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaSessionTest.createTestX509CA(issuerDN, null, false, keyusage);
        caid = testx509ca.getCAId();
        cacert = testx509ca.getCACertificate();
        caSession.addCA(ADMIN, testx509ca);

        // Initialize config in here
        EjbcaConfigurationHolder.instance();

        confSession.backupConfiguration();

        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "TestCA");

    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        CryptoTokenManagementSessionTest.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(ADMIN, caid);
        
        boolean cleanUpOk = true;
        if (!confSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
    }

    @Test
    public void test01HMACModule() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException,
            InvalidAlgorithmParameterException, CADoesntExistsException, AuthorizationDeniedException {

        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        assertFalse("caid is 0", (caid == 0));
        assertNotNull("cacert is null", cacert);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caSession.getCAInfo(ADMIN, caid));
        hmac.setSession(ADMIN, eeAccessSession, certStoreSession);
        boolean res = hmac.verifyOrExtract(req, null, false);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", "foo123", hmac.getAuthenticationString());

    }

    @Test
    public void test03HMACCrmfReq() throws Exception {
        
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(USER_DN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
    }

    @Test
    public void test04HMACRevReq() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

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
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, revUserDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, revUsername, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }

    }

    @Test
    public void test05EECrmfReq() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

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

            createUser(testUsername, testUserDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            KeyPair admkeys = KeyTools.genKeys("512", "RSA");
            admToken = createAdminToken(admkeys, testUsername, testUserDN, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            admCert = getCertFromCredentials(admToken);
            fingerprint = CertTools.getFingerprintAsString(admCert);
            
            CMPCertificate extraCert = getCMPCert(admCert);
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
            final byte[] resp = sendCmpHttp(ba, 200);
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
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

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
        CMPCertificate extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);

        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test07EERevReqWithUnknownCA() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

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
        PKIMessage msg = genRevReq("CN=cmprevuser1,C=SE", USER_DN, CertTools.getSerialNumber(cert), cert, nonce, transid, false, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, "CN=cmprevuser1,C=SE", USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert));
        assertEquals("Revocation request succeeded", RevokedCertInfo.NOT_REVOKED, revStatus);
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "CA with DN 'C=SE,CN=cmprevuser1' is unknown";
        assertEquals(expectedErrMsg, errMsg);
        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test08EECrmfReqMultipleAuthModules() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        String modules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
        String parameters = "foo123" + ";" + "TestCA";
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate extraCert = getCMPCert(admCert);
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
        final byte[] resp = sendCmpHttp(ba, 200);
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
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, modules);

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, parameters);

        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        confSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        assertTrue("The response protection was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe"));

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
        final byte[] resp = sendCmpHttp(ba, 200);
        // We configured PBE response protection above, so make sure it's correct
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, pbeSecret, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(USER_DN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), ADMIN, caSession, eeAccessSession, certStoreSession,
                authorizationSession, eeProfileSession, null, endEntityManagementSession);
        boolean verify = verifier.verify(req, null, false);
        assertTrue("Verifying PKIMessage failed", verify);
        assertEquals(CmpConfiguration.AUTHMODULE_HMAC, verifier.getUsedAuthenticationModule().getName());
    }

    @Test
    public void test10HMACCrmfReqWrongAuthenticationModule() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_DN_PART_PWD));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "UID"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "The authentication module 'DnPartPwd' cannot be used in RA mode";
        assertEquals(expectedErrMsg, errMsg);
    }

    @Test
    public void test11EECrmfCheckAdminAuthorization() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestUnauthorizedAdmin";
        createUser(adminName, "CN=" + adminName + ",C=SE", "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        KeyPair admkeys = KeyTools.genKeys("512", "RSA");
        Certificate admCert = signSession.createCertificate(ADMIN, adminName, "foo123", admkeys.getPublic());
        CMPCertificate extraCert = getCMPCert(admCert);
        msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, admkeys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
        assertNotNull(msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("'CN=cmpTestUnauthorizedAdmin,C=SE' is not an authorized administrator.", errMsg);

    }

    @Test
    public void test12EECrmfNotCheckAdmin() throws NoSuchAlgorithmException, EjbcaException, IOException, Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);

        String adminName = "cmpTestAdmin";
        KeyPair admkeys = KeyTools.genKeys("1024", "RSA");
        AuthenticationToken adminToken = createAdminToken(admkeys, adminName, "CN=" + adminName + ",C=SE", caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate admCert = getCertFromCredentials(adminToken);
        CMPCertificate extraCert = getCMPCert(admCert);
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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        assertEquals("The CMP message could not be authenticated in RA mode. No CA has been set in the configuration file and the message has not been authenticated previously", errMsg);

        removeAuthenticationToken(adminToken, admCert, adminName);
    }

    @Test
    public void test13CrmfReqClientModeHMAC() throws Exception {
        String clientPassword = "foo123client";

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, clientPassword);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, clientPassword));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());
        confSession.updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");

        confSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        assertTrue("The response protection was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature"));

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        // 
        // Try a request with no issuerDN in the certTemplate
        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        PKIMessage msgNoIssuer = genCertReq(null, clientDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest with no issuer failed.", msgNoIssuer);
        PKIMessage reqNoIssuer = protectPKIMessage(msgNoIssuer, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
        DEROutputStream out2 = new DEROutputStream(bao2);
        out2.writeObject(reqNoIssuer);
        byte[] ba2 = bao2.toByteArray();
        // Send request and receive response
        byte[] respNoIssuer = sendCmpHttp(ba2, 200);
        checkCmpResponseGeneral(respNoIssuer, issuerDN, clientDN, cacert, reqNoIssuer.getHeader().getSenderNonce().getOctets(), reqNoIssuer
                .getHeader().getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        ir = (CertReqMessages) reqNoIssuer.getBody().getContent();
        Certificate cert2 = checkCmpCertRepMessage(clientDN, cacert, respNoIssuer, ir.toCertReqMsgArray()[0].getCertReq()
                .getCertReqId().getValue().intValue());
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
        byte[] resp3 = sendCmpHttp(ba3, 200);
        checkCmpResponseGeneral(resp3, issuerDN, USER_DN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(USER_DN, cacert, resp3);
    }

    @Test
    public void test14HMACModuleInClientMode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException, InvalidAlgorithmParameterException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException, java.lang.Exception {

        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";

        createUser(clientUsername, clientDN, clientPassword, true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        PKIMessage req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);

        HMACAuthenticationModule hmac = new HMACAuthenticationModule("foo123");
        hmac.setCaInfo(caSession.getCAInfo(ADMIN, caid));
        hmac.setSession(ADMIN, eeAccessSession, certStoreSession);
        boolean res = hmac.verifyOrExtract(req, null, false);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());

        // Test the same but without issuerDN in the request
        msg = genCertReq(null, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        req = protectPKIMessage(msg, false, clientPassword, "mykeyid", 567);
        assertNotNull("Protecting PKIMessage failed", req);
        res = hmac.verifyOrExtract(req, null, false);
        assertTrue("Verifying the message authenticity using HMAC failed.", res);
        assertNotNull("HMAC returned null password.", hmac.getAuthenticationString());
        assertEquals("HMAC returned the wrong password", clientPassword, hmac.getAuthenticationString());
    }

    @Test
    public void test15CrmfReqClientModeRegToken() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch (Exception e) {
        }
        createUser(clientUsername, clientDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);
    }

    @Test
    public void test16CrmfReqClientModeMultipleModules() throws Exception {
        String authmodules = CmpConfiguration.AUTHMODULE_HMAC + ";" + CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD;
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, authmodules);

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123hmac;-"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123;-");

        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";

        createUser(clientUsername, clientDN, "foo123", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, clientDN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
        Certificate cert1 = checkCmpCertRepMessage(clientDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                .getValue().intValue());
        assertNotNull("Crmf request did not return a certificate", cert1);

        VerifyPKIMessage verifier = new VerifyPKIMessage(caSession.getCAInfo(ADMIN, caid), ADMIN, caSession, eeAccessSession, certStoreSession,
                authorizationSession, eeProfileSession, null, endEntityManagementSession);
        boolean verify = verifier.verify(msg, null, false);
        assertTrue(verify);
        assertEquals(CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD, verifier.getUsedAuthenticationModule().getName());
    }

    @Test
    public void test17HMACCrmfReqClientModeHMACInvalidPassword() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123client"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertFalse("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        String clientUsername = "clientTestUser";
        String clientDN = "CN=" + clientUsername + ",C=SE";
        String clientPassword = "foo123client";
        try {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, clientUsername, ReasonFlags.unused);
        } catch (Exception e) {
        }
        createUser(clientUsername, clientDN, "foo123ee", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

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
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, clientDN, cacert, req.getHeader().getSenderNonce().getOctets(), req.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "Authentication failed for message. clientTestUser.";
        assertEquals(expectedErrMsg, errMsg);
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
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));

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
                CMPCertificate extraCert = getCMPCert(fakeCert);
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
                final byte[] resp = sendCmpHttp(ba, 200);
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                        .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
                assertNotNull(respObject);
                PKIBody body = respObject.getBody();
                assertEquals(23, body.getType());
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                String expectedErrMsg = "CA does not exist: " + testUserDN.hashCode();
                assertEquals(expectedErrMsg, errMsg);
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
                CMPCertificate extraCert = getCMPCert(othercert);
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
                final byte[] resp = sendCmpHttp(ba, 200);
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                        .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
                assertNotNull(respObject);
                PKIBody body = respObject.getBody();
                assertEquals(23, body.getType());
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                String expectedErrMsg = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"
                        + testUsername + "'.";
                assertEquals(expectedErrMsg, errMsg);
            }

            // Step 3 sign with the real certificate, but user status is not NEW
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            CMPCertificate extraCert = getCMPCert(cert);
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
            final byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            // This should have failed
            PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);
            PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrMsg = "Got request with status GENERATED (40), NEW, FAILED or INPROCESS required: cmptestuser16.";
            assertEquals(expectedErrMsg, errMsg);

            // Step 4 now set status to NEW, and a clear text password, then it should finally work
            createUser(testUsername, testUserDN, "randompasswordhere", true, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            // Send request and receive response
            final byte[] resp2 = sendCmpHttp(ba, 200);
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert2 = checkCmpCertRepMessage(testUserDN, cacert, resp2, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert2);
            fingerprint3 = CertTools.getFingerprintAsString(cert2);

            // Step 5, revoke the certificate and try again
            {
                certStoreSession.setRevokeStatus(ADMIN, cert, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION, null);
                final byte[] resp3 = sendCmpHttp(ba, 200);
                // This should have failed
                checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                        .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                PKIMessage respObject3 = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp3)).readObject());
                assertNotNull(respObject);
                PKIBody body3 = respObject3.getBody();
                assertEquals(23, body3.getType());
                err = (ErrorMsgContent) body3.getContent();
                String errMsg3 = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                String expectedErrMsg3 = "The certificate attached to the PKIMessage in the extraCert field is revoked.";
                assertEquals(expectedErrMsg3, errMsg3);
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

        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_HMAC));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "foo123"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
        EjbcaConfigurationHolder.updateConfiguration(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        assertTrue("The CMP Authentication module was not configured correctly.", CmpConfiguration.getRAOperationMode());

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                .getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        final PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        final String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        final String expectedErrMsg = "PKI Message is not athenticated properly. No HMAC protection was found.";
        assertEquals(expectedErrMsg, errMsg);
    }

    /**
     * Test the error message returned when CMP request missing a signature in RA mode (operationmode=ra) and EndEntityCertificate authentication is configured. 
     * 
     * @throws Exception on some errors
     */
    @Test
    public void test20NoEECAuthentication() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");   
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));

        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        PKIMessage msg = genCertReq(issuerDN, USER_DN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, new DEROctetString(nonce));
        assertNotNull("Generating CrmfRequest failed.", msg);

        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        final DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(msg);
        final byte[] ba = bao.toByteArray();
        // Send request and receive response
        final byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, USER_DN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        
        PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
        assertNotNull(respObject);

        PKIBody body = respObject.getBody();
        assertEquals(23, body.getType());
        ErrorMsgContent err = (ErrorMsgContent) body.getContent();
        String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
        String expectedErrMsg = "PKI Message is not athenticated properly. No PKI protection is found.";
        assertEquals(expectedErrMsg, errMsg);
        
    }

    /**
     * Tests that EndEntityAuthentication module can be successfully used in client mode when the end entity's password is not stored in clear text.
     * 
     * @throws Exception
     */
    @Test
    public void test21CrmfRequestClientModeEECNotClearPassword() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-"));
        confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
        
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
            CMPCertificate extraCert = getCMPCert(cert);
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
            final byte[] resp = sendCmpHttp(ba, 200);
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
     * Tests that EndEntityAuthentication module in client mode when 3GPP option is activated:
     * 
     * 1- An initialization request, signed by the vendor-issued certificate (not in the database), is sent in RA mode. The request should fail.
     * 2- An initialization request, signed by the vendor-issued certificate (not in the database), is sent in client mode. The request should pass.
     * 3- An initialization request, signed by Ejbca issued certificate, is sent in client mode. The request should fail.
     * 4- A KeyUpdate request (aka. renewal request), signed by the vendor-issued certificate (still not in the database), is sent. The request should fail.
     * 5- A KeyUpdate request (aka. renewal request), signed by Ejbca issued certificate, is sent. The request should pass.
     * 6- A revocation request, signed by Ejbca issued certificate, is sent. The request should pass.
     * 
     * @throws Exception
     */
    @Test
    public void test223GPPMode() throws Exception {
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE));
        confSession.updateProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_VENDORCERTIFICATEMODE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_VENDORCERTIFICATEMODE, "true"));
        confSession.updateProperty(CmpConfiguration.CONFIG_VENDORCA, "3GPPCA");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_VENDORCA, "3GPPCA"));
        confSession.updateProperty(CmpConfiguration.CONFIG_EXTRACTUSERNAMECOMPONENT, "UID");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_EXTRACTUSERNAMECOMPONENT, "UID"));
        confSession.updateProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE, "true"));
        confSession.updateProperty(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true");
        assertTrue("The CMP Authentication module was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY, "true"));
        confSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        assertTrue("The response protection was not configured correctly.",
                confSession.verifyProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature"));
        
        String testUIDUsername = "uidusername";
        String testUserDN = "CN=3gpptestuse,UID=" + testUIDUsername + ",C=se";
        
        X509Certificate gppcacert = (X509Certificate) CertTools.getCertfromByteArray(gppCA);
        X509Certificate gppusercert = (X509Certificate) CertTools.getCertfromByteArray(gppuser);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(gppuserkey);
        PrivateKey privkey = kf.generatePrivate(ks);
        
        //importing gppcacert as an external CA
        Collection<Certificate> cacerts = new ArrayList<Certificate>();
        cacerts.add(gppcacert);
        caAdminSession.importCACertificate(ADMIN, "3GPPCA", cacerts);
        createUser(testUIDUsername, testUserDN, "foo123", false, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        
        String fingerprint = null;
        String fingerprint2 = null;
        try {
            
            // Creating an initialization Request in RA mode signed by the vendor-issued certificate, not in the database, for an endentity that already exists.
            confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
            assertTrue("The CMP Authentication module was not configured correctly.",
                    confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra"));
            
            PKIMessage msg = genCertReq(issuerDN, testUserDN, keys, gppcacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            CMPCertificate extraCert = getCMPCert(gppusercert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, privkey, pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(msg);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200);
            // Unprotected error message
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            
            PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);

            PKIBody body = respObject.getBody();
            assertEquals(23, body.getType());
            ErrorMsgContent err = (ErrorMsgContent) body.getContent();
            String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            String expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
            assertEquals(expectedErrMsg, errMsg);
            
            confSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
            assertTrue("The CMP Authentication module was not configured correctly.",
                    confSession.verifyProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "normal"));
            
            // Creating an initialization Request in client mode signed by the vendor-issued certificate, not in the database, for an endentity that already exists.
            msg = genCertReq(issuerDN, testUserDN, keys, gppcacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            extraCert = getCMPCert(gppusercert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, privkey, pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(msg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            CertReqMessages ir = (CertReqMessages) msg.getBody().getContent();
            Certificate cert = checkCmpCertRepMessage(testUserDN, cacert, resp, ir.toCertReqMsgArray()[0].getCertReq().getCertReqId()
                    .getValue().intValue());
            assertNotNull("CrmfRequest did not return a certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            
            
            // Sending another initialization Request in client mode signed by the endentity's certificate issued by Ejbca
            msg = genCertReq(issuerDN, testUserDN, keys, cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            extraCert = getCMPCert(cert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(msg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            
            respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);

            body = respObject.getBody();
            assertEquals(23, body.getType());
            err = (ErrorMsgContent) body.getContent();
            errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            expectedErrMsg = "The End Entity certificate attached to the PKIMessage is not issued by the CA '3GPPCA'";
            assertEquals(expectedErrMsg, errMsg);
            
            
            // Sending a KeyUpdateRequest signed by the vendor-issued certificate
            msg = genRenewalReq(testUserDN, gppcacert, nonce, transid, keys, false, null, null, pAlg, new DEROctetString(nonce));
            assertNotNull("Generating CrmfRequest failed.", msg);
            extraCert = getCMPCert(gppusercert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, privkey, pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(msg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, CertTools.getSubjectDN(gppcacert), testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader()
                    .getTransactionID().getOctets(), false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            
            respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);

            body = respObject.getBody();
            assertEquals(23, body.getType());
            err = (ErrorMsgContent) body.getContent();
            errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
            expectedErrMsg = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
            assertEquals(expectedErrMsg, errMsg);

            
            // Sending a KeyUpdateRequest signed by the endtity's certificate issued by Ejbca
            msg = genRenewalReq(testUserDN, cacert, nonce, transid, keys, false, null, null, pAlg, new DEROctetString(nonce));
            assertNotNull("Generating CrmfRequest failed.", msg);
            extraCert = getCMPCert(cert);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(msg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(resp)).readObject());
            assertNotNull(respObject);
            
            body = respObject.getBody();
            int tag = body.getType();
            assertEquals(8, tag);
            CertRepMessage c = (CertRepMessage) body.getContent();
            assertNotNull(c);            
            CMPCertificate cmpcert = c.getResponse()[0].getCertifiedKeyPair().getCertOrEncCert().getCertificate();
            assertNotNull(cmpcert);
            X509Certificate cert2 = (X509Certificate) CertTools.getCertfromByteArray(cmpcert.getEncoded());
            assertNotNull("Failed to renew the certificate", cert2);
            
            assertEquals(CertTools.stringToBCDNString(testUserDN), CertTools.stringToBCDNString(cert2.getSubjectDN().getName()) );// CertTools.getSubjectDN(cert2) );
            assertEquals(issuerDN, CertTools.getIssuerDN(cert2));
            fingerprint2 = CertTools.getFingerprintAsString(cert2);
            
            //Send a revocation request
            msg = genRevReq(issuerDN, testUserDN, CertTools.getSerialNumber(cert2), cacert, nonce, transid, false, pAlg, null);
            assertNotNull("Generating CrmfRequest failed.", msg);
            extraCert = getCMPCert(cert2);
            msg = CmpMessageHelper.buildCertBasedPKIProtection(msg, extraCert, keys.getPrivate(), pAlg.getAlgorithm().getId(), "BC");
            assertNotNull(msg);

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(msg);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, testUserDN, cacert, msg.getHeader().getSenderNonce().getOctets(), msg.getHeader().getTransactionID()
                    .getOctets(), true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(issuerDN, CertTools.getSerialNumber(cert2));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
            
            
        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(ADMIN, testUIDUsername, ReasonFlags.unused);
                caSession.removeCA(ADMIN, CertTools.getIssuerDN(gppcacert).hashCode());
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
    public void test24EECAuthWithSHA256AndECDSA() throws Exception {
        log.trace(">test24EECAuthWithSHA256AndECDSA()");
        
        //-------------- Set the necessary configurations
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "ECDSAEEP");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ECDSACP");
        updatePropertyOnServer(CmpConfiguration.CONFIG_DEFAULTCA, "CmpECDSATestCA");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "CmpECDSATestCA");
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "CmpECDSATestCA");
        
       
        removeTestCA("CmpECDSATestCA");
        try{
            CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            int cryptoTokenId = cryptoTokenManagementSession.getIdFromName("CmpECDSATestCA");
            CryptoTokenManagementSessionTest.removeCryptoToken(ADMIN, cryptoTokenId);
        } catch(Exception e) {}
        
        
        //---------------------- Create the test CA
        // Create catoken
        
        String ecdsaCADN = "CN=CmpECDSATestCA";
        String keyspec = "prime256v1";
        
        int cryptoTokenId = CryptoTokenManagementSessionTest.createCryptoTokenForCA(null, "foo123".toCharArray(), true, false, ecdsaCADN, keyspec);
        final CAToken catoken = CaSessionTest.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<ExtendedCAServiceInfo>(2);
        extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedCaServices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        String caname = CertTools.getPartFromDN(ecdsaCADN, "CN");
        X509CAInfo ecdsaCaInfo = new X509CAInfo(ecdsaCADN, caname, CAConstants.CA_ACTIVE, new Date(), "", CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                3650, null, // Expiretime
                CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection<Certificate>) null, catoken, "JUnit RSA CA", -1, null, null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList<Integer>(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // Authority Information Access
                null, // defaultfreshestcrl
                true, // Finish User
                extendedCaServices, false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null // cmpRaAuthSecret
        );
        X509CA ecdsaCA = new X509CA(ecdsaCaInfo);
        ecdsaCA.setCAToken(catoken);
        // A CA certificate
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        
        final CryptoToken cryptoToken = CryptoTokenManagementSessionTest.getCryptoTokenFromServer(cryptoTokenId, "foo123".toCharArray());
        final PublicKey publicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        //final String keyalg = AlgorithmTools.getKeyAlgorithm(publicKey);
        String sigalg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
        final PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        X509Certificate ecdsaCaCert = CertTools.genSelfCertForPurpose(ecdsaCADN, 10L, "1.1.1.1", privateKey, publicKey, sigalg, true, keyusage);
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
            //log.debug("Added Certificate Profile 'GOSTCP'");
        } catch (CertificateProfileExistsException e) {
            //certProfileSession.changeCertificateProfile(ADMIN, "GOSTCP", cp);
            //log.debug("Certificate Profile 'GOSTCP' already exists. It has now been updated.");
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
            //log.debug("Added End Entity Profile 'GOSTEEP'");
        } catch (EndEntityProfileExistsException e) {
            //eeProfileSession.changeEndEntityProfile(ADMIN, "GOSTEEP", eep);
            //log.debug("End Entity Profile 'GOSTEEP' already exists. It has now been updated.");
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
        
            CMPCertificate extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), AlgorithmTools.getDigestFromSigAlg(pAlg.getAlgorithm().getId()), "BC");//CMSSignedGenerator.DIGEST_SHA256
            assertNotNull(req);
        
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200);
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
            resp = sendCmpHttp(ba, 200);
            
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
            resp = sendCmpHttp(barev, 200);
            checkCmpResponseGeneral(resp, ecdsaCaInfo.getSubjectDN(), userDN, ecdsaCaCert, nonce, transid, true, null, X9ObjectIdentifiers.ecdsa_with_SHA256.getId());
            int revStatus = checkRevokeStatus(ecdsaCaInfo.getSubjectDN(), CertTools.getSerialNumber(cert));
            assertNotSame("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
            
        } finally {
            removeAuthenticationToken(admToken, admCert, testAdminName);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, "cmpecdsauser", ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fp);
            internalCertStoreSession.removeCertificate(fp2);
            eeProfileSession.removeEndEntityProfile(ADMIN, "ECDSAEEP");
            certProfileSession.removeCertificateProfile(ADMIN, "ECDSATCP");
        }
        log.trace("<test24EECAuthWithSHA256AndECDSA()");

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
    public void test25EECAuthWithRSAandECDSA() throws Exception {
        log.trace(">test25EECAuthWithRSAandECDSA()");
        
        //-------------- Set the necessary configurations

        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "TestCA" );
        
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
        
            CMPCertificate extraCert = getCMPCert(admCert);
            req = CmpMessageHelper.buildCertBasedPKIProtection(req, extraCert, admkeys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1, "BC");
            assertNotNull(req);
        
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            fp2 = CertTools.getFingerprintAsString(cert);
        
        } finally {
            removeAuthenticationToken(admToken, admCert, testAdminName);
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, "cmpmixuser", ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fp);
            internalCertStoreSession.removeCertificate(fp2);
        }
        log.trace("<test25EECAuthWithRSAandECDSA()");
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
   
    private CMPCertificate getCMPCert(Certificate cert) throws CertificateEncodingException, IOException {
        ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
        ASN1Primitive pcert = ins.readObject();
        ins.close();
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance(pcert.toASN1Primitive());
        return new CMPCertificate(c);
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
    
    
    
    static byte[] gppCA = Base64.decode( ("MIICHDCCAYWgAwIBAgIId2qio28kX2EwDQYJKoZIhvcNAQEFBQAwHjEPMA0GA1UE" +
                                            "AwwGM0dQUENBMQswCQYDVQQGEwJTRTAeFw0xMzAxMTYxMTM4MjRaFw0xNDAxMTYx" +
                                            "MTM4MjRaMB4xDzANBgNVBAMMBjNHUFBDQTELMAkGA1UEBhMCU0UwgZ8wDQYJKoZI" +
                                            "hvcNAQEBBQADgY0AMIGJAoGBAIK2gGWwWJgcwvB8f83/VAcT3UOiQ1ThZXWetf33" +
                                            "rcldeMD/7Rydz6SIle0MrDgc9rda4ZdVN+0FJPvL8Q3hcGHUvJeyKGwyf7mJMc8D" +
                                            "P11qCajZElbmV5Axv8/+i8EZk71XrRLbz8uxSLp84hFe+RQkkJV8hrlV5S8sKGGl" +
                                            "ebfRAgMBAAGjYzBhMB0GA1UdDgQWBBSZ3XmLRWJOBIt8YUHCETSEdyk4+zAPBgNV" +
                                            "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFJndeYtFYk4Ei3xhQcIRNIR3KTj7MA4G" +
                                            "A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQAsnWEJVneEGwD33JQuSwAH" +
                                            "c9IT4S7ZM+jrN9ybrJQEV9+dlbfXG8ISdo0aC7RH94vEiVWN2vPcXv1kHcYDmCus" +
                                            "TB1QaZ/ERhO8SI9x6OHMZ9E4tsgytBsndFadfKKVpODgvXkB6x3/PV96AKz/gpjd" +
                                            "LYGWSWywpLuutYiiFb6a8w==").getBytes() );
    
    static byte[] gppuser = Base64.decode( ("MIICWzCCAcSgAwIBAgIIAxXKnyDArMYwDQYJKoZIhvcNAQEFBQAwHjEPMA0GA1UE" +
                                            "AwwGM0dQUENBMQswCQYDVQQGEwJTRTAeFw0xMzAxMTYxMTM0MzhaFw0xNDAxMTYx" +
                                            "MTM4MjRaMEExGzAZBgoJkiaJk/IsZAEBDAt1aWR1c2VybmFtZTEVMBMGA1UEAwwM" +
                                            "M2dwcHRlc3R1c2VyMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw" +
                                            "gYkCgYEA3mEpApioQ1liwNTvrABdwiieJ9AeImQr5VFoZFDv7NXyoRitMgSZJYNT" +
                                            "hv1ANPnOTSVpB49n/rVVaniAP+kvdYyZyY3jJUZunQeC6QsdQ+oAE2eTFTyvuJJS" +
                                            "6bXEertb+Smv9dF+c9NMwLC3KDU4KpO+P9sXim0pCHn2iOWtaWcCAwEAAaN/MH0w" +
                                            "HQYDVR0OBBYEFJw2zz8wmLbzSP1RHyu5X6/u2X30MAwGA1UdEwEB/wQCMAAwHwYD" +
                                            "VR0jBBgwFoAUmd15i0ViTgSLfGFBwhE0hHcpOPswDgYDVR0PAQH/BAQDAgXgMB0G" +
                                            "A1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDANBgkqhkiG9w0BAQUFAAOBgQAG" +
                                            "VYKkWoysnf999Hxh9jcOC34chJYX0LMqRLpioPEB2uSqDoZgUdpAOJlI/CxLmTJh" +
                                            "Z/vCqCjWM2CX1T/NmokD3Ea4A0m99y73VEZ4dWtzBi/tFu93XSQzwWXMSRKyYp0/" +
                                            "SQuEunEJEw76otrAzhCVs3tcKr/+h5F7nMQuOFh1EA==").getBytes() );
    
    static byte[] gppuserkey = Base64.decode( ("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN5hKQKYqENZYsDU" +
                                            "76wAXcIonifQHiJkK+VRaGRQ7+zV8qEYrTIEmSWDU4b9QDT5zk0laQePZ/61VWp4" +
                                            "gD/pL3WMmcmN4yVGbp0HgukLHUPqABNnkxU8r7iSUum1xHq7W/kpr/XRfnPTTMCw" +
                                            "tyg1OCqTvj/bF4ptKQh59ojlrWlnAgMBAAECgYEA2LBsOa9vJlFPPP9Am6WvtqXF" +
                                            "lp3g/zoE2+s7gaSsZWcEiZ12BqscX8Vb+smDaxuPvvSZJ1jByRwBI0JQFfau2lcg" +
                                            "7wqRgjr6Y1rQV6/PsVJLr8xa1iKUgxI9JCktvKu+DT4cHEFMtLlOpIA6niSZP0el" +
                                            "qiRBzvpsb06Ai4Ng8qECQQDx/CFXxXoIndClM1T6w7snioMapfFgaiq8Ch8c1qoM" +
                                            "H/fyAfISVqlpmTd6ELHHabjl9hOUDn+0BX2jX5zNYy2LAkEA60JYOv0EruR6560B" +
                                            "NsnOqiFGYO1zZ583MEGdNXStxSzthplWAEEFkwKdHhaJzW0QQxzhDJqMF+BdTYnQ" +
                                            "Qh+nFQJANk+FWEK9KfPpoTpNJ18IwU4oMLHv49jQMJYA96MCVWhTaOCg6RbEPSwj" +
                                            "NGVM0VncItjA+ijq5oeY9DMAaWSKEwJAE3s7+S6Im7752oN+DT5q6bW1sUMYgmUx" +
                                            "2cIlNY8C8MgGp1W9RGod/w2BW0N8h9FXPmd+z19g6H1A3LHj2AXs/QJAPCWj2EPX" +
                                            "ZSPn88/rmy8Rrs7owCGvl+v2jeRyDARHF5SVS/7v3pcc8qOxTdWgChS2wv1juvQR" +
                                            "IgUnBaZUk5bbtw==").getBytes() ); 

}
