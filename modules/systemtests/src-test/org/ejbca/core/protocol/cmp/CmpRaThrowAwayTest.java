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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistoryProxySessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verify that CMP functionality works in RA mode, when any combination of - useCertReqHistory (Store copy of UserData at the time of certificate
 * issuance.) - useUserStorage (Store current UserData.) - useCertificateStorage (Store issued certificates and related information.) are used.
 * 
 * @version $Id$
 */
public class CmpRaThrowAwayTest extends CmpTestCase {

    private static final Logger LOG = Logger.getLogger(CmpRAAuthenticationTest.class);
    private static final Random RND = new SecureRandom();

    private static final String TESTCA_NAME = "CmpRaThrowAwayTestCA";
    private static final String CERTPROFILE_NAME = "CmpRaThrowAwayTest";
    private static final String EEPROFILE_NAME = "CmpRaThrowAwayTest";
    private static final String PBE_SECRET = "password";

    private X509Certificate caCertificate;
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final CertReqHistoryProxySessionRemote csrHistorySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private CmpConfiguration cmpConfiguration;
    private final static String configAlias = "CmpRaThrowAwayTestCmpConfigAlias";

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA(TESTCA_NAME); // Create test CA
    }

    @AfterClass
    public static void afterClass() throws Exception {
        try {
            removeTestCA(TESTCA_NAME);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    /** Create CA and change configuration for the following tests. */
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        LOG.trace(">test000Setup");
        final CAInfo caInfo = caSession.getCAInfo(ADMIN, getTestCAId(TESTCA_NAME));
        this.caCertificate = (X509Certificate) caInfo.getCertificateChain().iterator().next();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        reconfigureCA(false, true, true);
        assertCAConfig(false, true, true);
        // Setup a certificate profile to be able to test override
        certificateProfileSession.removeCertificateProfile(ADMIN, CERTPROFILE_NAME);
        certificateProfileSession.cloneCertificateProfile(ADMIN, CertificateProfile.ENDUSERPROFILENAME, CERTPROFILE_NAME, null);
        reconfigureCertificateProfile(false, false);
        endEntityProfileSession.removeEndEntityProfile(ADMIN, EEPROFILE_NAME);
        final EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.addField(DnComponents.ORGANIZATION);
        endEntityProfile.addField(DnComponents.ORGANIZATIONALUNIT);
        endEntityProfile.addField(DnComponents.COUNTRY);
        endEntityProfile.addField(DnComponents.RFC822NAME);
        endEntityProfile.addField(DnComponents.UPN);
        endEntityProfile.setAvailableCAs(Arrays.asList(caInfo.getCAId()));
        endEntityProfile.setAvailableCertificateProfileIds(Arrays.asList(certificateProfileSession.getCertificateProfileId(CERTPROFILE_NAME)));
        endEntityProfileSession.addEndEntityProfile(ADMIN, EEPROFILE_NAME, endEntityProfile);
        assertNotNull("Failed to create end entity profile.", endEntityProfileSession.getEndEntityProfile(EEPROFILE_NAME));
        final int eepId = endEntityProfileSession.getEndEntityProfileId(EEPROFILE_NAME);
        
        // Configure CMP for this test. RA mode with individual shared PBE secrets for each CA.
        this.cmpConfiguration.addAlias(configAlias);
        this.cmpConfiguration.setRAMode(configAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        this.cmpConfiguration.setResponseProtection(configAlias, "pbe");
        this.cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        this.cmpConfiguration.setRANameGenParams(configAlias, "CN");
        this.cmpConfiguration.setRAEEProfile(configAlias, String.valueOf(eepId));
        this.cmpConfiguration.setRACertProfile(configAlias, CERTPROFILE_NAME);
        this.cmpConfiguration.setRACAName(configAlias, TESTCA_NAME);
        this.cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(configAlias, "-;" + PBE_SECRET);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        LOG.trace("<test000Setup");
    }
    
    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        LOG.trace(">testZZZTearDown");
        try {
            endEntityProfileSession.removeEndEntityProfile(ADMIN, EEPROFILE_NAME);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        try {
            certificateProfileSession.removeCertificateProfile(ADMIN, CERTPROFILE_NAME);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        try {
            this.cmpConfiguration.removeAlias(configAlias);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        LOG.trace("<testZZZTearDown");
    }

    @Test
    public void testIssueConfirmRevokeCombination1() throws Exception {
        LOG.trace(">testIssueConfirmRevokeCombination1");
        // Run through all possible configurations of what to store in the database
        for (int i = 0; i <= 7; i++) {
            boolean useCertReqHistory = (i & 1) != 0; // Bit 0
            boolean useUserStorage = (i & 2) != 0; // Bit 1
            boolean useCertificateStorage = (i & 4) != 0; // Bit 2
            reconfigureCA(useCertReqHistory, useUserStorage, useCertificateStorage);
            testIssueConfirmRevoke(useCertReqHistory, useUserStorage, useCertificateStorage);
        }
        LOG.trace("<testIssueConfirmRevokeCombination1");
    }


    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    /**
     * Sends a certificate request message and verifies result. Sends a confirm message and verifies result. Sends a revocation message and verifies
     * result. (If we save certificate data!)
     */
    private void testIssueConfirmRevoke(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws Exception {
        LOG.trace(">testIssueConfirmRevoke");
        LOG.info("useCertReqHistory=" + useCertReqHistory + " useUserStorage=" + useUserStorage + " useCertificateStorage=" + useCertificateStorage);
        // Generate and send certificate request
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        Date notBefore = new Date();
        Date notAfter = new Date(new Date().getTime() + 24 * 3600 * 1000);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        String username = "cmpRaThrowAwayTestUser" + RND.nextLong(); // This is what we expect from the CMP configuration
        final X500Name subjectDN = new X500Name("CN=" + username);
        PKIMessage one = genCertReq(CertTools.getSubjectDN(this.caCertificate), subjectDN, keys, this.caCertificate, nonce, transid, true, null, notBefore,
                notAfter, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBE_SECRET, "unusedKeyId", 567);
        assertNotNull("Request was not created properly.", req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req);
        byte[] resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(subjectDN, this.caCertificate, resp, reqId);
        assertTrue(
                "Certificate history data was or wasn't stored: ",
                useCertReqHistory ==
                (this.csrHistorySession.retrieveCertReqHistory(CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert)) != null)
                );
        assertTrue("User data was or wasn't stored: ", useUserStorage == this.endEntityManagementSession.existsUser(username));
        assertTrue(
                "Certificate data was or wasn't stored: ",
                useCertificateStorage == (this.certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) != null));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, this.caCertificate, nonce, transid, hash, reqId);
        assertNotNull("Could not create confirmation message.", confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBE_SECRET, "unusedKeyId", 567);
        bao = new ByteArrayOutputStream();
        new DEROutputStream(bao).writeObject(req1);
        resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
        checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(subjectDN, this.caCertificate, resp);

        // We only expect revocation to work if we store certificate data and user data
        // TODO: ECA-1916 should remove dependency on useUserStorage
        if (useCertificateStorage && useUserStorage) {
            // Now revoke the bastard using the CMPv1 reason code!
            PKIMessage rev = genRevReq(CertTools.getSubjectDN(this.caCertificate), subjectDN, cert.getSerialNumber(), this.caCertificate, nonce, transid, false, null, null);
            PKIMessage revReq = protectPKIMessage(rev, false, PBE_SECRET, "unusedKeyId", 567);
            assertNotNull("Could not create revocation message.", revReq);
            bao = new ByteArrayOutputStream();
            new DEROutputStream(bao).writeObject(revReq);
            resp = sendCmpHttp(bao.toByteArray(), 200, configAlias);
            checkCmpResponseGeneral(resp, CertTools.getSubjectDN(this.caCertificate), subjectDN, this.caCertificate, nonce, transid, false, PBE_SECRET, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpRevokeConfirmMessage(CertTools.getSubjectDN(this.caCertificate), subjectDN, cert.getSerialNumber(), this.caCertificate, resp, true);
            int reason = this.certificateStoreSession.getStatus(CertTools.getSubjectDN(this.caCertificate), cert.getSerialNumber()).revocationReason;
            assertEquals("Certificate was not revoked with the right reason.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, reason);
        }
        // Clean up what we can
        if (useUserStorage) {
            this.endEntityManagementSession.deleteUser(ADMIN, username);
        }
        if (useCertReqHistory) {
            this.csrHistorySession.removeCertReqHistoryData(CertTools.getFingerprintAsString(cert));
        }
        LOG.trace("<testIssueConfirmRevoke");
    }

    @Test
    public void testLegacyEncodedRequestOverride() throws Exception {
        reconfigureCA(false, false, false);
        // Setup "Allow subject DN override" and "Allow certificate serial number override" in used cert profile
        reconfigureCertificateProfile(true, true);
        final String issuerDn = CertTools.getSubjectDN(getTestCACert(TESTCA_NAME));
        final X500Name issuerX500Name = new X500Name(issuerDn);
        final org.bouncycastle.asn1.crmf.CertTemplateBuilder certTemplate = new org.bouncycastle.asn1.crmf.CertTemplateBuilder();
        certTemplate.setIssuer(issuerX500Name);
        final KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final String serialNumber = "88883311121333FF33012345";
        final byte[] transactionId = new byte[16];
        final byte[] senderNonce = new byte[16];
        final Random random = new Random();
        random.nextBytes(transactionId);
        random.nextBytes(senderNonce);
        final String subjectDn = "C=SE,O=PrimeKey,OU=Labs,CN=Sec_"+serialNumber;
        final X500Name subjectX500Name = CertTools.stringToBcX500Name(subjectDn, new TeletexNamingStyle(), false);
        certTemplate.setSubject(subjectX500Name);
        final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        certTemplate.setPublicKey(keyInfo);
        // Request a custom certificate serial number
        certTemplate.setSerialNumber(new ASN1Integer(new BigInteger(serialNumber, 16)));
        final org.bouncycastle.asn1.crmf.ProofOfPossession myProofOfPossession = new org.bouncycastle.asn1.crmf.ProofOfPossession();
        final CertRequest certRequest = new CertRequest(4, certTemplate.build(), null);
        final AttributeTypeAndValue[] avs = { new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String(PBE_SECRET)) };
        final CertReqMsg certReqMsg = new CertReqMsg(certRequest, myProofOfPossession, avs);
        final CertReqMessages certReqMessages = new CertReqMessages(certReqMsg);
        PKIHeaderBuilder pkiHeader = new PKIHeaderBuilder(2, new GeneralName(subjectX500Name), new GeneralName(new X500Name(issuerDn)));
        pkiHeader.setMessageTime(new ASN1GeneralizedTime(new Date()));
        pkiHeader.setSenderNonce(new DEROctetString(senderNonce));
        pkiHeader.setTransactionID(new DEROctetString(transactionId));
        pkiHeader.setProtectionAlg(null);
        final DEROctetString senderKID = null;
        pkiHeader.setSenderKID(senderKID);
        final PKIBody pkiBody = new PKIBody(0, certReqMessages);
        final PKIMessage pkiMessage = new PKIMessage(pkiHeader.build(), pkiBody);
        final PKIMessage req = protectPKIMessage(pkiMessage, false, PBE_SECRET, "unusedKeyId", 567);
        assertNotNull("Request was not created properly.", req);
        final CertReqMessages initializationRequest = (CertReqMessages) req.getBody().getContent();
        final int requestId = initializationRequest.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        final byte[] reqBytes = req.getEncoded();
        final byte[] cmpResponse = sendCmpHttp(reqBytes, 200, configAlias);
        final X509Certificate cert = checkCmpCertRepMessage(subjectX500Name, this.caCertificate, cmpResponse, requestId);
        LOG.debug("Request:\n" + new String(CertTools.getPEMFromCertificateRequest(certRequest.getEncoded())));
        LOG.debug("Result:\n" + new String(CertTools.getPemFromCertificateChain(new ArrayList<Certificate>(Arrays.asList(cert)))));
        final byte[] requestSubjectyX500Principal = cert.getSubjectX500Principal().getEncoded();
        final byte[] responeSubjectyX500Principal = subjectX500Name.getEncoded();
        assertTrue("Requested X500Name was not returned the same way as requested.", Arrays.equals(requestSubjectyX500Principal, responeSubjectyX500Principal));
        // We cannot assume that the unique serial number index is enabled, and hence we cant be sure that our serial number override was allowed, but at least we can print it
        LOG.info("Requested serial number: "+ serialNumber);
        LOG.info("Response serial number:  "+ CertTools.getSerialNumberAsString(cert));
    }
    
    /** Assert that the CA is configured to store things as expected. 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException */
    private static void assertCAConfig(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws CADoesntExistsException, AuthorizationDeniedException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        assertTrue("CA has wrong useCertReqHistory setting: ", useCertReqHistory == caInfo.isUseCertReqHistory());
        assertTrue("CA has wrong useUserStorage setting: ", useUserStorage == caInfo.isUseUserStorage());
        assertTrue("CA has wrong useCertificateStorage setting: ", useCertificateStorage == caInfo.isUseCertificateStorage());
    }

    /** Change CA configuration for what to store and assert that the changes were made. 
     * @throws CADoesntExistsException */
    private static void reconfigureCA(boolean useCertReqHistory, boolean useUserStorage, boolean useCertificateStorage) throws AuthorizationDeniedException, CADoesntExistsException {
        CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(ADMIN, TESTCA_NAME);
        caInfo.setUseCertReqHistory(useCertReqHistory);
        caInfo.setUseUserStorage(useUserStorage);
        caInfo.setUseCertificateStorage(useCertificateStorage);
        // We can not enforce unique subjectDN for issued certificates when we do not store certificates
        caInfo.setDoEnforceUniqueDistinguishedName(false);
        // We can not enforce unique subject public keys for issued certificates when we do not store certificates        
        caInfo.setDoEnforceUniquePublicKeys(false);
        assertTrue("CAInfo did not store useCertReqHistory setting correctly: ", useCertReqHistory == caInfo.isUseCertReqHistory());
        assertTrue("CAInfo did not store useUserStorage setting correctly: ", useUserStorage == caInfo.isUseUserStorage());
        assertTrue("CAInfo did not store useCertificateStorage setting correctly: ", useCertificateStorage == caInfo.isUseCertificateStorage());
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(ADMIN, caInfo);
        assertCAConfig(useCertReqHistory, useUserStorage, useCertificateStorage);
    }

    private void reconfigureCertificateProfile(final boolean allowDNOverride, final boolean allowCertSerialNumberOverride) throws AuthorizationDeniedException {
        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(CERTPROFILE_NAME);
        certificateProfile.setAllowDNOverride(allowDNOverride);
        certificateProfile.setAllowCertSerialNumberOverride(allowCertSerialNumberOverride);
        certificateProfileSession.changeCertificateProfile(ADMIN, CERTPROFILE_NAME, certificateProfile);
    }

    /** Legacy teletex encoding for testing purpose. */
    private class TeletexNamingStyle extends BCStyle {

        static final String DER_PRINTABLE_STRING_WHITELIST = " \\()+-.:=?";

        @Override 
        public ASN1Encodable stringToValue(final ASN1ObjectIdentifier oid, final String value) {
            if (value.length() != 0 && value.charAt(0) == '#') {
                try {
                    return new ASN1InputStream(Hex.decode(value.substring(1))).readObject();
                } catch (IOException e) {
                    throw new RuntimeException("Unable to recode value for oid " + oid.getId());
                }
            } else if (oid.equals(BCStyle.EmailAddress) || oid.equals(BCStyle.DC)) {
                return new DERIA5String(value);
            } else if (canBePrintable(value)) {
                return new DERPrintableString(value);
            }
            return new DERT61String(value);
        }
        
        protected boolean canBePrintable(final String value) {
            for (final char current : value.toCharArray()) {
                if (current > 0x007f) {
                    return false;
                }
                if (('a' <= current && current <= 'z') || ('A' <= current && current <= 'Z') || ('0' <= current && current <= '9')) {
                    continue;
                }
                if (DER_PRINTABLE_STRING_WHITELIST.indexOf(current)!=-1) {
                    continue;
                }
                return false;
            }
            return true;
        }
    }
}
