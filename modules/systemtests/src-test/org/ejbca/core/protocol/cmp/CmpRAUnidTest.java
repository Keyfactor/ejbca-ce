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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.unidfnr.UnidFnrHandlerMock;
import org.ejbca.core.ejb.unidfnr.UnidfnrProxySessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * FNR is the Norwegian equivalent of a SSN or personal number, i.e, a unique numerical identifier for a Norwegian national. Norwegian regulation 
 * requires that the FNR is not unduly exposed, so hence during enrollment the FNR is replaced in the request with a generated unique ID (UnID), 
 * which will be used as reference for future OCSP requests, which for this purpose will contain the UnID as opposed to the FNR as an extension
 * in the response. 
 * 
 * The UnID <> FNR mapping is handled and lookup up from a separate datasource.
 */
public class CmpRAUnidTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpRAUnidTest.class);
    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpRAUnidTest"));

    private static final String PBEPASSWORD = "password";
    private static final String UNIDPREFIX = "1234-5678-";
    private static final String CPNAME = UNIDPREFIX + CmpRAUnidTest.class.getName();
    private static final String EEPNAME = UNIDPREFIX + CmpRAUnidTest.class.getName();

    /**
     * SUBJECT_DN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations
     */
    private static final String FNR = "90123456789";
    private static final String LRA = "01234";
    private static final String SUBJECT_SN = FNR + '-' + LRA;
    private static X500Name SUBJECT_DN;

    private static final String issuerDN = "CN=TestCA";
    private final KeyPair keys;
    private final X509Certificate cacert;
    private final X509CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private static final String configAlias = "CmpRAUnidTestCmpConfAlias";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final UnidfnrProxySessionRemote unidfnrProxySessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(UnidfnrProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);    

    @BeforeClass
    public static void beforeClass() {
        assumeTrue(enterpriseEjbBridgeSession.isRunningEnterprise());
        CryptoProviderTools.installBCProvider();
        // We must instantiate this after provider is installed as we set SN handling there 
        SUBJECT_DN = new X500Name("C=SE,SN=" + SUBJECT_SN + ",CN=unid-fnr");
    }

    public CmpRAUnidTest() throws Exception {
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        cacert = (X509Certificate) testx509ca.getCACertificate();
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        configurationSession.backupConfiguration();

        // Configure CMP for this test
        cmpConfiguration.addAlias(configAlias);
        cmpConfiguration.setRAMode(configAlias, true);
        cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        cmpConfiguration.setResponseProtection(configAlias, "pbe");
        cmpConfiguration.setRACertProfile(configAlias, CmpConfiguration.PROFILE_USE_KEYID);
        cmpConfiguration.setRAEEProfile(configAlias, CmpConfiguration.PROFILE_USE_KEYID);
        cmpConfiguration.setRACAName(configAlias, testx509ca.getName());
        cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(configAlias, "-;" + PBEPASSWORD);
  
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration);

        // Configure a Certificate profile (CmpRA) using ENDUSER as template
        if (certProfileSession.getCertificateProfile(CPNAME) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            try { // TODO: Fix this better
                certProfileSession.addCertificateProfile(admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                log.error("Certificate profile exists: ", e);
            }
        }
        final int cpId = certProfileSession.getCertificateProfileId(CPNAME);
        if (endEntityProfileSession.getEndEntityProfile(EEPNAME) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, Integer.toString(cpId));
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cpId));
            log.info("Set certificate profile (" + cpId + ") as available and default in EE profile");
            try {
                endEntityProfileSession.addEndEntityProfile(admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }

    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        endEntityProfileSession.removeEndEntityProfile(admin, EEPNAME);
        certProfileSession.removeCertificateProfile(admin, CPNAME);

        CaTestUtils.removeCa(admin, testx509ca.getCAInfo());

        assertTrue("Unable to clean up properly.", configurationSession.restoreConfiguration());
        cmpConfiguration.removeAlias(configAlias);
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration);
    }

    @Override
    public String getRoleName() {
        return getClass().getSimpleName();
    }

    @Override
    protected void checkDnIncludingAttributeOrder(X500Name expected, X500Name actual) {
        final ASN1ObjectIdentifier[] expectedOIDs = expected.getAttributeTypes();
        final ASN1ObjectIdentifier[] actualOIDs = actual.getAttributeTypes();
        assertEquals("Not the expected number of elements in the created certificate.", expectedOIDs.length, actualOIDs.length);
        String expectedValue, actualValue;
        for (int i = 0; i < expectedOIDs.length; i++) {
            final ASN1ObjectIdentifier oid = expectedOIDs[i];
            expectedValue = expected.getRDNs(oid)[0].getFirst().getValue().toString();
            actualValue = actual.getRDNs(oid)[0].getFirst().getValue().toString();
            if (!oid.equals(BCStyle.SERIALNUMBER)) {
                log.debug("Check that " + oid.getId() + " is OK. Expected '" + expectedValue + "'. Actual '" + actualValue + "'.");
                assertEquals("Not expected " + oid, expectedValue, actualValue);
                continue;
            }
            log.debug("Special handling of the SN " + oid.getId() + ". Input '" + expectedValue + "'. Transformed '" + actualValue + "'.");
            final String expectedSNPrefix = UNIDPREFIX + LRA;
            final String actualSNPrefix = actualValue.substring(0, expectedSNPrefix.length());
            assertEquals("New serial number prefix not as expected.", expectedSNPrefix, actualSNPrefix);
            final String actualSNRandom = actualValue.substring(expectedSNPrefix.length());
            assertTrue("Random in serial number not OK: " + actualSNRandom, Pattern.compile("^\\w{6}$").matcher(actualSNRandom).matches());
        }
    }

    /**
     * This system test will attempt to enroll a certificate over CMP, with the UnIDFNR plugin enabled. This will result in the FNR value in the final certificate
     * being replaced with the UnID by manipulating the request, and verifies that the mapping has been created in the unid datasource.
     * 
     */
    @Test
    public void testCmpEnrollment() throws Exception {
        //For the purposes of this system test, use UnidFnrHandlerMock instead of UnidFnrHandler. It's essentially the same but isn't
        //reliant on the existence of a data source. 
        X509CAInfo testX509CaInfo = (X509CAInfo) testx509ca.getCAInfo();
        testX509CaInfo.setRequestPreProcessor(UnidFnrHandlerMock.class.getCanonicalName());
        testx509ca.updateCA(null, testX509CaInfo, null);
        caSession.addCA(admin, testx509ca);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        final String unid;
        // In this test SUBJECT_DN contains special, escaped characters to verify
        // that that works with CMP RA as well
        final PKIMessage one = genCertReq(issuerDN, SUBJECT_DN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, CPNAME, 567);
        assertNotNull(req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        // Send request and receive response
        byte[] resp = sendCmpHttp(encodePKIMessage(req), 200, configAlias);
        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            PKIBody body = respObject.getBody();
            if (body.getContent() instanceof ErrorMsgContent) {
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                log.error(errMsg);
                fail("CMP ErrorMsg received: " + errMsg);
                unid = null;
            } else {
                checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, cacert, nonce, transid, false, PBEPASSWORD,
                        PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
                final X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, configAlias, SUBJECT_DN, cacert, resp, reqId);
                final X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
                unid = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());
                log.debug("Unid received in certificate response: " + unid);
            }
        } finally {
            inputStream.close();
        }
        
        String fnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(unid);
        assertNotNull("Unid value was not stored", fnr);
        assertEquals("FNR value was not correctly converted", FNR, fnr);
        // Send a confirm message to the CA
        final String hash = "foo123";
        final PKIMessage confirm = genCertConfirm(SUBJECT_DN, cacert, nonce, transid, hash, reqId, null);
        assertNotNull(confirm);
        final PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, CPNAME, 567);
        
        // Send request and receive response
        resp = sendCmpHttp(encodePKIMessage(req1), 200, configAlias);
        checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, cacert, nonce, transid, false, PBEPASSWORD,
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
        checkCmpPKIConfirmMessage(SUBJECT_DN, cacert, resp);

    }
    
    /**
     * Test enrollment using the legacy configuration in the CMP alias in order to make sure that the upgrade still works
     * 
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testCmpEnrollmentLegacy() throws Exception {
        //Set the deprecated value here in order to test that the legacy enrollment method still works
        cmpConfiguration.setCertReqHandlerClass(configAlias, UnidFnrHandlerMock.class.getName());
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration);

        //For the purposes of this system test, use UnidFnrHandlerMock instead of UnidFnrHandler. It's essentially the same but isn't
        //reliant on the existence of a data source. 
        caSession.addCA(admin, testx509ca);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        final String unid;
        // In this test SUBJECT_DN contains special, escaped characters to verify
        // that that works with CMP RA as well
        final PKIMessage one = genCertReq(issuerDN, SUBJECT_DN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, CPNAME, 567);
        assertNotNull(req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        // Send request and receive response
        byte[] resp = sendCmpHttp(encodePKIMessage(req), 200, configAlias);
        ASN1InputStream inputStream = new ASN1InputStream(new ByteArrayInputStream(resp));
        try {
            PKIMessage respObject = PKIMessage.getInstance(inputStream.readObject());
            PKIBody body = respObject.getBody();
            if (body.getContent() instanceof ErrorMsgContent) {
                ErrorMsgContent err = (ErrorMsgContent) body.getContent();
                String errMsg = err.getPKIStatusInfo().getStatusString().getStringAt(0).getString();
                log.error(errMsg);
                fail("CMP ErrorMsg received: " + errMsg);
                unid = null;
            } else {
                checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, cacert, nonce, transid, false, PBEPASSWORD,
                        PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
                final X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, configAlias, SUBJECT_DN, cacert, resp, reqId);
                final X500Name x500Name = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
                unid = IETFUtils.valueToString(x500Name.getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue());

                log.debug("Unid received in certificate response: " + unid);
            }
        } finally {
            inputStream.close();
        }
        
        String fnr = unidfnrProxySessionRemote.fetchUnidFnrDataFromMock(unid);
        assertNotNull("Unid value was not stored", fnr);
        assertEquals("FNR value was not correctly converted", FNR, fnr);
        // Send a confirm message to the CA
        final String hash = "foo123";
        final PKIMessage confirm = genCertConfirm(SUBJECT_DN, cacert, nonce, transid, hash, reqId, null);
        assertNotNull(confirm);
        final PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, CPNAME, 567);
        
        // Send request and receive response
        resp = sendCmpHttp(encodePKIMessage(req1), 200, configAlias);
        checkCmpResponseGeneral(resp, CmpRAUnidTest.issuerDN, SUBJECT_DN, cacert, nonce, transid, false, PBEPASSWORD,
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
        checkCmpPKIConfirmMessage(SUBJECT_DN, cacert, resp);

    }
    
    private byte[] encodePKIMessage(final PKIMessage request) {
        final ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        try {
            out.writeObject(request);
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode PKIMessage.", e);
        }
        return bao.toByteArray();
    }

}
