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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA sends CMP messages authenticated using PBE (password based encryption)
 * and these requests are handled by EJBCA without further authentication, end entities are created automatically in EJBCA.
 * 
 * You need a CMP TCP listener configured on port 5587 to run this test. (cmp.tcp.enabled=true, cmp.tcp.portno=5587)
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @author tomas
 * @version $Id$
 */
public class CrmfRAPbeTcpRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRAPbeTcpRequestTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRAPbeTcpRequestTest"));

    private static final String PBEPASSWORD = "password";
    private static final String CPNAME = CrmfRAPbeTcpRequestTest.class.getName();
    private static final String EEPNAME = CrmfRAPbeTcpRequestTest.class.getName();

    /** userDN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations */
    private static String userDN = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest";

    private static String issuerDN = "CN=TestCA";
    private KeyPair keys = null;
    private static int caid = 0;
    private static X509Certificate cacert = null;
    private CA testx509ca;
    private CmpConfiguration cmpConfiguration;
    private String cmpAlias = "tcp";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    /**
     * This is the same constructor as in CrmtRAPbeRequestTest, but it's hard to refactor not to duplicate this code.
     * 
     */
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        caid = testx509ca.getCAId();
        cacert = (X509Certificate) testx509ca.getCACertificate();
        caSession.addCA(admin, testx509ca);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        
        configurationSession.backupConfiguration();
        
        // Configure CMP for this test
        if(cmpConfiguration.aliasExists(cmpAlias)) {
            cmpConfiguration.renameAlias(cmpAlias, "backupTcpAlias");
        }
        cmpConfiguration.addAlias(cmpAlias);
        cmpConfiguration.setRAMode(cmpAlias, true);
        cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        cmpConfiguration.setResponseProtection(cmpAlias, "pbe");
        cmpConfiguration.setRACertProfile(cmpAlias, CPNAME);
        cmpConfiguration.setRAEEProfile(cmpAlias, EEPNAME);
        cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;" + PBEPASSWORD);
        cmpConfiguration.setRACAName(cmpAlias, testx509ca.getName());
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
        
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and check "Allow validity override".
        if (certificateProfileSession.getCertificateProfile(CPNAME) == null) {
            CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp.setAllowValidityOverride(true);
            try { // TODO: Fix this better
                certificateProfileSession.addCertificateProfile(admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
            }
        }
        int cpId = certificateProfileSession.getCertificateProfileId(CPNAME);
        if (endEntityProfileSession.getEndEntityProfile(EEPNAME) == null) {
            // Configure an EndEntity profile (CmpRA) with allow CN, O, C in DN and rfc822Name (uncheck 'Use entity e-mail field' and check
            // 'Modifyable'), MS UPN in altNames in the end entity profile.
            EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
            try {
                endEntityProfileSession.addEndEntityProfile(admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }
        
        if (keys == null) {
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        }
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        boolean cleanUpOk = true;
        try {
            endEntityManagementSession.deleteUser(admin, "cmptest");
        } catch (NotFoundException e) {
            // A test probably failed before creating the entity
            log.error("Failed to delete user \"cmptest\".");
            cleanUpOk = false;
        }
        endEntityProfileSession.removeEndEntityProfile(admin, EEPNAME);
        certificateProfileSession.removeCertificateProfile(admin, CPNAME);
        
        if (!configurationSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, caid);
        
        assertTrue("Unable to clean up properly.", cleanUpOk);
        
        cmpConfiguration.removeAlias(cmpAlias);
        if(cmpConfiguration.aliasExists("backupTcpAlias")) {
            cmpConfiguration.renameAlias("backupTcpAlias", cmpAlias);
        }
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void test02CrmfTcpOkUser() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
        assertNotNull(req);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
        assertNotNull(cert);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

        // Now revoke the bastard using the CMPv2 CRL entry extension!
        PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid, true, null, null);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, true);
        int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
        assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);

    }


}
