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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This test requires:
 * cmp.operationmode=ra, cmp.allowraverifypopo=true, cmp.responseProtection=pbe
 * cmp.ra.authenticationsecret=password, cmp.ra.namegenerationscheme=DN
 * cmp.ra.endentityprofile=KeyId, cmp.ra.certificateprofile=KeyId, cmp.ra.caname=ProfileDefault
 * 
 * You need a CMP tcp listener configured on port 5587.
 * 
 * Two CAs: CmpCA1 with DN "CN=CmpCA1,O=EJBCA Sample,C=SE"
 *          CmpCA2 with DN "CN=CmpCA2,O=EJBCA Sample,C=SE"
 *          
 * There must be four end entity profiles and four certificate profiles.
 * 
 * All certificate profiles must have "AllowDNOverride" set.
 * Cert Profile with name KeyId1 must have key usage "digital signature", non-overridable
 * Cert Profile with name KeyId2 must have key usage "non repudiation", non-overridable
 * Cert Profile with name KeyId3 must have key usage "key encipherment", overridable
 * Cert Profile with name KeyId4 must be the same as KeyId2, but have "Allow Extension Override".
 * 
 * EE Profile with name KeyId1 must have a fixed, non-modifiable C=SE, an O, a CN and be using certProfile KeyId1
 * EE Profile with name KeyId1 must have a modifyable rfc822Name and UPN field allowed in subjectAltNames 
 * EE Profile with name KeyId1 must have default CA with name CmpCA1
 * 
 * EE Profile with name KeyId2 must have a fixed, non-modifiable C=NO, an O, a CN  and be using certProfile KeyId2
 * EE Profile with name KeyId2 must have modifyable rfc822Name and MS UPN field allowed in subjectAltNames 
 * EE Profile with name KeyId2 must have default CA with name CmpCA2
 * 
 * EE Profile with name KeyId3 must have a fixed, non-modifiable C=NO, an O, a CN  and be using certProfile KeyId3
 * EE Profile with name KeyId3 must have modifyable rfc822Name and MS UPN field allowed in subjectAltNames 
 * EE Profile with name KeyId3 must have default CA with name CmpCA2 
 * (use entity profile KeyId2 as template for KeyId3)
 * 
 * EE Profile with name KeyId4 should be the same as KeyId3, but use certProfile KeyId4
 * (use entity profile KeyId3 as template for KeyId4)
 * 
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class CrmfRAPbeMultipleKeyIdRequestTest extends CmpTestCase {
	
    private static final Logger log = Logger.getLogger(CrmfRAPbeMultipleKeyIdRequestTest.class);

    private static final String PBEPASSWORD = "password";
    
    final private static X500Name userDN1 = new X500Name("C=SE,O=PrimeKey,CN=cmptestKeyId1");
    final private static X500Name userDN2 = new X500Name("C=NO,O=PrimeKey,CN=cmptestKeyId2");
    final private String issuerDN1;
    final private String issuerDN2;
    final private KeyPair keys;
    final private CmpConfiguration cmpConfiguration;
    final private static String configAlias = "tcp";

    final private int caid1;
    final private int caid2;
    final private Certificate cacert1;
    final private Certificate cacert2;
    
    final private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    final private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfRAPbeMultipleKeyIdRequestTest() throws Exception {
        CAInfo adminca1 = this.caSession.getCAInfo(ADMIN, "CmpCA1");
        this.caid1 = adminca1.getCAId();
        CAInfo adminca2 = this.caSession.getCAInfo(ADMIN, "CmpCA2");
        this.caid2 = adminca2.getCAId();

        CAInfo cainfo = this.caSession.getCAInfo(ADMIN, this.caid1);
        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                this.cacert1 = CertTools.getCertfromByteArray(cert.getEncoded());
            } else {
                this.cacert1 = null;
            }
        } else {
            log.error("NO CACERT for CmpCA1: " + this.caid1);
            this.cacert1 = null;
        }
        cainfo = this.caSession.getCAInfo(ADMIN, this.caid2);
        certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                this.cacert2 = CertTools.getCertfromByteArray(cert.getEncoded());
            } else {
                this.cacert2 = null;
            }
        } else {
            log.error("NO CACERT for CmpCA2: " + this.caid2);
            this.cacert2 = null;
        }

        if ( this.cacert1==null || this.cacert2==null ) {
            throw new Exception("CAs not set up properly.");
        }
        this.issuerDN1 = CertTools.getSubjectDN(this.cacert1);
        this.issuerDN2 = CertTools.getSubjectDN(this.cacert2);
            this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        this.cmpConfiguration = (CmpConfiguration) this.globalConfigSession.getCachedConfiguration(Configuration.CMPConfigID);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
     // Try to get caIds
        if ((this.caid1 == 0) || (this.caid2 == 0)) {
            assertTrue("No active CA! Must have CmpCA1 and CmpCA2 to run tests!", false);
        }

        if(this.cmpConfiguration.aliasExists(configAlias)) {
            this.cmpConfiguration.renameAlias(configAlias, "backupTcpAlias");
        }
        this.cmpConfiguration.addAlias(configAlias);
        this.cmpConfiguration.setRAMode(configAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(configAlias, true);
        this.cmpConfiguration.setResponseProtection(configAlias, "pbe");
        this.cmpConfiguration.setAuthenticationModule(configAlias, CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(configAlias, "password");
        this.cmpConfiguration.setRANameGenScheme(configAlias, "DN");
        this.cmpConfiguration.setRAEEProfile(configAlias, "KeyId");
        this.cmpConfiguration.setRACertProfile(configAlias, "KeyId");
        this.cmpConfiguration.setRACAName(configAlias, "ProfileDefault");
        updatePropertyOnServer("cmp.tcp.portno", "5587");
        this.globalConfigSession.saveConfiguration(ADMIN, this.cmpConfiguration, Configuration.CMPConfigID);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        final String user1 = userDN1.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        //String user1 = CertTools.getPartFromDN(userDN1, "CN");
        final String user2 = userDN2.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        //String user2 = CertTools.getPartFromDN(userDN2, "CN");
        try {
            this.endEntityManagementSession.deleteUser(ADMIN, user1);
            this.endEntityManagementSession.deleteUser(ADMIN, user2);
        } catch (Exception e) {
            // Ignore errors
        }
        
        this.cmpConfiguration.removeAlias(configAlias);
        if(this.cmpConfiguration.aliasExists("backupTcpAlias")) {
            this.cmpConfiguration.renameAlias("backupTcpAlias", configAlias);
        }
        this.globalConfigSession.saveConfiguration(ADMIN, this.cmpConfiguration, Configuration.CMPConfigID);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void test01CrmfHttpOkUserWrongKeyId() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // A message with the KeyId "foobarfoobar" should not be known by this
        PKIMessage one = genCertReq(this.issuerDN1, userDN1, this.keys, this.cacert1, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "foobarfoobar", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, configAlias);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        // We'll get back an InitializationResponse (but a reject) with FailInfo.BAD_REQUEST
        checkCmpFailMessage(resp, "End entity profile with name 'foobarfoobar' not found.", 1, reqId, 2, PKIFailureInfo.incorrectData);
    }


    @Test
    public void test02CrmfHttpOkUserKeyId1() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(this.issuerDN1, userDN1, this.keys, this.cacert1, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId1", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN1, this.cacert1, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Check key usage that it is digitalSignature for KeyId1 and
        // nonRepudiation for KeyId2
        boolean[] ku = cert.getKeyUsage();
        assertTrue(ku[0]);
        assertFalse(ku[1]);
        assertFalse(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        assertFalse(ku[8]);
        // Check DN that must be SE for KeyId1
        assertEquals("SE", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN1, this.cacert1, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN1, this.cacert1, resp);

        // Now revoke the bastard!
        PKIMessage rev = genRevReq(this.issuerDN1, userDN1, cert.getSerialNumber(), this.cacert1, nonce, transid, true, null, null);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpRevokeConfirmMessage(this.issuerDN1, userDN1, cert.getSerialNumber(), this.cacert1, resp, true);
        int reason = checkRevokeStatus(this.issuerDN1, cert.getSerialNumber());
        assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);

        // Create a revocation request for a non existing cert, chould fail!
        rev = genRevReq(this.issuerDN1, userDN1, new BigInteger("1"), this.cacert1, nonce, transid, true, null, null);
        revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpRevokeConfirmMessage(this.issuerDN1, userDN1, cert.getSerialNumber(), this.cacert1, resp, false);

    }

    @Test
    public void test03CrmfTcpOkUserKeyId1() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(this.issuerDN1, userDN1, this.keys, this.cacert1, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId1", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN1, this.cacert1, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Check key usage that it is digitalSignature for KeyId1 and
        // nonRepudiation for KeyId2
        boolean[] ku = cert.getKeyUsage();
        assertTrue(ku[0]);
        assertFalse(ku[1]);
        assertFalse(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        assertFalse(ku[8]);
        // Check DN that must be SE for KeyId1
        assertEquals("SE", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN1, this.cacert1, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN1, userDN1, this.cacert1, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN1, this.cacert1, resp);
    }

    @Test
    public void test04CrmfTcpOkUserKeyId2() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(this.issuerDN2, userDN2, this.keys, this.cacert2, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId2", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN2, this.cacert2, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Check key usage that it is digitalSignature for KeyId1 and
        // nonRepudiation for KeyId2
        boolean[] ku = cert.getKeyUsage();
        assertFalse(ku[0]);
        assertTrue(ku[1]);
        assertFalse(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        assertFalse(ku[8]);
        // Check DN that must be SE for KeyId1 and NO for KeyId2
        assertEquals("NO", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN2, this.cacert2, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN2, this.cacert2, resp);
    }

    @Test
    public void test05CrmfHttpOkUserKeyId2() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(this.issuerDN2, userDN2, this.keys, this.cacert2, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId2", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN2, this.cacert2, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Check key usage that it is digitalSignature for KeyId1 and
        // nonRepudiation for KeyId2
        boolean[] ku = cert.getKeyUsage();
        assertFalse(ku[0]);
        assertTrue(ku[1]);
        assertFalse(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        assertFalse(ku[8]);
        // Check DN that must be SE for KeyId1 and NO for KeyId2
        assertEquals("NO", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN2, this.cacert2, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN2, this.cacert2, resp);

        // Now revoke the bastard!
        PKIMessage rev = genRevReq(this.issuerDN2, userDN2, cert.getSerialNumber(), this.cacert2, nonce, transid, true, null, null);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, configAlias);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpRevokeConfirmMessage(this.issuerDN2, userDN2, cert.getSerialNumber(), this.cacert2, resp, true);
        int reason = checkRevokeStatus(this.issuerDN2, cert.getSerialNumber());
        assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION);
    }

    @Test
    public void test06CrmfTcpOkUserKeyId3() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(this.issuerDN2, userDN2, this.keys, this.cacert2, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId3", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN2, this.cacert2, resp, reqId);
        // FileOutputStream fos = new FileOutputStream("/home/tomas/foo.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Check key usage that it is digitalSignature, keyEncipherment and
        // nonRepudiation for KeyId3
        // Because keyUsage for keyId3 should be taken from the request (see
        // genCertReq)
        boolean[] ku = cert.getKeyUsage();
        assertTrue(ku[0]);
        assertTrue(ku[1]);
        assertTrue(ku[2]);
        assertFalse(ku[3]);
        assertFalse(ku[4]);
        assertFalse(ku[5]);
        assertFalse(ku[6]);
        assertFalse(ku[7]);
        assertFalse(ku[8]);
        // Check DN that must be SE for KeyId1 and NO for KeyId2
        assertEquals("NO", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN2, this.cacert2, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN2, this.cacert2, resp);
    } // test06CrmfTcpOkUserKeyId3

    @Test
    public void test07ExtensionOverride() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Create some crazy extensions to see that we get them when using
        // extension override.
        // We should not get our values when not using extension override
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        // SubjectAltName
        GeneralNames san = CertTools.getGeneralNamesFromAltName("dnsName=foo.bar.com");
        extgen.addExtension(Extension.subjectAlternativeName, false, san);
        // KeyUsage
        int bcku = 0;
        bcku = X509KeyUsage.decipherOnly;
        X509KeyUsage ku = new X509KeyUsage(bcku);
        extgen.addExtension(Extension.keyUsage, false, ku);
        // Extended Key Usage
        List<KeyPurposeId> usage = new ArrayList<KeyPurposeId>();
        usage.add(KeyPurposeId.id_kp_codeSigning);
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(usage);
        extgen.addExtension(Extension.extendedKeyUsage, false, eku);
        // OcspNoCheck
        extgen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE);
        // Netscape cert type
        extgen.addExtension(new ASN1ObjectIdentifier("2.16.840.1.113730.1.1"), false, new NetscapeCertType(NetscapeCertType.objectSigningCA));
        // My completely own
        extgen.addExtension(new ASN1ObjectIdentifier("1.1.1.1.1"), false, new DERIA5String("PrimeKey"));

        // Make the complete extension package
        Extensions exts = extgen.generate();

        // First test without extension override
        PKIMessage one = genCertReq(this.issuerDN2, userDN2, this.keys, this.cacert2, nonce, transid, true, exts, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId2", 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN2, this.cacert2, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("dNSName=foo.bar.com") != -1);

        // Check key usage that it is nonRepudiation for KeyId2
        boolean[] kubits = cert.getKeyUsage();
        assertFalse(kubits[0]);
        assertTrue(kubits[1]);
        assertFalse(kubits[2]);
        assertFalse(kubits[3]);
        assertFalse(kubits[4]);
        assertFalse(kubits[5]);
        assertFalse(kubits[6]);
        assertFalse(kubits[7]);
        assertFalse(kubits[8]);
        // Our own ext should not be here
        assertNull(cert.getExtensionValue("1.1.1.1.1"));
        assertNull(cert.getExtensionValue("2.16.840.1.113730.1.1"));
        assertNull(cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));

        // Skip confirmation message, we have tested that several times already

        //
        // Do the same with keyId4, that has full extension override
        one = genCertReq(this.issuerDN2, userDN2, this.keys, this.cacert2, nonce, transid, true, exts, null, null, null, null, null);
        req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId4", 567);

        ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, this.issuerDN2, userDN2, this.cacert2, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        cert = checkCmpCertRepMessage(userDN2, this.cacert2, resp, reqId);
        altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("dNSName=foo.bar.com") != -1);

        // Check key usage that it is decipherOnly for KeyId4
        kubits = cert.getKeyUsage();
        assertFalse(kubits[0]);
        assertFalse(kubits[1]);
        assertFalse(kubits[2]);
        assertFalse(kubits[3]);
        assertFalse(kubits[4]);
        assertFalse(kubits[5]);
        assertFalse(kubits[6]);
        assertFalse(kubits[7]);
        assertTrue(kubits[8]);
        // Our own ext should not be here
        assertNotNull(cert.getExtensionValue("1.1.1.1.1"));
        assertNotNull(cert.getExtensionValue("2.16.840.1.113730.1.1"));
        assertNotNull(cert.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId()));
        List<String> l = cert.getExtendedKeyUsage();
        assertEquals(1, l.size());
        String s = l.get(0);
        assertEquals(KeyPurposeId.id_kp_codeSigning.getId(), s);

        // Skip confirmation message, we have tested that several times already
    } // test07ExtensionOverride


}
