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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * You can run this test against a CMP Proxy instead of directly to the CA by setting the system property httpCmpProxyURL, 
 * for example "-DhttpCmpProxyURL=http://localhost:8080/cmpProxy-6.3.3", which can be set in Run Configurations if running the 
 * test from Eclipse.
 * 
 * @version $Id$
 */
public class CrmfRARequestTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestTest.class);

    final private static String PBEPASSWORD = "password";
    final private static String ISSUER_DN = "CN=TestCA";
    final private int caid;
    final private X509Certificate cacert;
    final private CA testx509ca;
    final private CmpConfiguration cmpConfiguration;
    final static private String cmpAlias = "CrmfRARequestTestCmpConfigAlias";

    final private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    final private CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    final private EndEntityAccessSession eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    final private GlobalConfigurationSessionRemote globalConfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    final private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfRARequestTest() throws Exception {
        this.caSession.removeCA(ADMIN, ISSUER_DN.hashCode());
        
        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(ISSUER_DN, null, false, keyusage);
        this.caSession.addCA(ADMIN, this.testx509ca);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        this.configurationSession.backupConfiguration();
        
        // Configure CMP for this test
        this.cmpConfiguration.addAlias(cmpAlias);
        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        this.cmpConfiguration.setRAEEProfile(cmpAlias, String.valueOf(eepDnOverrideId));
        this.cmpConfiguration.setRACertProfile(cmpAlias, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRACAName(cmpAlias, "TestCA");
        this.cmpConfiguration.setRANameGenScheme(cmpAlias, "DN");
        this.cmpConfiguration.setRANameGenParams(cmpAlias, "CN");
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;" + PBEPASSWORD);
        this.globalConfSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    /**
     * @param userDN for new certificate.
     * @param keys key of the new certificate.
     * @param sFailMessage if !=null then EJBCA is expected to fail. The failure response message string is checked against this parameter.
     * @return X509Certificate the cert produced if test was successful, null for a test that resulted in failure (can be expected if sFailMessage != null)
     * @throws Exception
     */
    private X509Certificate crmfHttpUserTest(
            X500Name userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno,
            String sigAlg, X509Certificate caCert, String issuerDN) throws Exception {

        // Create a new good user

        X509Certificate cert = null;
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, caCert, nonce, transid, true, null, null, null, customCertSerno, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, issuerDN, userDN, caCert, nonce, transid, sFailMessage == null, null, sigAlg);
            if (sFailMessage == null) {
                cert = checkCmpCertRepMessage(userDN, caCert, resp, reqId);
                // verify if custom cert serial number was used
                if (customCertSerno != null) {
                    Assert.assertTrue(cert.getSerialNumber().toString(16) + " is not same as expected " + customCertSerno.toString(16), cert
                            .getSerialNumber().equals(customCertSerno));
                }
            } else {
                checkCmpFailMessage(resp, sFailMessage, CmpPKIBodyConstants.ERRORMESSAGE, reqId, PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);
            }
        }
        {
            // Send a confirm message to the CA
            final String hash = "foo123";
            final PKIMessage con = genCertConfirm(userDN, caCert, nonce, transid, hash, reqId);
            Assert.assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, issuerDN, userDN, caCert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(userDN, caCert, resp);
        }
        return cert;
    }

    @Test
    public void test01CrmfHttpOkUser() throws Exception {
        final CAInfo caInfo = this.caSession.getCAInfo(ADMIN, "TestCA");
        // make sure same keys for different users is prevented
        caInfo.setDoEnforceUniquePublicKeys(true);
        // make sure same DN for different users is prevented
        caInfo.setDoEnforceUniqueDistinguishedName(true);
        caInfo.setUseUserStorage(true);
        this.caAdminSessionRemote.editCA(ADMIN, caInfo);

        final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key3 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key4 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String userName1 = "cmptest1";
        final String userName2 = "cmptest2";
        final X500Name userDN1 = new X500Name("C=SE,O=PrimeKey,CN=" + userName1);
        final X500Name userDN2 = new X500Name("C=SE,O=PrimeKey,CN=" + userName2);
        try {
            
            // check that several certificates could be created for one user and one key.
            crmfHttpUserTest(userDN1, key1, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), this.cacert, ISSUER_DN);
            crmfHttpUserTest(userDN2, key2, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), this.cacert, ISSUER_DN);
            // check that the request fails when asking for certificate for another user with same key.
            crmfHttpUserTest(
                    userDN2,
                    key1,
                    "User 'cmptest2' is not allowed to use same key as another user is using.",
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), this.cacert, ISSUER_DN);
            crmfHttpUserTest(
                    userDN1,
                    key2,
                    "User 'cmptest1' is not allowed to use same key as another user is using.",
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), this.cacert, ISSUER_DN);
            
            // check that you can not issue a certificate with same DN as another user.            
            EndEntityInformation user = new EndEntityInformation("samednuser1", "CN=SameDNUser,O=EJBCA Sample,C=SE", this.caid, null, "user1" + "@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
            user.setPassword("foo123");
            try {
                this.endEntityManagementSession.addUser(ADMIN, user, true); 
                log.debug("created user: samednuser1, foo123, CN=SameDNUser,O=EJBCA Sample,C=SE");
            } catch (Exception e) {/* Do nothing. */}
            
            Certificate user1Cert = null;
            try {
                user1Cert = this.signSession.createCertificate(ADMIN, "samednuser1", "foo123", new PublicKeyWrapper(key3.getPublic()));
            } catch(Exception e) {
                throw new IllegalStateException("Error encountered when creating certificate", e);
            }
            assertNotNull("Failed to create a test certificate", user1Cert);
            assertEquals(ISSUER_DN, CertTools.getIssuerDN(user1Cert));

            crmfHttpUserTest(
                    new X500Name("CN=SameDNUser,O=EJBCA Sample,C=SE"),
                    key4,
                    "User 'SameDNUser' is not allowed to use same subject DN as the user(s) 'samednuser1' is/are using while issued by the same CA (even if CN postfix is used). See setting for 'Enforce unique DN' in the section Certification Authorities.", 
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), this.cacert, ISSUER_DN);
            
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, userName1);
            } catch (NotFoundException e) {// Do nothing.
            }
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, userName2);
            } catch (NotFoundException e) {// Do nothing.
            }
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, "SameDNUser", ReasonFlags.unused);
            } catch (NotFoundException e) {// Do nothing.
            }
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, "samednuser1", ReasonFlags.unused);
            } catch (NotFoundException e) {// Do nothing.
            }
        }
    }

    @Test
    public void test02NullKeyID() throws Exception {

        // Create a new good user

        final X500Name userDN = new X500Name("CN=keyIDTestUser,C=SE");
        try {
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();
            final int reqId;
            
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DAY_OF_MONTH, 2);
            final PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, new Date(), cal.getTime(), null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, null, 567);
            Assert.assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();

            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
            BigInteger serialnumber = cert.getSerialNumber();

            // Revoke the created certificate
            final PKIMessage con = genRevReq(ISSUER_DN, userDN, serialnumber, this.cacert, nonce, transid, false, null, null);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, null, 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resprev, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(ISSUER_DN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "keyIDTestUser");
            } catch (NotFoundException e) {
                // NOPMD
            }
        }

    }

    @Test
    public void test03UseKeyID() throws Exception {

        GlobalConfiguration gc = (GlobalConfiguration) this.globalConfSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final boolean eelimitation = gc.getEnableEndEntityProfileLimitations();
        gc.setEnableEndEntityProfileLimitations(true);
        this.globalConfSession.saveConfiguration(ADMIN, gc);

        try {
            this.cmpConfiguration.setRAEEProfile(cmpAlias, CmpConfiguration.PROFILE_USE_KEYID);
            this.cmpConfiguration.setRACertProfile(cmpAlias, CmpConfiguration.PROFILE_USE_KEYID);
            this.globalConfSession.saveConfiguration(ADMIN, this.cmpConfiguration);

            try {
                this.certProfileSession.removeCertificateProfile(ADMIN, "CMPKEYIDTESTPROFILE");
                this.endEntityProfileSession.removeEndEntityProfile(ADMIN, "CMPKEYIDTESTPROFILE");
            } catch(Exception e) {/*Do nothing.*/}

            // Configure CMP for this test, we allow custom certificate serial numbers
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            try {
                this.certProfileSession.addCertificateProfile(ADMIN, "CMPKEYIDTESTPROFILE", profile);
            } catch (CertificateProfileExistsException e) {
                log.error("Could not create certificate profile.", e);
            }

            int cpId = this.certProfileSession.getCertificateProfileId("CMPKEYIDTESTPROFILE");

            EndEntityProfile eep = new EndEntityProfile();
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
            eep.setValue(EndEntityProfile.DEFAULTCA, 0, "" + this.caid);
            eep.setValue(EndEntityProfile.AVAILCAS, 0, "" + this.caid);
            eep.addField(DnComponents.ORGANIZATION);
            eep.setRequired(DnComponents.ORGANIZATION, 0, true);
            eep.addField(DnComponents.RFC822NAME);
            eep.addField(DnComponents.UPN);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data

            try {
                this.endEntityProfileSession.addEndEntityProfile(ADMIN, "CMPKEYIDTESTPROFILE", eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }

            // Create a new user that does not fulfill the end entity profile

            X500Name userDN = new X500Name("CN=keyIDTestUser,C=SE");
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();
            final int reqId;

            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "keyIDTestUser");
            } catch (NotFoundException e) {
                // NOPMD
            }
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, "keyidtest2");
            } catch (NotFoundException e) {
                // NOPMD
            }

            try {
                final PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, new Date(), null, null, null, null);
                final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

                CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
                reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
                Assert.assertNotNull(req);
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(req);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
                // do not check signing if we expect a failure (sFailMessage==null)
                checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                checkCmpFailMessage(resp, "Subject DN field 'ORGANIZATION' must exist.", CmpPKIBodyConstants.INITIALIZATIONRESPONSE, reqId, 
                        PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);


                // Create a new user that fulfills the end entity profile

                userDN = new X500Name("CN=keyidtest2,O=org");
                final KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                final byte[] nonce2 = CmpMessageHelper.createSenderNonce();
                final byte[] transid2 = CmpMessageHelper.createSenderNonce();
                final int reqId2;

                final PKIMessage one2 = genCertReq(ISSUER_DN, userDN, keys2, this.cacert, nonce2, transid2, true, null, null, null, null, null, null);
                final PKIMessage req2 = protectPKIMessage(one2, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

                ir = (CertReqMessages) req2.getBody().getContent();
                reqId2 = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
                Assert.assertNotNull(req2);
                final ByteArrayOutputStream bao2 = new ByteArrayOutputStream();
                final DEROutputStream out2 = new DEROutputStream(bao2);
                out2.writeObject(req2);
                final byte[] ba2 = bao2.toByteArray();
                // Send request and receive response
                final byte[] resp2 = sendCmpHttp(ba2, 200, cmpAlias);
                // do not check signing if we expect a failure (sFailMessage==null)
                checkCmpResponseGeneral(resp2, ISSUER_DN, userDN, this.cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp2, reqId2);
                BigInteger serialnumber = cert.getSerialNumber();

                EndEntityInformation ee = this.eeAccessSession.findUser(ADMIN, "keyidtest2");
                Assert.assertEquals("Wrong certificate profile", cpId, ee.getCertificateProfileId());

                // Revoke the created certificate and use keyid
                final PKIMessage con = genRevReq(ISSUER_DN, userDN, serialnumber, this.cacert, nonce2, transid2, false, null, null);
                Assert.assertNotNull(con);
                PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);
                final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
                final DEROutputStream outrev = new DEROutputStream(baorev);
                outrev.writeObject(revmsg);
                final byte[] barev = baorev.toByteArray();
                // Send request and receive response
                final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
                checkCmpResponseGeneral(resprev, ISSUER_DN, userDN, this.cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                int revstatus = checkRevokeStatus(ISSUER_DN, serialnumber);
                Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);

                // Create a request that points to a non existing profile (identified by keyId)
                final PKIMessage three = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, new Date(), null, null, null, null);
                final PKIMessage req3 = protectPKIMessage(three, false, PBEPASSWORD, "CMPKEYIDTESTPROFILEFAIL", 567);

                ir = (CertReqMessages) req3.getBody().getContent();
                final int reqId3 = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
                Assert.assertNotNull(reqId3);
                final ByteArrayOutputStream bao3 = new ByteArrayOutputStream();
                final DEROutputStream out3 = new DEROutputStream(bao3);
                out3.writeObject(req3);
                final byte[] ba3 = bao3.toByteArray();
                // Send request and receive response
                final byte[] resp3 = sendCmpHttp(ba3, 200, cmpAlias);
                // do not check signing if we expect a failure (sFailMessage==null)
                checkCmpResponseGeneral(resp3, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                checkCmpFailMessage(resp3, "End Entity Profile of name \"CMPKEYIDTESTPROFILEFAIL\" was not found", CmpPKIBodyConstants.INITIALIZATIONRESPONSE, reqId3, 
                        PKIFailureInfo.systemUnavail, PKIFailureInfo.systemUnavail);

            } finally {
                try {
                    this.endEntityManagementSession.deleteUser(ADMIN, "keyIDTestUser");
                } catch (NotFoundException e) {
                    // NOPMD
                }
                try {
                    this.endEntityManagementSession.deleteUser(ADMIN, "keyidtest2");
                } catch (NotFoundException e) {
                    // NOPMD
                }
            }      
        } finally {
            gc.setEnableEndEntityProfileLimitations(eelimitation);
            globalConfSession.saveConfiguration(ADMIN, gc);            
        }

    }
    
    /**
     * Send a CMP request with SubjectAltName containing OIDs that are not defined by Ejbca.
     * Expected to pass and a certificate containing the unsupported OIDs is returned.
     * 
     * @throws Exception
     */
    @Test
    public void test04UsingOtherNameInSubjectAltName() throws Exception {

        ASN1EncodableVector vec = new ASN1EncodableVector();
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(new ASN1ObjectIdentifier(CertTools.UPN_OBJECTID));
        v.add(new DERTaggedObject(true, 0, new DERUTF8String("boo@bar")));
        GeneralName gn = GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v)));
        vec.add(gn);
        
        v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier("2.5.5.6"));
        v.add(new DERTaggedObject(true, 0, new DERIA5String( "2.16.528.1.1007.99.8-1-993000027-N-99300011-00.000-00000000" )));
        gn = GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v)));
        vec.add(gn);
        
        GeneralNames san = GeneralNames.getInstance(new DERSequence(vec));
        
        ExtensionsGenerator gen = new ExtensionsGenerator();
        gen.addExtension(Extension.subjectAlternativeName, false, san);
        Extensions exts = gen.generate();
        
        final X500Name userDN = new X500Name("CN=TestAltNameUser");
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        String fingerprint = null;
        
        try {
            final PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
            fingerprint = CertTools.getFingerprintAsString(cert);
            
        } finally {
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, "TestAltNameUser", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            } catch (NotFoundException e) {/*Do nothing*/}
            
            try{
                this.internalCertStoreSession.removeCertificate(fingerprint);
            } catch(Exception e) {/*Do nothing*/}
        }    
        
    }
    
    @Test
    public void test05SubjectSerialNumber() throws Exception {

        // Set requirement of unique subjectDN serialnumber to be true
        CAInfo cainfo = this.caSession.getCAInfo(ADMIN, this.caid);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        // Set the CA to enforce unique serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.editCA(ADMIN, cainfo);

        // Create a new good user
        final String username = "subjectsnuser";
        X500Name userDN = new X500Name("CN=" + username + ",SN=1234567,C=SE");
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();
            int reqId;

            PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, null, 567);
            Assert.assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();

            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
            BigInteger serialnumber = cert.getSerialNumber();

            // create a second user with the same serialnumber, but spelled "SERIALNUMBER" instead of "SN"
            userDN = new X500Name("CN=subjectsnuser2,SERIALNUMBER=1234567,C=SE");
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            req = protectPKIMessage(one, false, PBEPASSWORD, null, 567);
            Assert.assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();

            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(req);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpFailMessage(resp, "Error: SubjectDN Serialnumber already exists.", CmpPKIBodyConstants.ERRORMESSAGE, reqId,
                    PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);

            // Revoke the created certificate
            final PKIMessage con = genRevReq(ISSUER_DN, userDN, serialnumber, this.cacert, nonce, transid, false, null, null);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, null, 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resprev, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(ISSUER_DN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);

            cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
            caAdminSession.editCA(ADMIN, cainfo);
        } finally {
            this.endEntityManagementSession.deleteUser(ADMIN, username);
        }
    }

    @Test
    public void test06CrmfEcdsaCA() throws Exception {
        try {
            createEllipticCurveDsaCa();
            CAInfo caInfo = this.caSession.getCAInfo(ADMIN, "TESTECDSA");
            this.cmpConfiguration.setRACAName(cmpAlias, "TESTECDSA");
            this.globalConfSession.saveConfiguration(ADMIN, this.cmpConfiguration);

            final String issuerDN = caInfo.getSubjectDN(); // Make sure this CA is used for the test
            final X509Certificate caCert = (X509Certificate)caInfo.getCertificateChain().iterator().next();
            final KeyPair key1 = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
            final String userName1 = "cmptestecdsa1";
            final X500Name userDN1 = new X500Name("C=SE,O=PrimeKey,CN=" + userName1);
            try {
                // check that we can get a certificate from this ECDSA CA.
                X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null, X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), caCert, issuerDN);
                assertNotNull(cert);
                // Check that this was really signed using SHA256WithECDSA and that the users key algo is in there
                assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getSignatureAlgorithm(cert));
                // Keyspec we get back from AlgorithmTools.getKeySpecification seems to differ between OracleJDK and OpenJDK so we only check key type
                assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(cert.getPublicKey()));
            } finally {
                try {
                    this.endEntityManagementSession.deleteUser(ADMIN, userName1);
                } catch (NotFoundException e) {// Do nothing
                }
            }
        } finally {
            // Reset this test class as it was before this test
            this.cmpConfiguration.setRACAName(cmpAlias, "TestCA");
            this.globalConfSession.saveConfiguration(ADMIN, this.cmpConfiguration);
            removeTestCA("TESTECDSA");
        }
    }

    @Test
    public void test07EscapedCharsInDN() throws Exception {

        final String username = "another\0nullguy%00<do>";
        final String sUserDN = "CN=" + username + ", C=SE";
        final X500Name userDN = new X500Name(sUserDN);

        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        final int reqId;
        try {
            final PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            final CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            Assert.assertNotNull(req);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            final byte[] ba = bao.toByteArray();
            {// this strange DN contains forbidden characters and may not be stored a a string in the DB, so it must be transformed by ejbca.
                final CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
                cp.setAllowDNOverride(false);
                this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
            }
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // do not check signing if we expect a failure (sFailMessage==null)
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
            {
                final CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
                cp.setAllowDNOverride(true);
                this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
            }
        } finally {
            String escapedName = "another/nullguy/00\\<do\\>";
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, escapedName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } catch (NotFoundException e) {
                log.debug("Failed to delete user: " + escapedName);
            }
        }
    } 

    @Test
    public void test08KeyUsageAndExtendedKeyUsageOverride() throws Exception {
        
        final String username = "overidetestuser";
        final String sUserDN = "CN=" + username + ", C=SE";
        final X500Name userDN = new X500Name(sUserDN);

        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        try {
            
            {
                // Certificate Profile customizing
                // Step 1 ->  Checking the default behavior. Extensions may not be overrideden if Allow Extension Override is setted to false. 
                final CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
                cp.setAllowExtensionOverride(false);
                cp.setUseExtendedKeyUsage(true);
                cp.setUseKeyUsage(true);
                cp.setKeyUsage(new boolean[9]);
                // Setting key usage to digitalsignature, nonrepudiation and keyencipherment
                cp.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
                cp.setKeyUsage(CertificateConstants.NONREPUDIATION, true);
                cp.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);
                cp.setKeyUsageCritical(true);
                cp.setUseExtendedKeyUsage(true);
                ArrayList<String> eku = new ArrayList<>();
                // Setting Extended key usage to clientAuth and emailProtection
                eku.add(KeyPurposeId.id_kp_clientAuth.getId());
                eku.add(KeyPurposeId.id_kp_emailProtection.getId());
                cp.setExtendedKeyUsage(eku);
                cp.setExtendedKeyUsageCritical(false);
                
                this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
                
            }
            // CRMF customizing
            int reqId;
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            // KeyUsage
            int bcku = 0;
            bcku = X509KeyUsage.decipherOnly;
            X509KeyUsage ku = new X509KeyUsage(bcku);
            extgen.addExtension(Extension.keyUsage, false, ku);
            // Extended Key Usage
            List<KeyPurposeId> usage = new ArrayList<KeyPurposeId>();
            usage.add(KeyPurposeId.id_kp_codeSigning);
            ExtendedKeyUsage eku = new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning);
            extgen.addExtension(Extension.extendedKeyUsage, false, eku);
            // Make the complete extension package
            Extensions exts = extgen.generate();
            
            PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
            
            // Checking key usage are digitalsignature, nonrepudiation and keyencipherment the values was not changed by CRMF.
            boolean[] kubits = cert.getKeyUsage();
            assertTrue(kubits[0]);
            assertTrue(kubits[1]);
            assertTrue(kubits[2]);
            assertFalse(kubits[3]);
            assertFalse(kubits[4]);
            assertFalse(kubits[5]);
            assertFalse(kubits[6]);
            assertFalse(kubits[7]);
            assertFalse(kubits[8]);
            // Checking Extended key usage are clientAuth and emailProtection the values was not changed by CRMF.
            List<String> l = cert.getExtendedKeyUsage();
            assertEquals(2, l.size());
            String s = l.get(0);
            assertEquals(KeyPurposeId.id_kp_clientAuth.getId(), s);
            s = l.get(1);
            assertEquals(KeyPurposeId.id_kp_emailProtection.getId(), s);
            
            {
             // Step 2 ->  If Allow Extension Override is setted to true but the OIDs for these extensions were added in the lists OverridableExtensionOIDs and NonOverridableExtensionOIDs these extensions will not be overridden.
                CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);             
                cp.setAllowExtensionOverride(true);
                cp.getOverridableExtensionOIDs().add("2.5.29.15"); // <- keyUsage
                cp.getOverridableExtensionOIDs().add("2.5.29.37"); // <- extendedKeyUsage
                cp.getNonOverridableExtensionOIDs().add("2.5.29.15"); // <- keyUsage
                cp.getNonOverridableExtensionOIDs().add("2.5.29.37"); // <- extendedKeyUsage
                this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
                
            }
            
            one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
            req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(req);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
            
            // Checking key usage are digitalsignature, nonrepudiation and keyencipherment the values was not changed by CRMF.
            kubits = cert.getKeyUsage();
            assertTrue(kubits[0]);
            assertTrue(kubits[1]);
            assertTrue(kubits[2]);
            assertFalse(kubits[3]);
            assertFalse(kubits[4]);
            assertFalse(kubits[5]);
            assertFalse(kubits[6]);
            assertFalse(kubits[7]);
            assertFalse(kubits[8]);
            // Checking Extended key usage are clientAuth and emailProtection the values was not changed by CRMF.
            l = cert.getExtendedKeyUsage();
            assertEquals(2, l.size());
            s = l.get(0);
            assertEquals(KeyPurposeId.id_kp_clientAuth.getId(), s);
            s = l.get(1);
            assertEquals(KeyPurposeId.id_kp_emailProtection.getId(), s);
            
            {
               // Step 3 ->  Allow Extension Override is setted to true.
               //            Testing Key Usage as non overridable extension and
               //            Extended Key Usage as overridable extension.
               CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);             
               cp.setAllowExtensionOverride(true);               
               cp.getNonOverridableExtensionOIDs().remove("2.5.29.37"); // <- extendedKeyUsage
               this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
               
           }
           
           one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
           req = protectPKIMessage(one, false, PBEPASSWORD, 567);

           ir = (CertReqMessages) req.getBody().getContent();
           reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
           assertNotNull(req);
           bao = new ByteArrayOutputStream();
           out = new DEROutputStream(bao);
           out.writeObject(req);
           ba = bao.toByteArray();
           // Send request and receive response
           resp = sendCmpHttp(ba, 200, cmpAlias);
           checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
           cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
           
           // Checking key usage are digitalsignature, nonrepudiation and keyencipherment the values was not changed by CRMF. 
           kubits = cert.getKeyUsage();
           assertTrue(kubits[0]);
           assertTrue(kubits[1]);
           assertTrue(kubits[2]);
           assertFalse(kubits[3]);
           assertFalse(kubits[4]);
           assertFalse(kubits[5]);
           assertFalse(kubits[6]);
           assertFalse(kubits[7]);
           assertFalse(kubits[8]);
           // Checking Extended key usage is codeSigning the value was changed by CRMF.
           l = cert.getExtendedKeyUsage();
           assertEquals(1, l.size());
           s = l.get(0);
           assertEquals(KeyPurposeId.id_kp_codeSigning.getId(), s);
           
           {
              // Step 4 ->  Allow Extension Override is setted to true.
              //            Testing Key Usage as overridable extension and
              //            Extended Key Usage as overridable extension.
              CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);             
              cp.setAllowExtensionOverride(true);               
              cp.getNonOverridableExtensionOIDs().remove("2.5.29.15"); // <- keyUsage
              this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
              
          }
          
          one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
          req = protectPKIMessage(one, false, PBEPASSWORD, 567);

          ir = (CertReqMessages) req.getBody().getContent();
          reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
          assertNotNull(req);
          bao = new ByteArrayOutputStream();
          out = new DEROutputStream(bao);
          out.writeObject(req);
          ba = bao.toByteArray();
          // Send request and receive response
          resp = sendCmpHttp(ba, 200, cmpAlias);
          checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
          cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
          
          // Checking key usage is decipherOnly the value was changed by CRMF.
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
          // Checking Extended key usage is codeSigning the value was changed by CRMF.
          l = cert.getExtendedKeyUsage();
          assertEquals(1, l.size());
          s = l.get(0);
          assertEquals(KeyPurposeId.id_kp_codeSigning.getId(), s);
            
        } finally {
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } catch (NotFoundException e) {
                log.debug("Failed to delete user: " + username);
            }
        }
            
    }
    
    @Test
    public void test09CertificatePoliceOverwrite() throws Exception {
        final String username = "overidetestuser";
        final String sUserDN = "CN=" + username + ", C=SE";
        final X500Name userDN = new X500Name(sUserDN);

        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        
        try {
        {
            // Certificate Profile customizing
            // Step 1 ->  Checking the default behavior. Extensions may not be overrideden if Allow Extension Override is setted to false. 
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp.setAllowExtensionOverride(false);
            cp.setUseCertificatePolicies(true);
            List<CertificatePolicy> l = cp.getCertificatePolicies();
            assertEquals(0, l.size());
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.1", "1.3.6.1.5.5.7.2.1", "https://ejbca.org/1"));
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", "1.3.6.1.5.5.7.2.2", "My User Notice Text"));
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.3", "1.3.6.1.5.5.7.2.1", "https://ejbca.org/3"));
            l = cp.getCertificatePolicies();
            assertEquals(3, l.size());
            CertificatePolicy policy1 = l.get(0);
            assertEquals("1.1.1.1", policy1.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.1", policy1.getQualifierId());
            assertEquals("https://ejbca.org/1", policy1.getQualifier());
            CertificatePolicy policy2 = l.get(1);
            assertEquals("1.1.1.2", policy2.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.2", policy2.getQualifierId());
            assertEquals("My User Notice Text", policy2.getQualifier());
            CertificatePolicy policy3= l.get(2);
            assertEquals("1.1.1.3", policy3.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.1", policy3.getQualifierId());
            assertEquals("https://ejbca.org/3", policy3.getQualifier());
            this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
        }
        // CRMF customizing
        int reqId;
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        
        final ASN1EncodableVector policyqualifyseq1 = new ASN1EncodableVector();
        PolicyQualifierInfo policyQualifierInfo1 = new PolicyQualifierInfo("https://ejbca.org/x1");
        policyqualifyseq1.add(policyQualifierInfo1);
        PolicyInformation pi1 = new PolicyInformation(new ASN1ObjectIdentifier("1.1.1.1"), new DERSequence(policyqualifyseq1));
        final ASN1EncodableVector policyseq = new ASN1EncodableVector();
        policyseq.add(pi1);
        
        final ASN1EncodableVector qualifyseq = new ASN1EncodableVector();
        qualifyseq.add(new DERIA5String("My User X Notice Text"));
        PolicyQualifierInfo policyQualifierInfo2 = new PolicyQualifierInfo(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.2.2"), new DERSequence(qualifyseq));
        final ASN1EncodableVector policyqualifyseq2 = new ASN1EncodableVector();
        policyqualifyseq2.add(policyQualifierInfo2);
        PolicyInformation pi2 = new PolicyInformation(new ASN1ObjectIdentifier("1.1.1.2"), new DERSequence(policyqualifyseq2));
        policyseq.add(pi2);
        
        final ASN1EncodableVector policyqualifyseq3 = new ASN1EncodableVector();
        PolicyQualifierInfo policyQualifierInfo3 = new PolicyQualifierInfo("https://ejbca.org/x3");
        policyqualifyseq3.add(policyQualifierInfo3);
        PolicyInformation pi3 = new PolicyInformation(new ASN1ObjectIdentifier("1.1.1.3"), new DERSequence(policyqualifyseq3));
        policyseq.add(pi3);
        extgen.addExtension(Extension.certificatePolicies, false, new DERSequence(policyseq));
                
        // Make the complete extension package
        Extensions exts = extgen.generate();
        
        PKIMessage one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);

        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
                        
        List<PolicyInformation> piList = CertTools.getCertificatePolicies(cert);
        assertEquals("Should be 3 Cert Policies", 3, piList.size());
        assertEquals("1.1.1.1", piList.get(0).getPolicyIdentifier().getId());
        assertEquals("1.1.1.2", piList.get(1).getPolicyIdentifier().getId());
        assertEquals("1.1.1.3", piList.get(2).getPolicyIdentifier().getId());
        
        //The first Policy object has a CPS URI
        ASN1Encodable qualifier = piList.get(0).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        DERIA5String str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/1", str.getString());
        
        // The second Policy object has a User Notice
        qualifier = piList.get(1).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        UserNotice un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("My User Notice Text", un.getExplicitText().getString());
        
        // The third Policy object has both a CPS URI and a User Notice
        qualifier = piList.get(2).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/3", str.getString());
        
        {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp.setAllowExtensionOverride(true);
            cp.getOverridableExtensionOIDs().add("2.5.29.32"); // <- certificatePolicies
            cp.setUseCertificatePolicies(true);
            List<CertificatePolicy> l = cp.getCertificatePolicies();
            assertEquals(0, l.size());
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.1", "1.3.6.1.5.5.7.2.1", "https://ejbca.org/1"));
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.2", "1.3.6.1.5.5.7.2.2", "My User Notice Text"));
            cp.addCertificatePolicy(new CertificatePolicy("1.1.1.3", "1.3.6.1.5.5.7.2.1", "https://ejbca.org/3"));
            l = cp.getCertificatePolicies();
            assertEquals(3, l.size());
            CertificatePolicy policy1 = l.get(0);
            assertEquals("1.1.1.1", policy1.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.1", policy1.getQualifierId());
            assertEquals("https://ejbca.org/1", policy1.getQualifier());
            CertificatePolicy policy2 = l.get(1);
            assertEquals("1.1.1.2", policy2.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.2", policy2.getQualifierId());
            assertEquals("My User Notice Text", policy2.getQualifier());
            CertificatePolicy policy3= l.get(2);
            assertEquals("1.1.1.3", policy3.getPolicyID());
            assertEquals("1.3.6.1.5.5.7.2.1", policy3.getQualifierId());
            assertEquals("https://ejbca.org/3", policy3.getQualifier());
            this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
        }
        
        // Make the complete extension package
        one = genCertReq(ISSUER_DN, userDN, keys, this.cacert, nonce, transid, true, exts, null, null, null, null, null);
        req = protectPKIMessage(one, false, PBEPASSWORD, 567);

        ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req);
        ba = bao.toByteArray();
        resp = sendCmpHttp(ba, 200, cmpAlias);

        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sUserDN)), this.cacert, resp, reqId);
                        
        piList = CertTools.getCertificatePolicies(cert);
        assertEquals("Should be 3 Cert Policies", 3, piList.size());
        assertEquals("1.1.1.1", piList.get(0).getPolicyIdentifier().getId());
        assertEquals("1.1.1.2", piList.get(1).getPolicyIdentifier().getId());
        assertEquals("1.1.1.3", piList.get(2).getPolicyIdentifier().getId());
        
        //The first Policy object has a CPS URI
        qualifier = piList.get(0).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/x1", str.getString());
        
        // The secound Policy object has a User Notice
        qualifier = piList.get(1).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_unotice = 1.3.6.1.5.5.7.2.2
        assertEquals(PolicyQualifierId.id_qt_unotice.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_unutice, we know this is a UserNotice
        un = UserNotice.getInstance(pqi.getQualifier());
        assertEquals("My User X Notice Text", un.getExplicitText().getString());
        
        // The third Policy object has both a CPS URI and a User Notice
        qualifier = piList.get(2).getPolicyQualifiers().getObjectAt(0);
        //System.out.println(ASN1Dump.dumpAsString(qualifier));
        pqi = PolicyQualifierInfo.getInstance(qualifier);
        // PolicyQualifierId.id_qt_cps = 1.3.6.1.5.5.7.2.1
        assertEquals(PolicyQualifierId.id_qt_cps.getId(), pqi.getPolicyQualifierId().getId());
        // When the qualifiedID is id_qt_cps, we know this is a DERIA5String
        str = DERIA5String.getInstance(pqi.getQualifier());
        assertEquals("https://ejbca.org/x3", str.getString());        
        //The first Policy object has a CPS URI
        
        } finally {
            try {
                this.endEntityManagementSession.revokeAndDeleteUser(ADMIN, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } catch (NotFoundException e) {
                log.debug("Failed to delete user: " + username);
            }
        }
            
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(ADMIN, this.caid);
        
        Assert.assertTrue("Unable to restore server configuration.", this.configurationSession.restoreConfiguration());
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        // Remove test profiles
        this.certProfileSession.removeCertificateProfile(ADMIN, "CMPTESTPROFILE");
        this.certProfileSession.removeCertificateProfile(ADMIN, "CMPKEYIDTESTPROFILE");
        this.endEntityProfileSession.removeEndEntityProfile(ADMIN, "CMPTESTPROFILE");
        this.endEntityProfileSession.removeEndEntityProfile(ADMIN, "CMPKEYIDTESTPROFILE");
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
