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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.CertificateCreationException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class CrmfRARequestTest extends CmpTestCase {

    final private static Logger log = Logger.getLogger(CrmfRARequestTest.class);
    
    final private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRARequestTest"));

    final private static String PBEPASSWORD = "password";
    private String issuerDN = "CN=TestCA";
    private int caid;
    private X509Certificate cacert;
    private CA testx509ca;
    private CmpConfiguration cmpConfiguration;
    private String cmpAlias = "CrmfRARequestTestCmpConfigAlias";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityProfileSession eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private CertificateProfileSession certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityAccessSession eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CrmfRARequestTest.class.getSimpleName()); 
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        cmpConfiguration = (CmpConfiguration) globalConfSession.getCachedConfiguration(Configuration.CMPConfigID);
        
        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setAllowExtensionOverride(true);
        try {
            certProfileSession.addCertificateProfile(admin, "CMPTESTPROFILE", profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        int cpId = certProfileSession.getCertificateProfileId("CMPTESTPROFILE");
        EndEntityProfile eep = new EndEntityProfile(true);
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
        eep.addField(DnComponents.COMMONNAME);
        eep.addField(DnComponents.ORGANIZATION);
        eep.addField(DnComponents.COUNTRY);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
        try {
            eeProfileSession.addEndEntityProfile(admin, "CMPTESTPROFILE", eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        
        configurationSession.backupConfiguration();
        
        // Configure CMP for this test
        cmpConfiguration.addAlias(cmpAlias);
        cmpConfiguration.setRAMode(cmpAlias, true);
        cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        cmpConfiguration.setRAEEProfile(cmpAlias, "CMPTESTPROFILE");
        cmpConfiguration.setRACertProfile(cmpAlias, "CMPTESTPROFILE");
        cmpConfiguration.setRACAName(cmpAlias, "TestCA");
        cmpConfiguration.setRANameGenScheme(cmpAlias, "DN");
        cmpConfiguration.setRANameGenParams(cmpAlias, "CN");
        cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;" + PBEPASSWORD);
        globalConfSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

        CryptoProviderTools.installBCProvider();
        
        caSession.removeCA(admin, issuerDN.hashCode());
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        caSession.addCA(admin, testx509ca);
        caid = testx509ca.getCAId();
        cacert = (X509Certificate) testx509ca.getCACertificate();
    }

    /**
     * @param userDN for new certificate.
     * @param keys key of the new certificate.
     * @param sFailMessage if !=null then EJBCA is expected to fail. The failure response message string is checked against this parameter.
     * @return X509Certificate the cert produced if test was successful, null for a test that resulted in failure (can be expected if sFailMessage != null)
     * @throws Exception
     */
    private X509Certificate crmfHttpUserTest(String userDN, KeyPair keys, String sFailMessage, BigInteger customCertSerno, String sigAlg) throws Exception {

        // Create a new good user

        X509Certificate cert = null;
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, customCertSerno, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, sFailMessage == null, null, sigAlg);
            if (sFailMessage == null) {
                cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
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
            final PKIMessage con = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
            Assert.assertNotNull(con);
            PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
            final ByteArrayOutputStream bao = new ByteArrayOutputStream();
            final DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(confirm);
            final byte[] ba = bao.toByteArray();
            // Send request and receive response
            final byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(userDN, cacert, resp);
        }
        return cert;
    }

    @Test
    public void test01CrmfHttpOkUser() throws Exception {
        final CAInfo caInfo = caSession.getCAInfo(admin, "TestCA");
        // make sure same keys for different users is prevented
        caInfo.setDoEnforceUniquePublicKeys(true);
        // make sure same DN for different users is prevented
        caInfo.setDoEnforceUniqueDistinguishedName(true);
        caInfo.setUseUserStorage(true);
        caAdminSessionRemote.editCA(admin, caInfo);

        final KeyPair key1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key3 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final KeyPair key4 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final String userName1 = "cmptest1";
        final String userName2 = "cmptest2";
        final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
        final String userDN2 = "C=SE,O=PrimeKey,CN=" + userName2;
        try {
            
            // check that several certificates could be created for one user and one key.
            crmfHttpUserTest(userDN1, key1, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            crmfHttpUserTest(userDN2, key2, null, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            // check that the request fails when asking for certificate for another user with same key.
            crmfHttpUserTest(
                    userDN2,
                    key1,
                    "User 'cmptest2' is not allowed to use same key as the user(s) 'cmptest1' is/are using.", null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            crmfHttpUserTest(
                    userDN1,
                    key2,
                    "User 'cmptest1' is not allowed to use same key as the user(s) 'cmptest2' is/are using.", null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            
            // check that you can not issue a certificate with same DN as another user.            
            EndEntityInformation user = new EndEntityInformation("samednuser1", "CN=SameDNUser,O=EJBCA Sample,C=SE", caid, null, "user1" + "@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
            user.setPassword("foo123");
            try {
                endEntityManagementSession.addUser(admin, user, true); 
                log.debug("created user: samednuser1, foo123, CN=SameDNUser,O=EJBCA Sample,C=SE");
            } catch (Exception e) {}
            
            Certificate user1Cert = null;
            try {
                user1Cert = (X509Certificate) signSession.createCertificate(admin, "samednuser1", "foo123", key3.getPublic());
            } catch(Exception e) {
                throw new CertificateCreationException("Error encountered when creating certificate", e);
            }
            assertNotNull("Failed to create a test certificate", user1Cert);
            assertEquals(issuerDN, CertTools.getIssuerDN(user1Cert));

            crmfHttpUserTest(
                    "CN=SameDNUser,O=EJBCA Sample,C=SE",
                    key4,
                    "User 'SameDNUser' is not allowed to use same subject DN as the user(s) 'samednuser1' is/are using (even if CN postfix is used). See setting for 'Enforce unique DN' in the section Certification Authorities.", 
                    null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, userName1);
            } catch (NotFoundException e) {
            }
            try {
                endEntityManagementSession.deleteUser(admin, userName2);
            } catch (NotFoundException e) {
            }
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, "SameDNUser", ReasonFlags.unused);
            } catch (NotFoundException e) {
            }
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, "samednuser1", ReasonFlags.unused);
            } catch (NotFoundException e) {
            }
        }
    }

    @Test
    public void test02NullKeyID() throws Exception {

        // Create a new good user

        String userDN = "CN=keyIDTestUser,C=SE";
        try {
            final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();
            final int reqId;

            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            BigInteger serialnumber = cert.getSerialNumber();

            // Revoke the created certificate
            final PKIMessage con = genRevReq(issuerDN, userDN, serialnumber, cacert, nonce, transid, false, null, null);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, null, 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resprev, issuerDN, userDN, cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(issuerDN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, "keyIDTestUser");
            } catch (NotFoundException e) {
                // NOPMD
            }
        }

    }

    @Test
    public void test03UseKeyID() throws Exception {

        GlobalConfiguration gc = (GlobalConfiguration) globalConfSession.getCachedConfiguration(Configuration.GlobalConfigID);
        gc.setEnableEndEntityProfileLimitations(true);
        globalConfSession.saveConfiguration(authenticationToken, gc, Configuration.GlobalConfigID);
        
        cmpConfiguration.setRAEEProfile(cmpAlias, "KeyId");
        cmpConfiguration.setRACertProfile(cmpAlias, "KeyId");
        globalConfSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

        try {
            certProfileSession.removeCertificateProfile(admin, "CMPKEYIDTESTPROFILE");
            eeProfileSession.removeEndEntityProfile(admin, "CMPKEYIDTESTPROFILE");
        } catch(Exception e) {}

        // Configure CMP for this test, we allow custom certificate serial numbers
        CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        try {
            certProfileSession.addCertificateProfile(admin, "CMPKEYIDTESTPROFILE", profile);
        } catch (CertificateProfileExistsException e) {
            log.error("Could not create certificate profile.", e);
        }
        
        int cpId = certProfileSession.getCertificateProfileId("CMPKEYIDTESTPROFILE");
        
        EndEntityProfile eep = new EndEntityProfile();
        eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
        eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
        eep.setValue(EndEntityProfile.DEFAULTCA, 0, "" + caid);
        eep.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);
        eep.addField(DnComponents.ORGANIZATION);
        eep.setRequired(DnComponents.ORGANIZATION, 0, true);
        eep.addField(DnComponents.RFC822NAME);
        eep.addField(DnComponents.UPN);
        eep.setModifyable(DnComponents.RFC822NAME, 0, true);
        eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field from "email" data
        
        try {
            eeProfileSession.addEndEntityProfile(admin, "CMPKEYIDTESTPROFILE", eep);
        } catch (EndEntityProfileExistsException e) {
            log.error("Could not create end entity profile.", e);
        }
        
        // Create a new user that does not fulfill the end entity profile

        String userDN = "CN=keyIDTestUser,C=SE";
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        
        try {
            endEntityManagementSession.deleteUser(admin, "keyIDTestUser");
        } catch (NotFoundException e) {
            // NOPMD
        }
        try {
            endEntityManagementSession.deleteUser(admin, "keyidtest2");
        } catch (NotFoundException e) {
            // NOPMD
        }
        
        try {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpFailMessage(resp, "Subject DN field 'ORGANIZATION' must exist.", CmpPKIBodyConstants.INITIALIZATIONRESPONSE, reqId, 
                                                                PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);


            // Create a new user that fulfills the end entity profile

            userDN = "CN=keyidtest2,O=org";
            final KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce2 = CmpMessageHelper.createSenderNonce();
            final byte[] transid2 = CmpMessageHelper.createSenderNonce();
            final int reqId2;

            final PKIMessage one2 = genCertReq(issuerDN, userDN, keys2, cacert, nonce2, transid2, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp2, issuerDN, userDN, cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp2, reqId2);
            BigInteger serialnumber = cert.getSerialNumber();

            EndEntityInformation ee = eeAccessSession.findUser(admin, "keyidtest2");
            Assert.assertEquals("Wrong certificate profile", cpId, ee.getCertificateProfileId());

            // Revoke the created certificate and use keyid
            final PKIMessage con = genRevReq(issuerDN, userDN, serialnumber, cacert, nonce2, transid2, false, null, null);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, "CMPKEYIDTESTPROFILE", 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resprev, issuerDN, userDN, cacert, nonce2, transid2, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(issuerDN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, "keyIDTestUser");
            } catch (NotFoundException e) {
                // NOPMD
            }
            try {
                endEntityManagementSession.deleteUser(admin, "keyidtest2");
            } catch (NotFoundException e) {
                // NOPMD
            }
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
        
        v.add(new DERObjectIdentifier(CertTools.UPN_OBJECTID));
        v.add(new DERTaggedObject(true, 0, new DERUTF8String("boo@bar")));
        GeneralName gn = GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v)));
        vec.add(gn);
        
        v = new ASN1EncodableVector();
        v.add(new DERObjectIdentifier("2.5.5.6"));
        v.add(new DERTaggedObject(true, 0, new DERIA5String( "2.16.528.1.1007.99.8-1-993000027-N-99300011-00.000-00000000" )));
        gn = GeneralName.getInstance(new DERTaggedObject(false, 0, new DERSequence(v)));
        vec.add(gn);
        
        GeneralNames san = GeneralNames.getInstance(new DERSequence(vec));
        
        ExtensionsGenerator gen = new ExtensionsGenerator();
        gen.addExtension(Extension.subjectAlternativeName, false, san);
        Extensions exts = gen.generate();
        
        String userDN = "CN=TestAltNameUser";
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final int reqId;
        String fingerprint = null;
        
        try {
            final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, exts, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            fingerprint = CertTools.getFingerprintAsString(cert);
            
        } finally {
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, "TestAltNameUser", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            } catch (NotFoundException e) {}
            
            try{
                internalCertStoreSession.removeCertificate(fingerprint);
            } catch(Exception e) {}
        }    
        
    }
    
    @Test
    public void test05SubjectSerialNumber() throws Exception {

        // Set requirement of unique subjectDN serialnumber to be true
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        boolean requiredUniqueSerialnumber = cainfo.isDoEnforceUniqueSubjectDNSerialnumber();
        // Set the CA to enforce unique serialnumber
        cainfo.setDoEnforceUniqueSubjectDNSerialnumber(true);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.editCA(admin, cainfo);

        // Create a new good user
        String username = "subjectsnuser";
        String userDN = "CN=" + username + ",SN=1234567,C=SE";
        try {
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();
            int reqId;

            PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            BigInteger serialnumber = cert.getSerialNumber();

            // create a second user with the same serialnumber, but spelled "SERIALNUMBER" instead of "SN"
            userDN = "CN=subjectsnuser2,SERIALNUMBER=1234567,C=SE";
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpFailMessage(resp, "Error: SubjectDN Serialnumber already exists.", CmpPKIBodyConstants.ERRORMESSAGE, reqId,
                    PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);

            // Revoke the created certificate
            final PKIMessage con = genRevReq(issuerDN, userDN, serialnumber, cacert, nonce, transid, false, null, null);
            Assert.assertNotNull(con);
            PKIMessage revmsg = protectPKIMessage(con, false, PBEPASSWORD, null, 567);
            final ByteArrayOutputStream baorev = new ByteArrayOutputStream();
            final DEROutputStream outrev = new DEROutputStream(baorev);
            outrev.writeObject(revmsg);
            final byte[] barev = baorev.toByteArray();
            // Send request and receive response
            final byte[] resprev = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resprev, issuerDN, userDN, cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revstatus = checkRevokeStatus(issuerDN, serialnumber);
            Assert.assertEquals("Certificate revocation failed.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, revstatus);

            cainfo.setDoEnforceUniqueSubjectDNSerialnumber(requiredUniqueSerialnumber);
            caAdminSession.editCA(admin, cainfo);
        } finally {
            endEntityManagementSession.deleteUser(admin, username);
        }
    }

    @Test
    public void test06CrmfEcdsaCA() throws Exception {
        final String oldIssuerDN = issuerDN;
        final X509Certificate oldCaCert = cacert;
        try {
            createEllipticCurveDsaCa();
            CAInfo caInfo = caSession.getCAInfo(admin, "TESTECDSA");
            cmpConfiguration.setRACAName(cmpAlias, "TESTECDSA");
            globalConfSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

            issuerDN = caInfo.getSubjectDN(); // Make sure this CA is used for the test
            cacert = (X509Certificate)caInfo.getCertificateChain().iterator().next();
            final KeyPair key1 = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
            final String userName1 = "cmptestecdsa1";
            final String userDN1 = "C=SE,O=PrimeKey,CN=" + userName1;
            try {
                // check that we can get a certificate from this ECDSA CA.
                X509Certificate cert = crmfHttpUserTest(userDN1, key1, null, null, X9ObjectIdentifiers.ecdsa_with_SHA1.getId());
                assertNotNull(cert);
                // Check that this was really signed using SHA256WithECDSA and that the users key algo is in there
                assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmTools.getSignatureAlgorithm(cert));
                // Keyspec we get back from AlgorithmTools.getKeySpecification seems to differ between OracleJDK and OpenJDK so we only check key type
                assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(cert.getPublicKey()));
            } finally {
                try {
                    endEntityManagementSession.deleteUser(admin, userName1);
                } catch (NotFoundException e) {
                }
            }
        } finally {
            // Reset this test class as it was before this test
            issuerDN = oldIssuerDN;
            cacert = oldCaCert;
            cmpConfiguration.setRACAName(cmpAlias, "TestCA");
            globalConfSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
            removeTestCA("TESTECDSA");
        }
    }

    @Test
    public void test07EscapedCharsInDN() throws Exception {

        final String username = "another\0nullguy%00<do>";
        final String userDN = "CN=" + username + ", C=SE";
        
        final byte[] nonce = CmpMessageHelper.createSenderNonce();
        final byte[] transid = CmpMessageHelper.createSenderNonce();
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        final int reqId;
        try {
        final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(StringTools.strip(userDN), cacert, resp, reqId);
        } finally {
            String escapedName = StringTools.stripUsername(username);
            try {
                endEntityManagementSession.revokeAndDeleteUser(admin, escapedName, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } catch (NotFoundException e) {
                log.debug("Failed to delete user: " + escapedName);
            }
        }
    } 

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, caid);
        
        Assert.assertTrue("Unable to restore server configuration.", configurationSession.restoreConfiguration());
        cmpConfiguration.removeAlias(cmpAlias);
        globalConfSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
        
        // Remove test profiles
        certProfileSession.removeCertificateProfile(admin, "CMPTESTPROFILE");
        certProfileSession.removeCertificateProfile(admin, "CMPKEYIDTESTPROFILE");
        eeProfileSession.removeEndEntityProfile(admin, "CMPTESTPROFILE");
        eeProfileSession.removeEndEntityProfile(admin, "CMPKEYIDTESTPROFILE");
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
}
