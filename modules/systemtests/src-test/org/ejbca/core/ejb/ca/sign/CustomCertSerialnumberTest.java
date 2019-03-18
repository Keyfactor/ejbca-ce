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

package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @version $Id$
 */
public class CustomCertSerialnumberTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CustomCertSerialnumberTest.class);

    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CustomCertSerialnumberTest"));

    private static int rsacaid = 0;

    private int fooCertProfileId;
    private int fooEEProfileId;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateRequestSessionRemote certificateRequestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        CAInfo inforsa = caSession.getCAInfo(internalAdmin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();

        certificateProfileSession.removeCertificateProfile(internalAdmin, "FOOCERTPROFILE");
        endEntityProfileSession.removeEndEntityProfile(internalAdmin, "FOOEEPROFILE");

        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowKeyUsageOverride(true);
        certprof.setAllowCertSerialNumberOverride(true);
        certificateProfileSession.addCertificateProfile(internalAdmin, "FOOCERTPROFILE", certprof);
        fooCertProfileId = certificateProfileSession.getCertificateProfileId("FOOCERTPROFILE");

        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, Integer.toString(fooCertProfileId));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfileId));
        profile.setValue(EndEntityProfile.AVAILKEYSTORE, 0, Integer.toString(SecConst.TOKEN_SOFT_BROWSERGEN));
        assertTrue(profile.getUse(EndEntityProfile.CERTSERIALNR, 0));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, "FOOEEPROFILE", profile);
        fooEEProfileId = endEntityProfileSession.getEndEntityProfileId("FOOEEPROFILE");
      
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        try {
            endEntityManagementSession.deleteUser(internalAdmin, "foo");
            log.debug("deleted user: foo");
        } catch (Exception e) {
        }
        try {
            endEntityManagementSession.deleteUser(internalAdmin, "foo2");
            log.debug("deleted user: foo2");
        } catch (Exception e) {
        }
        try {
            endEntityManagementSession.deleteUser(internalAdmin, "foo3");
            log.debug("deleted user: foo3");
        } catch (Exception e) {
        }

        certificateStoreSession.revokeAllCertByCA(internalAdmin, caSession.getCAInfo(internalAdmin, rsacaid).getSubjectDN(),
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
    }

    // Create certificate request for user: foo with cert serialnumber=1234567890
    @Test
    public void test01CreateCertWithCustomSN() throws InvalidAlgorithmParameterException, OperatorCreationException, IOException,
            EndEntityExistsException, AuthorizationDeniedException, EndEntityProfileValidationException, EjbcaException, CesecoreException,
            CertificateExtensionException, CertificateParsingException, CertificateEncodingException {
     log.trace(">test01CreateCustomCert()");

        KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        BigInteger serno = SernoGeneratorRandom.instance(20).getSerno();
        log.debug("serno: " + serno);

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo"),
                rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(req.toASN1Structure().getEncoded());
        p10.setUsername("foo");
        p10.setPassword("foo123");

        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER),
                fooEEProfileId, fooCertProfileId, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
        ExtendedInformation ei = new ExtendedInformation();
        ei.setCertificateSerialNumber(serno);
        user.setExtendedInformation(ei);
        ResponseMessage resp = certificateRequestSession.processCertReq(internalAdmin, user, p10, X509ResponseMessage.class);

        X509Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), X509Certificate.class);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.debug("foo certificate serialnumber: " + cert.getSerialNumber());
        assertTrue(cert.getSerialNumber().compareTo(serno) == 0);

        log.trace("<test01CreateCustomCert()");

    }

    // Create certificate request for user: foo2 with random cert serialnumber
    @Test
    public void test02CreateCertWithRandomSN() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException, EndEntityExistsException, AuthorizationDeniedException, EndEntityProfileValidationException, EjbcaException,
            ClassNotFoundException, CertificateEncodingException, CertificateException, InvalidAlgorithmParameterException, CesecoreException, OperatorCreationException, CertificateExtensionException {

        log.trace(">test02CreateCertWithRandomSN()");

        KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        BigInteger serno = ((X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername("foo")).iterator().next()).getSerialNumber();
        log.debug("foo serno: " + serno);

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo2"),
                rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(req.toASN1Structure().getEncoded());
        p10.setUsername("foo2");
        p10.setPassword("foo123");

        EndEntityInformation user = new EndEntityInformation("foo2", "C=SE,O=AnaTom,CN=foo2", rsacaid, null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER),
                fooEEProfileId, fooCertProfileId, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");

        ResponseMessage resp = certificateRequestSession.processCertReq(internalAdmin, user, p10, X509ResponseMessage.class);

        X509Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), X509Certificate.class);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.debug("foo2 certificate serialnumber: " + cert.getSerialNumber());
        assertTrue(cert.getSerialNumber().compareTo(serno) != 0);

        log.trace("<test02CreateCertWithRandomSN()");
    }

    // Create certificate request for user: foo3 with cert serialnumber=1234567890 (the same as cert serialnumber of user foo)
    @Test
    public void test03CreateCertWithDublicateSN() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException, EndEntityExistsException, AuthorizationDeniedException,
            EndEntityProfileValidationException, ClassNotFoundException, CertificateEncodingException, CertificateException,
            WaitingForApprovalException, InvalidAlgorithmParameterException, EjbcaException, OperatorCreationException, CertificateExtensionException {
        log.trace(">test03CreateCertWithDublicateSN()");

        KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        BigInteger serno = ((X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername("foo")).iterator().next()).getSerialNumber();
        log.debug("foo serno: " + serno);

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo3"),
                rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(req.toASN1Structure().getEncoded());
        p10.setUsername("foo3");
        p10.setPassword("foo123");

        EndEntityInformation user = new EndEntityInformation("foo3", "C=SE,O=AnaTom,CN=foo3", rsacaid, null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER),
                fooEEProfileId, fooCertProfileId, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
        ExtendedInformation ei = new ExtendedInformation();
        ei.setCertificateSerialNumber(serno);
        user.setExtendedInformation(ei);

        ResponseMessage resp = null;
        try {
            resp = certificateRequestSession.processCertReq(internalAdmin, user, p10, X509ResponseMessage.class);
        } catch (CesecoreException e) {
            log.debug(e.getMessage());
            assertTrue("Unexpected exception.",
                    e.getMessage().startsWith("There is already a certificate stored in 'CertificateData' with the serial number"));
        }
        assertNull(resp);
    }

    @Test
    public void test04CreateCertWithCustomSNNotAllowed() throws EndEntityProfileExistsException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException, EndEntityExistsException, AuthorizationDeniedException,
            EndEntityProfileValidationException, EjbcaException, ClassNotFoundException, CertificateEncodingException, CertificateException,
            WaitingForApprovalException, InvalidAlgorithmParameterException, OperatorCreationException, CertificateExtensionException {
        log.trace(">test04CreateCertWithCustomSNNotAllowed()");

        KeyPair rsakeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        BigInteger serno = SernoGeneratorRandom.instance(8).getSerno();
        log.debug("serno: " + serno);

        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo"),
                rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(req.getEncoded());
        p10.setUsername("foo");
        p10.setPassword("foo123");

        CertificateProfile fooCertProfile = certificateProfileSession.getCertificateProfile("FOOCERTPROFILE");
        fooCertProfile.setAllowCertSerialNumberOverride(false);
        certificateProfileSession.changeCertificateProfile(internalAdmin, "FOOCERTPROFILE", fooCertProfile);

        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER),
                fooEEProfileId, fooCertProfileId, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setPassword("foo123");
        ExtendedInformation ei = new ExtendedInformation();
        ei.setCertificateSerialNumber(serno);
        user.setExtendedInformation(ei);
        try {
            certificateRequestSession.processCertReq(internalAdmin, user, p10, X509ResponseMessage.class);
            assertTrue("This method should throw exception", false);
        } catch (CesecoreException e) {
            assertTrue(e.getMessage().contains("not allowing certificate serial number override"));
        }
        log.trace("<test04CreateCertWithCustomSNNotAllowed()");
    }

    public String getRoleName() {
        return "";
    }
}