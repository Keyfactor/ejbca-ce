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

package org.ejbca.core.ejb.ra;

import java.security.KeyPair;
import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Add a lot of users and a lot of certificates for each user 
 *
 * @version $Id$
 */
public class AddLotsofCertsPerUserTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(AddLotsofCertsPerUserTest.class);

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private CertificateStoreSessionRemote storeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private int userNo = 0;
    private KeyPair keys;

    private static final AuthenticationToken administrator = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AddLotsofCertsPerUserTest"));

    /**
     * Creates a new TestAddLotsofUsers object.
     */
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        final CAInfo cainfo = caSession.getCAInfo(administrator, getTestCAName());
        cainfo.setDoEnforceUniquePublicKeys(false);
        caAdminSession.editCA(administrator, cainfo);
        keys = KeyTools.genKeys("2048", "RSA");
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public String getRoleName() {
        return "AddLotsofCertsPerUserTest";
    }

    private String genUserName(String baseUsername) {
        userNo++;
        return baseUsername + userNo;
    }

    /**
     * tests creating 10 users, each with 50 active, 50 revoked, 50 expired and
     * 50 expired and "archived"
     * 
     * @throws Exception
     *             on error
     */
    @Test
    public void test01Create2000Users() throws Exception {
        log.trace(">test01Create2000Users()");
        final String baseUsername = "lotsacertsperuser-" + System.currentTimeMillis() + "-";
        final int NUMBER_OF_USERS = 10;
        final int CERTS_OF_EACH_KIND = 50;
        for (int i = 0; i < NUMBER_OF_USERS; i++) {
            String username = genUserName(baseUsername);
            String password = genRandomPwd();
            final String certificateProfileName = "testLotsOfCertsPerUser";
            final String endEntityProfileName = "testLotsOfCertsPerUser";
            CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            certificateProfile.setAllowValidityOverride(true);
            try {
                certificateProfileSession.addCertificateProfile(administrator, certificateProfileName, certificateProfile);
            } catch (CertificateProfileExistsException e) {
            }

            EndEntityType type = new EndEntityType(EndEntityTypes.ENDUSER);
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            EndEntityInformation userdata = new EndEntityInformation(username, CertTools.stringToBCDNString(dn), getTestCAId(), subjectaltname,
                    email, EndEntityConstants.STATUS_NEW, type, profileid, certificatetypeid, null, null, token, hardtokenissuerid, null);
            userdata.setPassword(password);
            if (endEntityAccessSession.findUser(administrator, username) != null) {
                log.warn("User already exists in the database.");
            } else {
                endEntityManagementSession.addUser(administrator, userdata, true);
            }
            // Create some valid certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                endEntityManagementSession.setClearTextPassword(administrator, username, password);
                endEntityManagementSession.setUserStatus(administrator, username, EndEntityConstants.STATUS_NEW, 0);
                signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(keys.getPublic()));
            }
            // Create some revoked certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                endEntityManagementSession.setClearTextPassword(administrator, username, password);
                endEntityManagementSession.setUserStatus(administrator, username, EndEntityConstants.STATUS_NEW, 0);
                Certificate certificate = signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(keys.getPublic()));
                endEntityManagementSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            }

            int cid = certificateProfileSession.getCertificateProfileId(certificateProfileName);
            int eid = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
            if (eid == 0) {
                EndEntityProfile endEntityProfile = new EndEntityProfile(true);
                endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cid);
                endEntityProfile.setUse(EndEntityProfile.ENDTIME, 0, true);
                // endEntityProfile.setValue(EndEntityProfile.ENDTIME, 0,
                // "0:0:10");
                endEntityProfileSession.addEndEntityProfile(administrator, endEntityProfileName, endEntityProfile);
                eid = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
            }
            userdata.setEndEntityProfileId(eid);
            ExtendedInformation extendedInformation = new ExtendedInformation();
            extendedInformation.setCustomData(EndEntityProfile.ENDTIME, "0:0:10");
            userdata.setExtendedinformation(extendedInformation);
            userdata.setCertificateProfileId(cid);
            endEntityManagementSession.changeUser(administrator, userdata, true);
            // Create some soon-to-be-expired certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                endEntityManagementSession.setClearTextPassword(administrator, username, password);
                endEntityManagementSession.setUserStatus(administrator, username, EndEntityConstants.STATUS_NEW, 0);
                Certificate certificate = signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(keys.getPublic()));
                endEntityManagementSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            }
            // Create some expired and archived
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                endEntityManagementSession.setClearTextPassword(administrator, username, password);
                endEntityManagementSession.setUserStatus(administrator, username, EndEntityConstants.STATUS_NEW, 0);
                Certificate certificate = signSession.createCertificate(administrator, username, password, new PublicKeyWrapper(keys.getPublic()));
                endEntityManagementSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                storeSession.setStatus(administrator, CertTools.getFingerprintAsString(certificate), CertificateConstants.CERT_ARCHIVED);
            }
            endEntityProfileSession.removeEndEntityProfile(administrator, endEntityProfileName);
            certificateProfileSession.removeCertificateProfile(administrator, certificateProfileName);
            if (i % 10 == 0) {
                log.debug("Created " + i + " users...");
            }
        }
        log.debug("Created 2000 users!");
        log.trace("<test01Create2000Users()");
    }
}
