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

package org.ejbca.core.ejb.ra;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

/**
 * Add a lot of users and a lot of certificates for each user 
 *
 * @version $Id$
 */
public class AddLotsofCertsPerUserTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(AddLotsofCertsPerUserTest.class);

    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private CertificateStoreSessionRemote storeSession = InterfaceCache.getCertificateStoreSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();

    private int userNo = 0;
    private KeyPair keys;

    final Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

    /**
     * Creates a new TestAddLotsofUsers object.
     */
    public AddLotsofCertsPerUserTest(String name) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        super(name);
        CryptoProviderTools.installBCProviderIfNotAvailable();
        keys = KeyTools.genKeys("2048", "RSA");
    }

    public void setUp() throws Exception {
        createTestCA();
        final CAInfo cainfo = caAdminSession.getCAInfo(administrator, getTestCAName());
        cainfo.setDoEnforceUniquePublicKeys(false);
        caAdminSession.editCA(administrator, cainfo);
    }

    public void tearDown() throws Exception {
        removeTestCA();
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
            CertificateProfile certificateProfile = new EndUserCertificateProfile();
            certificateProfile.setAllowValidityOverride(true);
            try {
                certificateProfileSession.addCertificateProfile(administrator, certificateProfileName, certificateProfile);
            } catch (CertificateProfileExistsException e) {
            }

            int type = SecConst.USER_ENDUSER;
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            UserDataVO userdata = new UserDataVO(username, CertTools.stringToBCDNString(dn), getTestCAId(), subjectaltname, email,
                    UserDataConstants.STATUS_NEW, type, profileid, certificatetypeid, null, null, token, hardtokenissuerid, null);
            userdata.setPassword(password);
            if (userAdminSession.findUser(administrator, username) != null) {
                log.warn("User already exists in the database.");
            } else {
                userAdminSession.addUser(administrator, userdata, true);
            }
            // Create some valid certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
                userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                signSession.createCertificate(administrator, username, password, keys.getPublic());
            }
            // Create some revoked certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
                userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            }

            int cid = certificateProfileSession.getCertificateProfileId(administrator, certificateProfileName);
            int eid = endEntityProfileSession.getEndEntityProfileId(administrator, endEntityProfileName);
            if (eid == 0) {
                EndEntityProfile endEntityProfile = new EndEntityProfile(true);
                endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cid);
                endEntityProfile.setUse(EndEntityProfile.ENDTIME, 0, true);
                // endEntityProfile.setValue(EndEntityProfile.ENDTIME, 0,
                // "0:0:10");
                endEntityProfileSession.addEndEntityProfile(administrator, endEntityProfileName, endEntityProfile);
                eid = endEntityProfileSession.getEndEntityProfileId(administrator, endEntityProfileName);
            }
            userdata.setEndEntityProfileId(eid);
            ExtendedInformation extendedInformation = new ExtendedInformation();
            extendedInformation.setCustomData(EndEntityProfile.ENDTIME, "0:0:10");
            userdata.setExtendedinformation(extendedInformation);
            userdata.setCertificateProfileId(cid);
            userAdminSession.changeUser(administrator, userdata, true);
            // Create some soon-to-be-expired certs
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
                userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            }
            // Create some expired and archived
            for (int j = 0; j < CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
                userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                        RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                storeSession.setArchivedStatus(new Admin(Admin.TYPE_INTERNALUSER), CertTools.getFingerprintAsString(certificate));
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
