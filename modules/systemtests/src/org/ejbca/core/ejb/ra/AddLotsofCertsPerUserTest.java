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
import java.util.Date;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
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
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Add a lot of users and a lot of certificates for each user 
 *
 * @version $Id$
 */
public class AddLotsofCertsPerUserTest extends TestCase {
    private static final Logger log = Logger.getLogger(AddLotsofCertsPerUserTest.class);

    private IUserAdminSessionRemote userAdminSession = TestTools.getUserAdminSession();
    private ISignSessionRemote signSession = TestTools.getSignSession();
    private IRaAdminSessionRemote raAdminSession = TestTools.getRaAdminSession();
    private ICertificateStoreSessionRemote certificateStoreSession = TestTools.getCertificateStoreSession();
    private ICreateCRLSessionRemote createCrlSession = TestTools.getCreateCRLSession();

    private int userNo = 0;
    private KeyPair keys;

    /**
     * Creates a new TestAddLotsofUsers object.
     */
    public AddLotsofCertsPerUserTest(String name) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        super(name);
        CertTools.installBCProviderIfNotAvailable();
        keys = KeyTools.genKeys("2048", "RSA");
    }

    protected void setUp() throws Exception {
        TestTools.createTestCA();
    }

    protected void tearDown() throws Exception {
        TestTools.removeTestCA();
    }

    private String genUserName(String baseUsername) {
        userNo++;
        return baseUsername + userNo;
    }

    private String genRandomPwd() throws Exception {
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        return password;
    }

    /**
     * tests creating 10 users, each with 50 active, 50 revoked, 50 expired and 50 expired and "archived"
     *
     * @throws Exception on error
     */
    public void test01Create2000Users() throws Exception {
        log.trace(">test01Create2000Users()");
        final Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);
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
            	certificateStoreSession.addCertificateProfile(administrator, certificateProfileName, certificateProfile);
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
        	UserDataVO userdata = new UserDataVO(username, CertTools.stringToBCDNString(dn), TestTools.getTestCAId(), subjectaltname, 
        			email, UserDataConstants.STATUS_NEW, type, profileid, certificatetypeid,
        			null,null, token, hardtokenissuerid, null);
        	userdata.setPassword(password);
            if (userAdminSession.findUser(administrator, username) != null) {
                log.warn("User already exists in the database.");
            } else {
            	userAdminSession.addUser(administrator, userdata, true);
            }
            // Create some valid certs
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                signSession.createCertificate(administrator, username, password, keys.getPublic());
            }
            // Create some revoked certs
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            }

            int cid = certificateStoreSession.getCertificateProfileId(administrator, certificateProfileName);
            int eid = raAdminSession.getEndEntityProfileId(administrator, endEntityProfileName);
            if (eid == 0) {
                EndEntityProfile endEntityProfile = new EndEntityProfile(true);
                endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES , 0, "" + cid);
                endEntityProfile.setUse(EndEntityProfile.ENDTIME, 0, true);
                //endEntityProfile.setValue(EndEntityProfile.ENDTIME, 0, "0:0:10");
                raAdminSession.addEndEntityProfile(administrator, endEntityProfileName, endEntityProfile);
                eid = raAdminSession.getEndEntityProfileId(administrator, endEntityProfileName);
            }
            userdata.setEndEntityProfileId(eid);
            ExtendedInformation extendedInformation = userdata.getExtendedinformation();
            extendedInformation.setCustomData(EndEntityProfile.ENDTIME, "0:0:10");
            userdata.setExtendedinformation(extendedInformation);
            userdata.setCertificateProfileId(cid);
            userAdminSession.changeUser(administrator, userdata, true);
            // Create some soon-to-be-expired certs
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            }
            // Create some expired and archived
            for (int j=0; j<CERTS_OF_EACH_KIND; j++) {
                userAdminSession.setClearTextPassword(administrator, username, password);
            	userAdminSession.setUserStatus(administrator, username, UserDataConstants.STATUS_NEW);
                Certificate certificate = signSession.createCertificate(administrator, username, password, keys.getPublic());
                userAdminSession.revokeCert(administrator, CertTools.getSerialNumber(certificate), CertTools.getIssuerDN(certificate),
                		username, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
                createCrlSession.setArchivedStatus(CertTools.getFingerprintAsString(certificate));
            }
            raAdminSession.removeEndEntityProfile(administrator, endEntityProfileName);
            certificateStoreSession.removeCertificateProfile(administrator, certificateProfileName);
            if (i % 10 == 0) {
                log.debug("Created " + i + " users...");
            }
        }
        log.debug("Created 2000 users!");
        log.trace("<test01Create2000Users()");
    }
}
