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
package org.ejbca.core.ejb.ca;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.EJB;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;

/**
 * This class represents an abstract class for all tests which require testing
 * CAs.
 * 
 * @author mikek
 * 
 */
public abstract class CaTestCase extends TestCase {
    private static final String DEFAULT_SUPERADMIN_CN = "SuperAdmin";
    
    private final static Logger log = Logger.getLogger(CaTestCase.class);

    protected Admin admin;

    @EJB
    private AuthorizationSessionRemote authorizationSession;
    
    @EJB
    protected CAAdminSessionRemote caAdminSessionRemote;
    
    @EJB
    private CertificateStoreSessionRemote certificateStoreSession;
    
    @EJB
    private RaAdminSessionRemote raAdminSession;

    public CaTestCase() {
        super();
        setupInterfaces();
    }

    public CaTestCase(String name) {
        super(name);
        setupInterfaces();
    }

    public void setupInterfaces() {
        admin = new Admin(Admin.TYPE_INTERNALUSER);
    }

    public void setUp() throws Exception {
        super.setUp();
    }

    public void tearDown() throws Exception {
        super.tearDown();
        admin = null;
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     */
    public boolean createTestCA() {
        return createTestCA(getTestCAName(), 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     */
    public boolean createTestCA(int keyStrength) {
        return createTestCA(getTestCAName(), keyStrength);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     */
    public boolean createTestCA(String caName) {
        return createTestCA(caName, 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     */
    public boolean createTestCA(String caName, int keyStrength) {
        log.trace(">createTestCA");
        try {
            authorizationSession.initialize(admin, ("CN=" + caName).hashCode(), DEFAULT_SUPERADMIN_CN);
        } catch (AdminGroupExistsException e) {
            log.error("", e);
        }
        // Search for requested CA

        CAInfo caInfo = caAdminSessionRemote.getCAInfo(admin, caName);
        if (caInfo != null) {
            return true;
        }

        // Create request CA, if necessary
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignKeySpec("" + keyStrength);
        catokeninfo.setEncKeySpec("" + keyStrength);
        catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        ArrayList extendedcaservices = new ArrayList();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, "CN=XKMSCertificate, " + "CN=" + caName, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));

        X509CAInfo cainfo = new X509CAInfo("CN=" + caName, caName, SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA, 3650, null, // Expiretime
                CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, (Collection) null, catokeninfo, "JUnit RSA CA", -1, null, null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices, false, // use default utf8 settings
                new ArrayList(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                true, // Use LDAP DN order by default
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true // useCertReqHistory
        );

        try {
            caAdminSessionRemote.createCA(admin, cainfo);
        } catch (Exception e) {
            log.error("", e);
            return false;
        }
        CAInfo info;

        info = caAdminSessionRemote.getCAInfo(admin, caName);

        X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
        if (!cert.getSubjectDN().toString().equals("CN=" + caName)) {
            log.error("Error in created CA certificate!");
            return false;
        }
        if (!info.getSubjectDN().equals("CN=" + caName)) {
            log.error("Creating CA failed!");
            return false;
        }
        try {
            if (certificateStoreSession.findCertificateByFingerprint(admin, CertTools.getCertFingerprintAsString(cert.getEncoded())) == null) {
                log.error("CA certificate not available in database!!");
                return false;
            }
        } catch (CertificateEncodingException e) {
            log.error("", e);
            return false;
        }
        log.trace("<createTestCA");
        return true;
    }

    /**
     * @return the caid of the test CA
     */
    public int getTestCAId() {
        return getTestCAId(getTestCAName());
    }

    /**
     * @return the CA certificate
     */
    public Certificate getTestCACert() {
        return getTestCACert(getTestCAName());
    }

    /**
     * @return the CA certificate
     */
    public Certificate getTestCACert(String caName) {
        Certificate cacert = null;

        CAInfo cainfo = caAdminSessionRemote.getCAInfo(admin, getTestCAId(caName));
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            cacert = (X509Certificate) certiter.next();
        } else {
            log.error("NO CACERT for caid " + getTestCAId(caName));
        }

        return cacert;
    }

    /**
     * @return the name of the test CA
     */
    public String getTestCAName() {
        return "TEST";
    }

    /**
     * @return the caid of a test CA with subject DN CN=caName
     */
    public int getTestCAId(String caName) {
        return ("CN=" + caName).hashCode();
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @return true if successful
     */
    public boolean removeTestCA() {
        return removeTestCA(getTestCAName());
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @return true if successful
     */
    public boolean removeTestCA(String caName) {
        // Search for requested CA
        try {
            CAInfo caInfo = caAdminSessionRemote.getCAInfo(admin, caName);
            if (caInfo == null) {
                return true;
            }
            caAdminSessionRemote.removeCA(admin, ("CN=" + caName).hashCode());
        } catch (Exception e) {
            log.error("", e);
            return false;
        }
        return true;
    }

    public static final String genRandomPwd() {
        // Generate random password
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd

    public static final String genRandomUserName() {
        // Generate random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return username;
    } // genRandomUserName
    
    /**
     * Find all certificates for a user and approve any outstanding revocation.
     */
    protected int approveRevocation(Admin internalAdmin, Admin approvingAdmin, String username, int reason, int approvalType,
            CertificateStoreSessionRemote certificateStoreSession, ApprovalSessionRemote approvalSession, int approvalCAID) throws Exception {
        Collection userCerts = certificateStoreSession.findCertificatesByUsername(internalAdmin, username);
        Iterator i = userCerts.iterator();
        int approvedRevocations = 0;
        while (i.hasNext()) {
            X509Certificate cert = (X509Certificate) i.next();
            String issuerDN = cert.getIssuerDN().toString();
            BigInteger serialNumber = cert.getSerialNumber();
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
            if ((reason != RevokedCertInfo.NOT_REVOKED && !isRevoked) || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked)) {
                int approvalID;
                if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN);
                } else {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null);
                }
                Query q = new Query(Query.TYPE_APPROVALQUERY);
                q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId=" + approvalCAID, "(endEntityProfileId="
                        + SecConst.EMPTY_ENDENTITYPROFILE + ")").get(0));
                Approval approval = new Approval("Approved during testing.");
                approvalSession.approve(approvingAdmin, approvalID, approval, raAdminSession.loadGlobalConfiguration(new Admin(Admin.INTERNALCAID)));
                approvalData = (ApprovalDataVO) approvalSession.findApprovalDataVO(internalAdmin, approvalID).iterator().next();
                assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
                assertEquals(status.revocationReason, reason);
                approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
                approvedRevocations++;
            }
        }
        return approvedRevocations;
    } 

}
