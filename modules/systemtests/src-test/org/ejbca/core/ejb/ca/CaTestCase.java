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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

/**
 * This class represents an abstract class for all tests which require testing CAs.
 * 
 * @version $Id$
 */
public abstract class CaTestCase extends RoleUsingTestCase {

    private final static Logger log = Logger.getLogger(CaTestCase.class);

    private CAAdminSessionRemote caAdminSessionRemote = null;
    private CaSessionRemote caSession = null;
    private CertificateStoreSessionRemote certificateStoreSession = null;
    private GlobalConfigurationSessionRemote globalConfigurationSession = null;

    protected String roleName = "CaTestCase";

    @Before
    public void setUp() throws Exception {
        super.setUpAuthTokenAndRole(roleName);
        removeTestCA(); // We cant be sure this CA was not left over from
        createTestCA();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDownRemoveRole();
        removeTestCA();
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private boolean createTestCA() throws CADoesntExistsException, AuthorizationDeniedException {
        return createTestCA(getTestCAName(), 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public boolean createTestCA(int keyStrength) throws CADoesntExistsException, AuthorizationDeniedException {
        return createTestCA(getTestCAName(), keyStrength);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public boolean createTestCA(String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        return createTestCA(caName, 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public boolean createTestCA(String caName, int keyStrength) throws CADoesntExistsException, AuthorizationDeniedException {
        return createTestCA(caName, keyStrength, "CN=" + caName, CAInfo.SELFSIGNED, null);
    }

    /**
     * Make sure testCA exist.
     * 
     * @param caName The CA name
     * @param keyStrength
     * @param dn DN of the CA
     * @param signedBy id of the signing CA
     * @return
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public boolean createTestCA(String caName, int keyStrength, String dn, int signedBy, Collection certificateChain) throws CADoesntExistsException,
            AuthorizationDeniedException {
        log.trace(">createTestCA");
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

        // Search for requested CA
        CAInfo caInfo = this.caSession.getCAInfo(admin, caName);
        if (caInfo != null) {
            return true;
        }
        // Create request CA, if necessary
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        // Create and active OSCP CA Service.
        ArrayList extendedcaservices = new ArrayList();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, "CN=XKMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        /*
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
        		"CN=CMSCertificate, " + dn,
        		"",
        		""+keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        */
        X509CAInfo cainfo = new X509CAInfo(dn, caName, SecConst.CA_ACTIVE, new Date(), "",
                signedBy == CAInfo.SELFSIGNED ? SecConst.CERTPROFILE_FIXED_ROOTCA : SecConst.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                CAInfo.CATYPE_X509, signedBy, certificateChain, catokeninfo, "JUnit RSA CA", -1, null, null, // PolicyId
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
                true, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null // cmpRaAuthSecret
        );

        try {
            this.caAdminSessionRemote.createCA(admin, cainfo);
        } catch (Exception e) {
            log.error("", e);
            return false;
        }
        final CAInfo info = this.caSession.getCAInfo(admin, caName);
        final String normalizedDN = CertTools.stringToBCDNString(dn);
        final X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
        final String normalizedCertDN = CertTools.stringToBCDNString(cert.getSubjectDN().toString());
        if (!normalizedCertDN.equals(normalizedDN)) {
            log.error("CA certificate DN is not what it should. Is '" + normalizedDN + "'. Should be '" + normalizedCertDN + "'.");
            return false;
        }
        if (!info.getSubjectDN().equals(normalizedCertDN)) {
            log.error("Creating CA failed!");
            return false;
        }
        if (this.certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) == null) {
            log.error("CA certificate not available in database!!");
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
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public Certificate getTestCACert() throws CADoesntExistsException, AuthorizationDeniedException {
        return getTestCACert(getTestCAName());
    }

    /**
     * @return the CA certificate
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public Certificate getTestCACert(String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        Certificate cacert = null;
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        CAInfo cainfo = caSession.getCAInfo(admin, getTestCAId(caName));
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
    private boolean removeTestCA() {
        return removeTestCA(getTestCAName());
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @return true if successful
     */
    public boolean removeTestCA(String caName) {
        // Search for requested CA
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
        try {
            final CAInfo caInfo = this.caSession.getCAInfo(admin, caName);
            if (caInfo == null) {
                return true;
            }
            this.caSession.removeCA(admin, caInfo.getCAId());
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
            password += (Integer.valueOf(randint)).toString();
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
            username += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return username;
    } // genRandomUserName

    /**
     * Find all certificates for a user and approve any outstanding revocation.
     */
    protected int approveRevocation(AuthenticationToken internalAdmin, AuthenticationToken approvingAdmin, String username, int reason,
            int approvalType, CertificateStoreSessionRemote certificateStoreSession, ApprovalSessionRemote approvalSession,
            ApprovalExecutionSessionRemote approvalExecutionSession, int approvalCAID) throws Exception {
        log.debug("approvingAdmin=" + approvingAdmin.toString() + " username=" + username + " reason=" + reason + " approvalType=" + approvalType
                + " approvalCAID=" + approvalCAID);
        Collection userCerts = certificateStoreSession.findCertificatesByUsername(username);
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
                ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId=" + approvalCAID,
                        "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")").get(0));
                Approval approval = new Approval("Approved during testing.");
                approvalExecutionSession.approve(approvingAdmin, approvalID, approval,
                        globalConfigurationSession.getCachedGlobalConfiguration(internalAdmin));
                approvalData = (ApprovalDataVO) approvalSession.findApprovalDataVO(internalAdmin, approvalID).iterator().next();
                Assert.assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
                Assert.assertEquals(status.revocationReason, reason);
                approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
                approvedRevocations++;
            }
        }
        return approvedRevocations;
    }

    public CAInfo getCAInfo(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException {
        return this.caSession.getCAInfo(admin, name);
    }
}
