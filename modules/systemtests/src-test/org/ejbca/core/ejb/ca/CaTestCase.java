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
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.Assert;

/**
 * This class represents an abstract class for all tests which require testing
 * CAs.
 * 
 * @version $Id$
 */
public abstract class CaTestCase extends RoleUsingTestCase {

    public static final String TEST_RSA_REVERSE_CA_NAME = "TESTRSAREVERSE";
    public static final String TEST_RSA_REVSERSE_CA_DN = CertTools.stringToBCDNString("CN=TESTRSAReverse,O=FooBar,OU=BarFoo,C=SE");

    private final static Logger log = Logger.getLogger(CaTestCase.class);

    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);  
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private SimpleAuthenticationProviderRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderRemote.class);

    private String roleName;

    protected TestX509CertificateAuthenticationToken caAdmin;

    public abstract String getRoleName();

    protected void setUp() throws Exception {
        roleName = getRoleName();
        super.setUpAuthTokenAndRole(getRoleName());
        removeTestCA(); // We cant be sure this CA was not left over from
        createTestCA();

        final Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=CaUser,CN=CaUser"));
        caAdmin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
        final X509Certificate certificate = caAdmin.getCertificate();

        RoleData role = roleAccessSession.findRole(roleName);
        if (role == null) {
            log.error("Role should not be null here.");
            role = roleManagementSession.create(roleMgmgToken, roleName);
        }
        final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(roleName, AccessRulesConstants.ROLE_ROOT, AccessRuleState.RULE_ACCEPT, true));
        role = roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        final List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(roleName, CertTools.getIssuerDN(certificate).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, CertTools.getPartFromDN(CertTools.getSubjectDN(certificate), "CN")));
        roleManagementSession.addSubjectsToRole(roleMgmgToken, role, accessUsers);

        accessControlSession.forceCacheExpire();
    }

    protected void tearDown() throws Exception {
        super.tearDownRemoveRole();
        removeTestCA();
        RoleData role = roleAccessSession.findRole(roleName);
        if (role != null) {
            roleManagementSession.remove(roleMgmgToken, role);
        }
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws CAExistsException
     */
    private boolean createTestCA() throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        return createTestCA(getTestCAName(), 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws CAExistsException
     */
    public boolean createTestCA(int keyStrength) throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        return createTestCA(getTestCAName(), keyStrength);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws CAExistsException
     */
    public static boolean createTestCA(String caName) throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        return createTestCA(caName, 1024);
    }

    /**
     * Makes sure the Test CA exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws CAExistsException
     */
    public static boolean createTestCA(String caName, int keyStrength) throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        return createTestCA(caName, keyStrength, "CN=" + caName, CAInfo.SELFSIGNED, null);
    }

    /**
     * Make sure testCA exist.
     * 
     * @param caName
     *            The CA name
     * @param keyStrength
     * @param dn
     *            DN of the CA
     * @param signedBy
     *            id of the signing CA
     * @return
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws InvalidAlgorithmException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws CAExistsException
     */
    public static boolean createTestCA(String caName, int keyStrength, String dn, int signedBy, Collection<Certificate> certificateChain)
            throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        log.trace(">createTestCA");

        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        
        // Search for requested CA
        try {
            caSession.getCAInfo(internalAdmin, caName);
            return true;
        } catch (CADoesntExistsException e) {
            // Ignore this state, continue instead. This is due to a lack of an exists-method in CaSession
        }

        // Create request CA, if necessary
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf(keyStrength));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        // Create and active OSCP CA Service.
        List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, "CN=XKMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        // Set the CMS service non-active by default
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo cainfo = new X509CAInfo(dn, caName, CAConstants.CA_ACTIVE, new Date(), "",
                signedBy == CAInfo.SELFSIGNED ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 3650, null, // Expiretime
                CAInfo.CATYPE_X509, signedBy, certificateChain, catokeninfo, "JUnit RSA CA", -1, null, null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList<Integer>(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // Authority Information Access
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices, false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
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

        caAdminSession.createCA(internalAdmin, cainfo);

        final CAInfo info = caSession.getCAInfo(internalAdmin, caName);
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
        if (certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) == null) {
            log.error("CA certificate not available in database!!");
            return false;
        }
        log.trace("<createTestCA: "+info.getCAId());
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
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        CAInfo cainfo = caSession.getCAInfo(admin, getTestCAId(caName));
        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            cacert = certiter.next();
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
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private void removeTestCA() throws AuthorizationDeniedException {
        removeTestCA(getTestCAName());
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public static void removeTestCA(String caName) throws AuthorizationDeniedException {
        // Search for requested CA
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class);        
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        try {
            CA ca = caTestSession.getCA(internalAdmin, caName);
            caSession.removeCA(internalAdmin, ca.getCAId());
        } catch (CADoesntExistsException e) {
            //Ignore
        }
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
        Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
        Iterator<Certificate> i = userCerts.iterator();
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
                approvalExecutionSession.approve(approvingAdmin, approvalID, approval, globalConfigurationSession.getCachedGlobalConfiguration());
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

    protected void createTestRSAReverseCa(AuthenticationToken admin) throws CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, InvalidAlgorithmException {
        String dn = TEST_RSA_REVSERSE_CA_DN;
        String name = TEST_RSA_REVERSE_CA_NAME;

        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + dn, "", "1024",
                AlgorithmConstants.KEYALGORITHM_RSA));

        Properties prop = catokeninfo.getProperties();
        // Set some CA token properties if they are not set already
        if (prop.getProperty(CryptoToken.KEYSPEC_PROPERTY) == null) {
            prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("1024"));
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        if (prop.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING) == null) {
            prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        }
        catokeninfo.setProperties(prop);

        X509CAInfo cainfo = new X509CAInfo(
                dn,
                name,
                CAConstants.CA_ACTIVE,
                new Date(),
                "",
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                365,
                null, // Expiretime
                CAInfo.CATYPE_X509,
                CAInfo.SELFSIGNED,
                (Collection<Certificate>) null,
                catokeninfo,
                "JUnit RSA CA, we ned also a very long CA description for this CA, because we want to create a CA Data string that is more than 36000 characters or something like that. All this is because Oracle can not set very long strings with the JDBC provider and we must test that we can handle long CAs",
                -1, null, null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                0, // Delta CRL period
                new ArrayList<Integer>(), true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint
                null, // defaultcrlissuer
                null, // defaultocsplocator
                null, // Authority Information Access
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices, false, // use default utf8 settings
                new ArrayList<Integer>(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
                false, // Use X500 DN order
                false, // Use CRL Distribution Point on CRL
                false, // CRL Distribution Point on CRL critical
                true, // Include in health check
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true, // useCertReqHistory
                true, // useUserStorage
                true, // useCertificateStorage
                null // cmpRaAuthSecret
        );

        caAdminSession.createCA(admin, cainfo);
    }
    
    /**
     * 
     * @return an AuthenticationToken which matches the default test CA
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     */
    public AuthenticationToken createCaAuthenticatedToken() throws CADoesntExistsException, AuthorizationDeniedException {
        String subjectDn = CertTools.getSubjectDN(getTestCACert());
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal(subjectDn));
        Set<Certificate> credentials = new HashSet<Certificate>();
        credentials.add(getTestCACert());
        AuthenticationSubject subject = new AuthenticationSubject(principals, credentials);
        return simpleAuthenticationProvider.authenticate(subject);
    }
}
