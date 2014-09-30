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
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.approval.ApprovalExecutionSession;
import org.ejbca.core.ejb.approval.ApprovalSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
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
    public static final String TEST_ECDSA_CA_NAME = "TESTECDSA";
    public static final String TEST_ECGOST3410_CA_NAME = "TESTECGOST3410";
    public static final String TEST_DSTU4145_CA_NAME = "TESTDSTU4145";
    public static final String TEST_ECDSA_IMPLICIT_CA_NAME = "TESTECDSAImplicitlyCA";
    public static final String TEST_SHA256_WITH_MFG1_CA_NAME = "TESTSha256WithMGF1";
    public static final String TEST_SHA256_WITH_MFG1_CA_DN = "CN="+TEST_SHA256_WITH_MFG1_CA_NAME;
    public static final String TEST_RSA_REVSERSE_CA_DN = CertTools.stringToBCDNString("CN=TESTRSAReverse,O=FooBar,OU=BarFoo,C=SE"); 
    public static final String TEST_CVC_RSA_CA_DN = "CN=TESTCVCA,C=SE";
    public static final String TEST_CVC_RSA_CA_NAME = "TESTCVCA";
    public static final String TEST_CVC_ECC_CA_DN = "CN=TCVCAEC,C=SE";
    public static final String TEST_CVC_ECC_CA_NAME = "TESTCVCAECC";
    public static final String TEST_CVC_ECC_DOCUMENT_VERIFIER_DN = "CN=TDVEC-D,C=SE";
    public static final String TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME = "TESTDVECC-D";
    public static final String TEST_DSA_CA_NAME = "TESTDSA";

    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final static Logger log = Logger.getLogger(CaTestCase.class);

    protected static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));

    protected TestX509CertificateAuthenticationToken caAdmin;

    public abstract String getRoleName();

    protected void setUp() throws Exception { // NOPMD: this is a base class
        log.trace(">CaTestCase.setUp()");
        super.setUpAuthTokenAndRole(getRoleName());
        removeTestCA(); // We can't be sure this CA was not left over from
        createTestCA();
        addDefaultRole();
    }
    
    protected void addDefaultRole() throws RoleExistsException, AuthorizationDeniedException, AccessRuleNotFoundException, RoleNotFoundException {
        String roleName = getRoleName();
        final Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal("C=SE,O=CaUser,CN=CaUser"));
        final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = getAuthenticationProviderSession();
        caAdmin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider.authenticate(new AuthenticationSubject(principals, null));
        final X509Certificate certificate = caAdmin.getCertificate();

        final RoleManagementSessionRemote roleManagementSession = getRoleManagementSession();
        RoleData role = CaTestCase.getRoleAccessSession().findRole(roleName);
        if (role == null) {
            log.error("Role should not be null here.");
            role = roleManagementSession.create(internalAdmin, roleName);
        }
        final List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(roleName, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
        role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);

        final List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(roleName, CertTools.getIssuerDN(certificate).hashCode(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, CertTools.getPartFromDN(
                        CertTools.getSubjectDN(certificate), "CN")));
        roleManagementSession.addSubjectsToRole(internalAdmin, role, accessUsers);

        final AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
        accessControlSession.forceCacheExpire();
    }

    protected void tearDown() throws Exception { // NOPMD: this is a base class
        log.trace(">CaTestCase.tearDown()");
        super.tearDownRemoveRole();
        removeTestCA();
        removeDefaultRole();
    }
    
    protected void removeDefaultRole() throws RoleNotFoundException, AuthorizationDeniedException {
        RoleAccessSessionRemote roleAccessSession = CaTestCase.getRoleAccessSession();
        RoleData role = roleAccessSession.findRole(getRoleName());
        if (role != null) {
            CaTestCase.getRoleManagementSession().remove(internalAdmin, role);
        }
    }
    
    private static SimpleAuthenticationProviderSessionRemote getAuthenticationProviderSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    }

    private static RoleManagementSessionRemote getRoleManagementSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    }

    private static CaSessionRemote getCaSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    }

    private static RoleAccessSessionRemote getRoleAccessSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
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
    public static boolean createTestCA() throws CADoesntExistsException, AuthorizationDeniedException, CAExistsException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeTestCA(); // We cant be sure this CA was not left over from
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
    public static boolean createTestCA(String caName, int keyStrength) throws CADoesntExistsException, AuthorizationDeniedException,
            CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
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
        log.trace(">createTestCA("+caName+", "+dn+")");
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        final CaSessionRemote caSession = getCaSession();
        final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        // Search for requested CA
        try {
            caSession.getCAInfo(internalAdmin, caName);
            log.debug("CA with name " + caName+" already exists, returning true from createTestCA.");
            return true;
        } catch (CADoesntExistsException e) {
            log.debug("CA with name " + caName+" does not exist, move on to try to rename a CA with same Id");
            // Ignore this state, continue instead. This is due to a lack of an exists-method in CaSession
        }
        
        try {
            CAInfo cainfo = caSession.getCAInfo(internalAdmin, dn.hashCode() );
            caSession.renameCA(internalAdmin, cainfo.getName(), caName);
            log.debug("CA with name " + cainfo.getName()+" was renamed to "+caName+"', returning true from createTestCA.");
            return true;
        } catch (CADoesntExistsException e) {
            log.debug("CA with id " + dn.hashCode()+" can not be renamed to '"+caName+"', because strangely CAinfo id and name does not match (or multiple threads are messing with the same CA.");
            // Ignore this state, continue instead. This is due to a lack of an exists-method in CaSession
        }
        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, caName, String.valueOf(keyStrength));
        log.debug("Creating CryptoToken with id " + cryptoTokenId + " to be used by CA " + caName);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE, "CN=XKMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        // Set the CMS service non-active by default
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo cainfo = new X509CAInfo(dn, caName, CAConstants.CA_ACTIVE,
                signedBy == CAInfo.SELFSIGNED ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA
                        : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 3650, signedBy, certificateChain, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
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
        log.trace("<createTestCA: " + info.getCAId());
        return true;
    }

    /** @return the caid of the test CA */
    public static int getTestCAId() {
        return getTestCAId(getTestCAName());
    }

    /** @return the CA certificate */
    public static Certificate getTestCACert() throws CADoesntExistsException, AuthorizationDeniedException {
        return getTestCACert(getTestCAName());
    }

    /** @return the CA certificate */
    public static Certificate getTestCACert(String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        Certificate cacert = null;
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        CAInfo cainfo = CaTestCase.getCaSession().getCAInfo(admin, getTestCAId(caName));
        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            cacert = certiter.next();
        } else {
            log.error("NO CACERT for caid " + getTestCAId(caName));
        }

        return cacert;
    }

    /** @return the name of the test CA */
    public static String getTestCAName() {
        return "TEST";
    }

    /** @return the caid of a test CA with subject DN CN=caName */
    public static int getTestCAId(String caName) {
        return ("CN=" + caName).hashCode();
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @return true if successful
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    public static void removeTestCA() throws AuthorizationDeniedException {
        removeTestCA(getTestCAName());
    }

    /** Removes the Test-CA if it exists. */
    public static void removeTestCA(String caName) throws AuthorizationDeniedException {
    	final CaSessionRemote caSession = CaTestCase.getCaSession();
        final CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        int cryptoTokenId = 0;
        try {
            CA ca = caTestSession.getCA(internalAdmin, caName);
            cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, ca.getCAId());
        } catch (CADoesntExistsException e) {
            log.debug("CA with name " + caName + " does not exist and can not be removed (probably not a problem here).");
        }
        log.debug("Deleting CryptoToken with id " + cryptoTokenId + " last used by CA " + caName);
        cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
    }

    /** Removes the Test-CA if it exists. */
    public static void removeTestCA(int caId) throws AuthorizationDeniedException {
        final CaSessionRemote caSession = CaTestCase.getCaSession();
        final CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        int cryptoTokenId = 0;
        try {
            CA ca = caTestSession.getCA(internalAdmin, caId);
            cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, ca.getCAId());
        } catch (CADoesntExistsException e) {
            log.debug("CA with id " + caId + " does not exist and can not be removed (probably not a problem here).");
        }
        log.debug("Deleting CryptoToken with id " + cryptoTokenId + " last used by CA " + caId);
        cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
    }

    /** Generate random password */
    public static final String genRandomPwd() {
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    }

    /** Generate random user */
    public static final String genRandomUserName() {
        Random rand = new Random(System.nanoTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return username;
    }

    /**
     * Find all certificates for a user and approve any outstanding revocation.
     */
    protected int approveRevocation(AuthenticationToken internalAdmin, AuthenticationToken approvingAdmin, String username, int reason,
            int approvalType, CertificateStoreSession certificateStoreSession, ApprovalSession approvalSession,
            ApprovalExecutionSession approvalExecutionSession, int approvalCAID) throws Exception {
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
                approvalExecutionSession.approve(approvingAdmin, approvalID, approval);
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
        return CaTestCase.getCaSession().getCAInfo(admin, name);
    }

    public static void createTestRSAReverseCa(AuthenticationToken admin) throws CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, InvalidAlgorithmException {
        String dn = TEST_RSA_REVSERSE_CA_DN;
        String name = TEST_RSA_REVERSE_CA_NAME;
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + dn, "", "1024",
                AlgorithmConstants.KEYALGORITHM_RSA));
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, name, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        final X509CAInfo cainfo = new X509CAInfo(dn, name, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA, we ned also a very long CA description for this CA, because we want to create a CA Data string that is more than 36000 characters or something like that. All this is because Oracle can not set very long strings with the JDBC provider and we must test that we can handle long CAs");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        cainfo.setUseLdapDnOrder(false); // not sure if this is correct, but it was false before the X509CAInfo refactoring
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(admin, cainfo);
    }

    /** @return an AuthenticationToken which matches the default test CA */
    public AuthenticationToken createCaAuthenticatedToken() throws CADoesntExistsException, AuthorizationDeniedException {
        String subjectDn = CertTools.getSubjectDN(getTestCACert());
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new X500Principal(subjectDn));
        Set<Certificate> credentials = new HashSet<Certificate>();
        credentials.add(getTestCACert());
        AuthenticationSubject subject = new AuthenticationSubject(principals, credentials);
        final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = getAuthenticationProviderSession();
        return simpleAuthenticationProvider.authenticate(subject);
    }

    protected static void createRSASha256WithMGF1CA() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeOldCa(TEST_SHA256_WITH_MFG1_CA_NAME, TEST_SHA256_WITH_MFG1_CA_DN);    
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_SHA256_WITH_MFG1_CA_NAME, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + TEST_SHA256_WITH_MFG1_CA_DN, "", "1024",
                AlgorithmConstants.KEYALGORITHM_RSA));
        final X509CAInfo cainfo = new X509CAInfo(TEST_SHA256_WITH_MFG1_CA_DN, TEST_SHA256_WITH_MFG1_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }

    protected static void createEllipticCurveDsaImplicitCa() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeOldCa(TEST_ECDSA_IMPLICIT_CA_NAME);
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_ECDSA_IMPLICIT_CA_NAME, "implicitlyCA");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN="
                + TEST_ECDSA_IMPLICIT_CA_NAME, "", "secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        final X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECDSA_IMPLICIT_CA_NAME, TEST_ECDSA_IMPLICIT_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365,
                CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit ECDSA ImplicitlyCA CA");
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }

    protected static void createEllipticCurveDsaCa() throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmException, AuthorizationDeniedException {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_ECDSA_CA_NAME, "secp256r1");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                "CN=XKMSSignerCertificate, " + "CN=" + TEST_ECDSA_CA_NAME, "", "secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECDSA_CA_NAME, TEST_ECDSA_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit ECDSA CA");
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        removeOldCa(TEST_ECDSA_CA_NAME);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }
    
    protected static void createECGOST3410Ca() throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmException, AuthorizationDeniedException {
        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_ECGOST3410_CA_NAME, keyspec);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                "CN=XKMSSignerCertificate, " + "CN=" + TEST_ECGOST3410_CA_NAME, "", keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECGOST3410_CA_NAME, TEST_ECGOST3410_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit GOST3410 CA");
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        removeOldCa(TEST_ECGOST3410_CA_NAME);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }
    
    protected static void createDSTU4145Ca() throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmException, AuthorizationDeniedException {
        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_DSTU4145_CA_NAME, keyspec);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                "CN=XKMSSignerCertificate, " + "CN=" + TEST_DSTU4145_CA_NAME, "", keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_DSTU4145_CA_NAME, TEST_DSTU4145_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit DSTU4145 CA");
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        removeOldCa(TEST_DSTU4145_CA_NAME);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }

    /** Creates a root CA if one doesn't already exist */
    protected static void createDefaultCvcEccCaDomestic() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        createDefaultCvcEccCaDomestic(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
    }

    /** Creates a root CA if one doesn't already exist */
    protected static void createDefaultCvcEccCaDomestic(int rootProfileId, int subcaProfileId) throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        CaSessionRemote caSession = CaTestCase.getCaSession();
        try {
            caSession.getCAInfo(internalAdmin, TEST_CVC_ECC_CA_NAME);
        } catch(CADoesntExistsException e) {
            createDefaultCvcEccCa(rootProfileId);
        }
        removeOldCa(TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME, TEST_CVC_ECC_DOCUMENT_VERIFIER_DN);        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_CVC_ECC_DOCUMENT_VERIFIER_DN, "secp256r1");
        // TODO: Using ECDSA for decryption seems fishy..!
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);      
        CVCCAInfo cvccainfo = new CVCCAInfo(TEST_CVC_ECC_DOCUMENT_VERIFIER_DN, TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME, CAConstants.CA_ACTIVE,
                subcaProfileId, 3650, TEST_CVC_ECC_CA_DN.hashCode(), null, catoken);
        cvccainfo.setDescription("JUnit CVC CA");
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cvccainfo);
    }
    
    protected static void createDefaultDsaCa() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeOldCa(TEST_DSA_CA_NAME, "CN="+TEST_DSA_CA_NAME);        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_DSA_CA_NAME, "DSA1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=XKMSCertificate, " + "CN=TESTDSA", "", "1024",
                AlgorithmConstants.KEYALGORITHM_DSA));
        X509CAInfo cainfo = new X509CAInfo("CN=TESTDSA", "TESTDSA", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit DSA CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }
    
    protected static void createDefaultCvcEccCa() throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException, AuthorizationDeniedException {
        createDefaultCvcEccCa(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
    }
    
    protected static void createDefaultCvcEccCa(int certProfileId) throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException, AuthorizationDeniedException {
        removeOldCa(TEST_CVC_ECC_CA_NAME, TEST_CVC_ECC_CA_DN);
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_CVC_ECC_CA_NAME, "secp256r1");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        CVCCAInfo cvccainfo = new CVCCAInfo(TEST_CVC_ECC_CA_DN, TEST_CVC_ECC_CA_NAME, CAConstants.CA_ACTIVE,
                certProfileId, 3650, CAInfo.SELFSIGNED, null, catoken);
        cvccainfo.setDescription("JUnit CVC CA");
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cvccainfo);
    }
    
    protected static void createDefaultCvcRsaCA() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        createDefaultCvcRsaCA(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
    }
    
    protected static void createDefaultCvcRsaCA(int certProfileId) throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeOldCa(TEST_CVC_RSA_CA_NAME, TEST_CVC_RSA_CA_DN);
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_CVC_RSA_CA_NAME, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1);
        CVCCAInfo cvccainfo = new CVCCAInfo(TEST_CVC_RSA_CA_DN, TEST_CVC_RSA_CA_NAME, CAConstants.CA_ACTIVE,
                certProfileId, 3650, CAInfo.SELFSIGNED, null, catoken);
        cvccainfo.setDescription("JUnit CVC CA");
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cvccainfo);
    }
    
    /** Preemptively remove CA in case it was created by a previous run. */
    protected static void removeOldCa(String caName, String dn) throws AuthorizationDeniedException {
        final CaSessionRemote caSession = CaTestCase.getCaSession();
        try {
            CAInfo info = caSession.getCAInfo(internalAdmin, caName);
            final int cryptoTokenId = info.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, info.getCAId());
            cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
            internalCertificateStoreSession.removeCertificatesBySubject(dn);
        } catch (CADoesntExistsException e) {
            // NOPMD: we ignore this
        }
    }
    
    protected static void removeOldCa(String caName) throws AuthorizationDeniedException {
        removeOldCa(caName, "CN="+caName);
    }
}
