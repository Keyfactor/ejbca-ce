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
import java.util.Arrays;
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
import org.cesecore.authorization.control.StandardRules;
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
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionProxyRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
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

    private final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private final ApprovalSessionProxyRemote approvalSessionProxyRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionProxyRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final static Logger log = Logger.getLogger(CaTestCase.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));

    protected TestX509CertificateAuthenticationToken caAdmin;

    public abstract String getRoleName();

    protected void setUp() throws Exception { // NOPMD: this is a base class
        log.trace(">CaTestCase.setUp()");
        super.setUpAuthTokenAndRole(getRoleName()+"Base");
        removeTestCA(); // We can't be sure this CA was not left over from
        createTestCA();
        addDefaultRole();
    }
    
    protected void addDefaultRole() throws RoleExistsException {
        final String commonName = CaTestCase.class.getCanonicalName();
        caAdmin = getRoleInitializationSession().createAuthenticationTokenAndAssignToNewRole("C=SE,O=Test,CN="+commonName, null, getRoleName(),
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
    }

    protected void tearDown() throws Exception { // NOPMD: this is a base class
        log.trace(">CaTestCase.tearDown()");
        super.tearDownRemoveRole();
        removeTestCA();
        removeDefaultRole();
    }
    
    protected void removeDefaultRole() throws RoleNotFoundException, AuthorizationDeniedException {
        getRoleInitializationSession().removeAllAuthenticationTokensRoles(caAdmin);
    }
    
    private static SimpleAuthenticationProviderSessionRemote getAuthenticationProviderSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    }

    private static CaSessionRemote getCaSession() {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
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
        if(caSession.existsCa(caName)) {
            log.debug("CA with name " + caName+" already exists, returning true from createTestCA.");
            return true;
        }
                
        try {
            CAInfo cainfo = caSession.getCAInfo(internalAdmin, dn.hashCode());
            if (cainfo != null) {
                caSession.renameCA(internalAdmin, cainfo.getName(), caName);
                log.debug("CA with name " + cainfo.getName() + " was renamed to " + caName + "', returning true from createTestCA.");
                return true;
            }
        } catch (CADoesntExistsException e) {
            log.debug("CA with id " + dn.hashCode() + " can not be renamed to '" + caName
                    + "', because strangely CAinfo id and name does not match (or multiple threads are messing with the same CA.");
            // Ignore this state, continue instead. 
        }
        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, caName, String.valueOf(keyStrength));
        log.debug("Creating CryptoToken with id " + cryptoTokenId + " to be used by CA " + caName);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        // Set the CMS service non-active by default
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, " + dn, "", "" + keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo cainfo = new X509CAInfo(dn, caName, CAConstants.CA_ACTIVE,
                signedBy == CAInfo.SELFSIGNED ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA
                        : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d", signedBy, certificateChain, catoken);
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
    public static Certificate getTestCACertUsingItsName(final String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        return getTestCACert(caName);
    }

    
    /** @return the CA certificate */
    public static Certificate getTestCACert() throws CADoesntExistsException, AuthorizationDeniedException {
        return getTestCACert(getTestCAName());
    }

    /** @return the CA certificate */
    public static Certificate getTestCACert(String caName) throws CADoesntExistsException, AuthorizationDeniedException {
        Certificate cacert = null;
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        CAInfo cainfo = CaTestCase.getCaSession().getCAInfo(admin, caName);
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

    /** @return the CA ID of a test CA, and if not found it falls back to assuming subject DN CN=caNames */
    public static int getTestCAId(String caName) {
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaTestCase"));
        CAInfo cainfo = null;
        try {
            cainfo = CaTestCase.getCaSession().getCAInfo(admin, caName);
        } catch (AuthorizationDeniedException e) {
            log.info("Authorization denied while getting the CA ID by its name " + caName, e);
        }
        if (cainfo != null) {
            return cainfo.getCAId();
        } else {
            return ("CN=" + caName).hashCode();
        }
    }

    /**
     * Removes the Test-CA if it exists.
     * 
     * @throws AuthorizationDeniedException
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
        CA ca = caTestSession.getCA(internalAdmin, caName);
        if (ca != null) {
            cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, ca.getCAId());
            internalCertificateStoreSession.removeCertificatesBySubject(ca.getSubjectDN());
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
        CA ca = caTestSession.getCA(internalAdmin, caId);
        if (ca != null) {
            cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, ca.getCAId());
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
            int approvalType, int approvalCAID, final ApprovalProfile approvalProfile, final int sequenceId, final int partitionId) throws Exception {
        log.debug("approvingAdmin=" + approvingAdmin.toString() + " username=" + username + " reason=" + reason + " approvalType=" + approvalType
                + " approvalCAID=" + approvalCAID);
        Collection<CertificateWrapper> wrappedCertificates = certificateStoreSession.findCertificatesByUsername(username);
        Collection<Certificate> userCerts = EJBTools.unwrapCertCollection(wrappedCertificates);
        int approvedRevocations = 0;
        for(Certificate cert : userCerts) {
            String issuerDN = CertTools.getIssuerDN(cert);
            BigInteger serialNumber = CertTools.getSerialNumber(cert);
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
            if ((reason != RevokedCertInfo.NOT_REVOKED && !isRevoked) || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked)) {
                int approvalID;
                if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN, approvalProfile.getProfileName());
                } else {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null, approvalProfile.getProfileName());
                }
                Query q = new Query(Query.TYPE_APPROVALQUERY);
                q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                List<ApprovalDataVO> queryResults = approvalSessionProxyRemote.query(q, 0, 1, "cAId=" + approvalCAID,
                        "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
                if (queryResults.size() > 0) {
                    ApprovalDataVO approvalData = queryResults.get(0);
                    Approval approval = new Approval("Approved during testing.", sequenceId, partitionId);
                    approvalExecutionSession.approve(approvingAdmin, approvalID, approval);
                    approvalData = approvalSession.findApprovalDataVO(approvalID).iterator().next();
                    Assert.assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                    CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
                    Assert.assertEquals(status.revocationReason, reason);
                    approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
                    approvedRevocations++;
                }
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
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, name, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        final X509CAInfo cainfo = new X509CAInfo(dn, name, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
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
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        final X509CAInfo cainfo = new X509CAInfo(TEST_SHA256_WITH_MFG1_CA_DN, TEST_SHA256_WITH_MFG1_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
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
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        final X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECDSA_IMPLICIT_CA_NAME, TEST_ECDSA_IMPLICIT_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d",
                CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit ECDSA ImplicitlyCA CA");
        cainfo.setPolicies(policies);
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cainfo);
    }

    protected static void createEllipticCurveDsaCa() throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
    InvalidAlgorithmException, AuthorizationDeniedException {
        createEllipticCurveDsaCa("secp256r1");
    }
    protected static void createEllipticCurveDsaCa(final String keySpec) throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmException, AuthorizationDeniedException {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_ECDSA_CA_NAME, keySpec);
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECDSA_CA_NAME, TEST_ECDSA_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
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
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_ECGOST3410_CA_NAME, TEST_ECGOST3410_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
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
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
        policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
        X509CAInfo cainfo = new X509CAInfo("CN=" + TEST_DSTU4145_CA_NAME, TEST_DSTU4145_CA_NAME, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
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
        if(!caSession.existsCa(TEST_CVC_ECC_CA_NAME)) {
            createDefaultCvcEccCa(rootProfileId);
        }
        removeOldCa(TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME, TEST_CVC_ECC_DOCUMENT_VERIFIER_DN);        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_CVC_ECC_DOCUMENT_VERIFIER_DN, "secp256r1");
        // TODO: Using ECDSA for decryption seems fishy..!
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);      
        CVCCAInfo cvccainfo = new CVCCAInfo(TEST_CVC_ECC_DOCUMENT_VERIFIER_DN, TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME, CAConstants.CA_ACTIVE,
                subcaProfileId, "3650d", TEST_CVC_ECC_CA_DN.hashCode(), null, catoken);
        cvccainfo.setDescription("JUnit CVC CA");
        CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cvccainfo);
    }
    
    protected static void createDefaultDsaCa() throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        removeOldCa(TEST_DSA_CA_NAME, "CN="+TEST_DSA_CA_NAME);        
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(null, TEST_DSA_CA_NAME, "DSA1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active Extended CA Services.
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        X509CAInfo cainfo = new X509CAInfo("CN=TESTDSA", "TESTDSA", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
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
                certProfileId, "3650d", CAInfo.SELFSIGNED, null, catoken);
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
                certProfileId, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cvccainfo.setDescription("JUnit CVC CA");
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        caAdminSession.createCA(internalAdmin, cvccainfo);
    }
    
    /** Preemptively remove CA in case it was created by a previous run. */
    protected static void removeOldCa(String caName, String dn) throws AuthorizationDeniedException {
        final CaSessionRemote caSession = CaTestCase.getCaSession();
        CAInfo info = caSession.getCAInfo(internalAdmin, caName);
        if (info != null) {
            final int cryptoTokenId = info.getCAToken().getCryptoTokenId();
            caSession.removeCA(internalAdmin, info.getCAId());
            cryptoTokenManagementSession.deleteCryptoToken(internalAdmin, cryptoTokenId);
        }
        internalCertificateStoreSession.removeCertificatesBySubject(dn);

    }
    
    protected static void removeOldCa(String caName) throws AuthorizationDeniedException {
        removeOldCa(caName, "CN="+caName);
    }
}
