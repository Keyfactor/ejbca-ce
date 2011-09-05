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

package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import javax.ejb.FinderException;
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.cert.SeisCardNumberExtension;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests signing session.
 * 
 * Since all the CAs from "TestCAs" is required, you should run it manually
 * before running this test and "RemoveCAs" after.
 * 
 * @version $Id$
 */
public class SignSessionTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(SignSessionTest.class);

    private static byte[] keytoolp10 = Base64.decode(("MIIBbDCB1gIBADAtMQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY+ATE4ZB0oKfmXStu8J+do0GhTag6rOGtoydI"
            + "eNX9DdytlsmXDyONKl8746478/3HXdx9rA0RevUizKSataMpDsb3TjprRjzBTvYPZSIfzko6s8g6"
            + "AZLO07xCFOoDmyRzb9k/KEZsMls0ujx79CQ9p5K4rg2ksjmDeW7DaPMphQIDAQABoAAwDQYJKoZI"
            + "hvcNAQEFBQADgYEAyJVobqn6wGRoEsdHxjoqPXw8fLrQyBGEwXccnVpI4kv9iIZ45Xres0LrOwtS"
            + "kFLbpn0guEzhxPBbL6mhhmDDE4hbbHJp1Kh6gZ4Bmbb5FrwpvUyrSjTIwwRC7GAT00A1kOjl9jCC" + "XCfJkJH2QleCy7eKANq+DDTXzpEOvL/UqN0=").getBytes());
    private static byte[] iep10 = Base64.decode(("MIICnTCCAgYCAQAwGzEZMBcGA1UEAxMQNkFFSzM0N2Z3OHZXRTQyNDCBnzANBgkq"
            + "hkiG9w0BAQEFAAOBjQAwgYkCgYEAukW70HN9bt5x2AiSZm7y8GXQuyp1jN2OIvqU" + "sr0dzLIOFt1H8GPJkL80wx3tLDj3xJfWJdww3TqExsxMSP+qScoYKIOeNBb/2OMW"
            + "p/k3DThCOewPebmt+M08AClq5WofXTG+YxyJgXWbMTNfXKIUyR0Ju4Spmg6Y4eJm" + "GXTG7ZUCAwEAAaCCAUAwGgYKKwYBBAGCNw0CAzEMFgo1LjAuMjE5NS4yMCAGCisG"
            + "AQQBgjcCAQ4xEjAQMA4GA1UdDwEB/wQEAwIE8DCB/wYKKwYBBAGCNw0CAjGB8DCB" + "7QIBAR5cAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwBy"
            + "AHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAu" + "ADADgYkAjuYPzZPpbLgCWYnXoNeX2gS6nuI4osrWHlQQKcS67VJclhELlnT3hBb9"
            + "Blr7I0BsJ/lguZvZFTZnC1bMeNULRg17bhExTg+nUovzPcJhMvG7G3DR17PrJ7V+" + "egHAsQV4dQC2hOGGhOnv88JhP9Pwpso3t2tqJROa5ZNRRSJSkw8AAAAAAAAAADAN"
            + "BgkqhkiG9w0BAQQFAAOBgQCL5k4bJt265j63qB/9GoQb1XFOPSar1BDFi+veCPA2" + "GJ/vRXt77Vcr4inx9M51iy87FNcGGsmyesBoDg73p06UxpIDhkL/WpPwZAfQhWGe"
            + "o/gWydmP/hl3uEfE0E4WG02UXtNwn3ziIiJM2pBCGQQIN2rFggyD+aTxwAwOU7Z2" + "fw==").getBytes());
    private static byte[] keytooldsa = Base64.decode(("MIICNjCCAfQCAQAwMTERMA8GA1UEAxMIRFNBIFRlc3QxDzANBgNVBAoTBkFuYXRvbTELMAkGA1UE"
            + "BhMCU0UwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/"
            + "gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfG"
            + "G/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKS"
            + "uYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZV4661FlP5nEH"
            + "EIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFuo38L+iE1YvH7YnoBJDvMpPG+"
            + "qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOBhQACgYEAiVCUaC95mHaU3C9odWcuJ8j3fT6z"
            + "bSR02CVFC0F6QO5s2Tx3JYWrm5aAjWkXWJfeYOR6qBSwX0R1US3rDI0Kepsrdco2q7wGSo+235KL"
            + "Yfl7tQ9RLOKUGX/1c5+XuvN1ZbGy0yUw3Le16UViahWmmx6FM1sW6M48U7C/CZOyoxagADALBgcq"
            + "hkjOOAQDBQADLwAwLAIUQ+S2iFA1y7dfDWUCg7j1Nc8RW0oCFFhnDlU69xFRMeXXn1C/Oi+8pwrQ").getBytes());

    private static final String CERTPROFILE_PRIVKEYUSAGEPERIOD = "TestPrivKeyUsagePeriodCertProfile";
    private static final String EEPROFILE_PRIVKEYUSAGEPERIOD = "TestPrivKeyUsagePeriodEEProfile";
    private static final String USER_PRIVKEYUSAGEPERIOD = "fooprivkeyusageperiod";
    private static final String DN_PRIVKEYUSAGEPERIOD = "C=SE,CN=testprivatekeyusage";
    
    private static KeyPair rsakeys = null;
    private static KeyPair rsakeys2 = null;
    private static KeyPair rsakeyPrivKeyUsagePeriod;
    private static KeyPair ecdsakeys = null;
    private static KeyPair ecdsasecpkeys = null;
    private static KeyPair ecdsaimplicitlyca = null;
    private static KeyPair dsakeys = null;
    private int rsacaid = 0;
    private int rsareversecaid = 0;
    private int ecdsacaid = 0;
    private int ecdsaimplicitlycacaid = 0;
    private int rsamgf1cacaid = 0;
    private int cvccaid = 0;
    private int cvccaecid = 0;
    private int dsacaid = 0;

    private X509Certificate rsacacert = null;
    private X509Certificate rsarevcacert = null;
    private X509Certificate ecdsacacert = null;
    private X509Certificate ecdsaimplicitlycacacert = null;
    private X509Certificate rsamgf1cacacert = null;
    private Certificate cvccacert = null;
    private Certificate cvcdveccert = null;
    private Certificate cvcaeccert = null;
    private X509Certificate dsacacert = null;
    
    private final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CertReqHistorySessionRemote certReqHistorySession = InterfaceCache.getCertReqHistorySession();
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();

    private CAInfo inforsa;

    @BeforeClass
    public static void beforeClass() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
       
        if (rsakeys == null) {
            rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            System.out.println("generating RSA keys...");
        }
        if (rsakeys2 == null) {
            rsakeys2 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
        if (rsakeyPrivKeyUsagePeriod == null) {
            rsakeyPrivKeyUsagePeriod = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
        if (ecdsakeys == null) {
            ecdsakeys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        }
        if (ecdsasecpkeys == null) {
            ecdsasecpkeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        }
        if (ecdsaimplicitlyca == null) {
            ecdsaimplicitlyca = KeyTools.genKeys("implicitlyCA", AlgorithmConstants.KEYALGORITHM_ECDSA);
        }
        if (dsakeys == null) {
            dsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_DSA);
        }
        // Add this again since it will be removed by the other tests in the
        // batch..
       
        inforsa = caSession.getCAInfo(admin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();

        CAInfo inforsareverse = null;
        try {
            inforsareverse = caSession.getCAInfo(admin, "TESTRSAREVERSE");
        } catch (CADoesntExistsException e) {
            createTestRSAReverseCa(admin);
        }
        assertTrue("No active RSA Reverse CA! Must have at least one active reverse CA to run tests!", inforsareverse != null);
        rsareversecaid = inforsareverse.getCAId();
       
        CAInfo infoecdsa = caSession.getCAInfo(admin, "TESTECDSA");
        assertTrue("No active ECDSA CA! Must have at least one active CA to run tests!", infoecdsa != null);
        ecdsacaid = infoecdsa.getCAId();
        CAInfo infoecdsaimplicitlyca = caSession.getCAInfo(admin, "TESTECDSAImplicitlyCA");
        assertTrue("No active ECDSA ImplicitlyCA CA! Must have at least one active CA to run tests!", infoecdsaimplicitlyca != null);
        ecdsaimplicitlycacaid = infoecdsaimplicitlyca.getCAId();
        CAInfo inforsamgf1ca = caSession.getCAInfo(admin, "TESTSha256WithMGF1");
        assertTrue("No active RSA MGF1 CA! Must have at least one active CA to run tests!", inforsamgf1ca != null);
        rsamgf1cacaid = inforsamgf1ca.getCAId();
        CAInfo infocvcca = caSession.getCAInfo(admin, "TESTDV-D");
        assertTrue("No active CVC CA! Must have at least one active CA to run tests!", infocvcca != null);
        cvccaid = infocvcca.getCAId();
        CAInfo infocvccaec = caSession.getCAInfo(admin, "TESTDVECC-D");
        assertTrue("No active CVC EC CA! Must have at least one active CA to run tests!", infocvccaec != null);
        cvccaecid = infocvccaec.getCAId();
        CAInfo infodsa = caSession.getCAInfo(admin, "TESTDSA");
        assertTrue("No active DSA CA! Must have at least one active CA to run tests!", infodsa != null);
        dsacaid = infodsa.getCAId();
        Collection<Certificate> coll = inforsa.getCertificateChain();
        Object[] objs = coll.toArray();
        rsacacert = (X509Certificate) objs[0];
        coll = inforsareverse.getCertificateChain();
        objs = coll.toArray();
        rsarevcacert = (X509Certificate) objs[0];
        coll = infoecdsa.getCertificateChain();
        objs = coll.toArray();
        ecdsacacert = (X509Certificate) objs[0];
        coll = infoecdsaimplicitlyca.getCertificateChain();
        objs = coll.toArray();
        ecdsaimplicitlycacacert = (X509Certificate) objs[0];
        coll = inforsamgf1ca.getCertificateChain();
        objs = coll.toArray();
        rsamgf1cacacert = (X509Certificate) objs[0];
        coll = infocvcca.getCertificateChain();
        objs = coll.toArray();
        cvccacert = (Certificate) objs[0];
        coll = infocvccaec.getCertificateChain();
        objs = coll.toArray();
        cvcdveccert = (Certificate) objs[0];
        cvcaeccert = (Certificate) objs[1];
        coll = infodsa.getCertificateChain();
        objs = coll.toArray();
        dsacacert = (X509Certificate) objs[0];
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Delete test end entity profile
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");
        } catch (Exception e) { /* ignore */
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTISSUANCEREVREASON");
        } catch (Exception e) { /* ignore */
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, "TESTDNOVERRIDE");
        } catch (Exception e) { /* ignore */
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, EEPROFILE_PRIVKEYUSAGEPERIOD);
        } catch (Exception ignored) { /* ignore */
        }
        try {
            certificateProfileSession.removeCertificateProfile(admin, CERTPROFILE_PRIVKEYUSAGEPERIOD);
        } catch (Exception e) { /* ignore */
        }
        try {
            certificateProfileSession.removeCertificateProfile(admin, "TESTDNOVERRIDE ");
        } catch (Exception e) { /* ignore */
        }
        try {
        	endEntityProfileSession.removeEndEntityProfile(admin, "FOOEEPROFILE");
        } catch (Exception e) { /* ignore */
        }
        try {
        	certificateProfileSession.removeCertificateProfile(admin, "FOOCERTPROFILE");
        } catch (Exception e) { /* ignore */
        }
        // delete users that we know...
        try {
            userAdminSession.deleteUser(admin, "foo");
            log.debug("deleted user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "fooecdsa");
            log.debug("deleted user: fooecdsa, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "foorev");
            log.debug("deleted user: fooecdsa, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "fooecdsaimpca");
            log.debug("deleted user: fooecdsaimpca, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "foorsamgf1ca");
            log.debug("deleted user: fooecdsa, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "cvc");
            log.debug("deleted user: cvc, foo123, C=SE,CN=TESTCVC");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "cvcec");
            log.debug("deleted user: cvcec, foo123, C=SE,CN=TCVCEC");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, "foodsa");
            log.debug("deleted user: foodsa, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (Exception e) { /* ignore */
        }
        try {
            userAdminSession.deleteUser(admin, USER_PRIVKEYUSAGEPERIOD);
            log.debug("deleted user: " + USER_PRIVKEYUSAGEPERIOD + ", foo123, " + DN_PRIVKEYUSAGEPERIOD);
        } catch (Exception e) { /* ignore */
        }
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    private void createUsers() throws CertificateProfileExistsException, AuthorizationDeniedException, EndEntityProfileExistsException, PersistenceException, CADoesntExistsException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException, FinderException {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowKeyUsageOverride(true);
        certificateProfileSession.addCertificateProfile(admin, "FOOCERTPROFILE", certprof);
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId("FOOCERTPROFILE");

        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        endEntityProfileSession.addEndEntityProfile(admin, "FOOEEPROFILE", profile);
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(admin, "FOOEEPROFILE");

    	// Make user that we know...
    	if (!userAdminSession.existsUser(admin, "foo")) {
    		userAdminSession.addUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo", null, "foo@anatom.se", false, fooEEProfile, fooCertProfile,
    				SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
    		if (log.isDebugEnabled()) {
    			log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
    		}
    	} else {
    		log.info("User foo already exists, resetting status.");
    		userAdminSession.changeUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo", null, "foo@anatom.se", false, fooEEProfile, fooCertProfile,
    				SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsacaid);
    		if (log.isDebugEnabled()) {
    			log.debug("Reset status to NEW");
    		}
    	}

    	if (!userAdminSession.existsUser(admin, "foorev")) {
    		userAdminSession.addUser(admin, "foorev", "foo123", "C=SE,O=AnaTom,CN=foorev", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
    				SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsareversecaid);
    		log.debug("created user: foorev, foo123, C=SE, O=AnaTom, CN=foorev");
    	} else {
    		log.info("User foorev already exists, resetting status.");
    		userAdminSession.changeUser(admin, "foorev", "foo123", "C=SE,O=AnaTom,CN=foorev", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
    				SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsareversecaid);
    		log.debug("Reset status to NEW");
    	}

    	if (!userAdminSession.existsUser(admin, "fooecdsa")) {
    		userAdminSession.addUser(admin, "fooecdsa", "foo123", "C=SE,O=AnaTom,CN=fooecdsa", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
    				SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ecdsacaid);
    		log.debug("created user: fooecdsa, foo123, C=SE, O=AnaTom, CN=fooecdsa");
    	} else {
    		log.info("User fooecdsa already exists, resetting status.");
    		userAdminSession.setUserStatus(admin, "fooecdsa", UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}

    	if (!userAdminSession.existsUser(admin, "fooecdsaimpca")) {
    		userAdminSession.addUser(admin, "fooecdsaimpca", "foo123", "C=SE,O=AnaTom,CN=fooecdsaimpca", null, "foo@anatom.se", false,
    				SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
    				ecdsaimplicitlycacaid);
    		log.debug("created user: fooecdsaimpca, foo123, C=SE, O=AnaTom, CN=fooecdsaimpca");
    	} else {
    		log.info("User fooecdsaimpca already exists, resetting status.");
    		userAdminSession.setUserStatus(admin, "fooecdsaimpca", UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}

    	if (!userAdminSession.existsUser(admin, "foorsamgf1ca")) {
    		userAdminSession.addUser(admin, "foorsamgf1ca", "foo123", "C=SE,O=AnaTom,CN=foorsamgf1ca", null, "foo@anatom.se", false,
    				SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsamgf1cacaid);
    		log.debug("created user: foorsamgf1ca, foo123, C=SE, O=AnaTom, CN=foorsamgf1ca");
    	} else {
    		log.info("User foorsamgf1ca already exists, resetting status.");
    		userAdminSession.setUserStatus(admin, "foorsamgf1ca", UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}

    	if (!userAdminSession.existsUser(admin, "foodsa")) {
    		userAdminSession.addUser(admin, "foodsa", "foo123", "C=SE,O=AnaTom,CN=foodsa", null, "foodsa@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
    				SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, dsacaid);
    		log.debug("created user: foodsa, foo123, C=SE, O=AnaTom, CN=foodsa");
    	} else {
    		log.info("User foodsa already exists, resetting status.");
    		userAdminSession.setUserStatus(admin, "foodsa", UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}

    	if (!userAdminSession.existsUser(admin, USER_PRIVKEYUSAGEPERIOD)) {
    		userAdminSession.addUser(admin, USER_PRIVKEYUSAGEPERIOD, "foo123", DN_PRIVKEYUSAGEPERIOD, null, "fooprivkeyusage@example.com", false, SecConst.EMPTY_ENDENTITYPROFILE,
    				SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
    		log.debug("created user: " + USER_PRIVKEYUSAGEPERIOD + ", foo123, " + DN_PRIVKEYUSAGEPERIOD);
    	} else {
    		log.info("User " + USER_PRIVKEYUSAGEPERIOD + " already exists, resetting status.");
    		userAdminSession.setUserStatus(admin, USER_PRIVKEYUSAGEPERIOD, UserDataConstants.STATUS_NEW);
    		log.debug("Reset status to NEW");
    	}
    } // createUsers


    @Test
    public void test01CreateNewUser() throws PersistenceException, CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException, EndEntityProfileExistsException, FinderException, CertificateProfileExistsException {
        log.trace(">test01CreateNewUser()");

        createUsers();
        
        if (log.isTraceEnabled()) {
            log.trace("<test01CreateNewUser()");
        }
    }

    @Test
    public void test02SignSession() throws Exception {
        log.trace(">test02SignSession()");

        createUsers();

        // user that we know exists...
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "C=SE,O=AnaTom,CN=foo");

        cert.verify(rsacacert.getPublicKey());

        // assertTrue("Verify failed: " + e.getMessage(), false);
        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        cert = (X509Certificate) signSession.createCertificate(admin, "foorev", "foo123", rsakeys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        // Reverse DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "CN=foorev,O=AnaTom,C=SE");
        try {
            cert.verify(rsarevcacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // FileOutputStream fos = new FileOutputStream("testcertrev.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test02SignSession()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test03TestBCPKCS10() throws Exception {
        log.trace(">test03TestBCPKCS10()");
        
        createUsers();
        
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), rsakeys
                .getPublic(), new DERSet(), rsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());

        // Verify error handling
        EndEntityInformation badUserData = new EndEntityInformation();
        badUserData.setCAId(rsacaid);
        p10 = new PKCS10RequestMessage(bcp10);
        try {
        	signSession.createCertificate(admin, p10, X509ResponseMessage.class, badUserData);
            assertFalse("Was able to create certificate when it should have failed.", true);
        } catch (SignRequestException e) {
        	log.info("Expected exception caught (no password supplied): " + e.getMessage());
        }
        log.trace("<test03TestBCPKCS10()");
    }

    /**
     * tests keytool pkcs10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test04TestKeytoolPKCS10() throws Exception {
        log.trace(">test04TestKeytoolPKCS10()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(keytoolp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.trace("<test04TestKeytoolPKCS10()");
    }

    /**
     * tests ie pkcs10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test05TestIEPKCS10() throws Exception {
        log.trace(">test05TestIEPKCS10()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(iep10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.trace("<test05TestIEPKCS10()");
    }

    /**
     * test to set specific key usage
     * 
     * @throws Exception if an error occurs...
     */
    @Test
    public void test06KeyUsage() throws Exception {
        log.trace(">test06KeyUsage()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        int keyusage1 = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment;

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), keyusage1, null, null);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        boolean[] retKU = cert.getKeyUsage();
        assertTrue("Fel KeyUsage, digitalSignature finns ej!", retKU[0]);
        assertTrue("Fel KeyUsage, keyEncipherment finns ej!", retKU[2]);
        assertTrue("Fel KeyUsage, cRLSign finns!", !retKU[6]);

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        int keyusage2 = X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign;
        
        X509Certificate cert1 = (X509Certificate)signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), keyusage2, null, null);
        
        assertNotNull("Misslyckades skapa cert", cert1);
        retKU = cert1.getKeyUsage();
        assertTrue("Fel KeyUsage, keyCertSign finns ej!", retKU[5]);
        assertTrue("Fel KeyUsage, cRLSign finns ej!", retKU[6]);
        assertTrue("Fel KeyUsage, digitalSignature finns!", !retKU[0]);

        log.debug("Cert=" + cert1.toString());
        log.trace("<test06KeyUsage()");
    }

    /**
     * test DSA keys instead of RSA
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test07DSAKey() throws Exception {
        log.trace(">test07DSAKey()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        try {
            PKCS10RequestMessage p10 = new PKCS10RequestMessage(keytooldsa);
            p10.setUsername("foo");
            p10.setPassword("foo123");
            ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
            Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
            log.info("cert with DN '" + CertTools.getSubjectDN(cert) + "' should not be issued?");
        } catch (Exception e) {
            // RSASignSession should throw an IllegalKeyException here.
            assertTrue("Expected IllegalKeyException: " + e.toString(), e instanceof IllegalKeyException);
        }

        log.trace("<test07DSAKey()");
    }

    /**
     * Tests international characters
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test08SwedeChars() throws Exception {
        log.trace(">test08SwedeChars()");
        // Make user that we know...

        createUsers();

        if (!userAdminSession.existsUser(admin, "swede")) {
            // We use unicode encoding for the three swedish character åäö
            userAdminSession.addUser(admin, "swede", "foo123", "C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6", null, "swede@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
            log.debug("created user: swede, foo123, C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6");
        } else {
            log.debug("user swede already exists: swede, foo123, C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6");
            userAdminSession.setUserStatus(admin, "swede", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        try {
            // user that we know exists...; use new key so that the check that
            // two
            // don't prevent the creation of the certificate.
            X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "swede", "foo123", rsakeys2.getPublic());
            assertNotNull("Failed to create certificate", cert);
            log.debug("Cert=" + cert.toString());
            assertEquals("Wrong DN med swedechars", CertTools.stringToBCDNString("C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6"), CertTools
                    .getSubjectDN(cert));
        } finally {
            userAdminSession.deleteUser(admin, "swede");
        }
        log.trace("<test08SwedeChars()");
    }

    /**
     * Tests multiple instances of one altName
     * 
     */
    @Test
    public void test09TestMultipleAltNames() throws Exception {
        log.trace(">test09TestMultipleAltNames()");

        createUsers();

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTMULALTNAME");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.UNIFORMRESOURCEID);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.RFC822NAME);
        profile.addField(DnComponents.IPADDRESS);
        profile.addField(DnComponents.UPN);
        profile.addField(DnComponents.UPN);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTMULALTNAME", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTMULALTNAME");

        // Change a user that we know...
        userAdminSession.changeUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo",
                "uniformResourceId=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1",
                "foo@anatom.se", false, eeprofile, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
                UserDataConstants.STATUS_NEW, rsacaid);
        log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        String altNames = CertTools.getSubjectAlternativeName(cert);
        log.debug(altNames);
        ArrayList<String> list = CertTools.getPartsFromDN(altNames, CertTools.UPN);
        assertEquals(2, list.size());
        assertTrue(list.contains("foo@a.se"));
        assertTrue(list.contains("foo@b.se"));
        String name = CertTools.getPartFromDN(altNames, CertTools.URI);
        assertEquals("http://www.a.se/", name);
        name = CertTools.getPartFromDN(altNames, CertTools.EMAIL);
        assertEquals("tomas@a.se", name);
        list = CertTools.getPartsFromDN(altNames, CertTools.DNS);
        assertEquals(2, list.size());
        assertTrue(list.contains("www.a.se"));
        assertTrue(list.contains("www.b.se"));
        name = CertTools.getPartFromDN(altNames, CertTools.IPADDR);
        assertEquals("10.1.1.1", name);

        // Change a user that we know...
        userAdminSession.changeUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo",
                "uri=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1", "foo@anatom.se",
                false, eeprofile, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsacaid);
        log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");

        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        altNames = CertTools.getSubjectAlternativeName(cert);
        log.debug(altNames);
        list = CertTools.getPartsFromDN(altNames, CertTools.UPN);
        assertEquals(2, list.size());
        assertTrue(list.contains("foo@a.se"));
        assertTrue(list.contains("foo@b.se"));
        name = CertTools.getPartFromDN(altNames, CertTools.URI);
        assertEquals("http://www.a.se/", name);
        name = CertTools.getPartFromDN(altNames, CertTools.EMAIL);
        assertEquals("tomas@a.se", name);
        list = CertTools.getPartsFromDN(altNames, CertTools.DNS);
        assertEquals(2, list.size());
        assertTrue(list.contains("www.a.se"));
        assertTrue(list.contains("www.b.se"));
        name = CertTools.getPartFromDN(altNames, CertTools.IPADDR);
        assertEquals("10.1.1.1", name);

        // Clean up
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTMULALTNAME");

        log.trace("<test09TestMultipleAltNames()");
    }

    /** Tests creating a certificate with QC statement */
    @Test
    public void test10TestQcCert() throws Exception {
        log.trace(">test10TestQcCert()");

        createUsers();

        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTQC");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setUseQCStatement(true);
        certprof.setQCStatementRAName("rfc822Name=qc@primekey.se");
        certprof.setUseQCEtsiQCCompliance(true);
        certprof.setUseQCEtsiSignatureDevice(true);
        certprof.setUseQCEtsiValueLimit(true);
        certprof.setQCEtsiValueLimit(50000);
        certprof.setQCEtsiValueLimitCurrency("SEK");
        certificateProfileSession.addCertificateProfile(admin, "TESTQC", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId( "TESTQC");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTQC");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTQC", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTQC");

        // Change a user that we know...
        userAdminSession.changeUser(admin, "foo", "foo123", "C=SE,CN=qc", null, "foo@anatom.nu", false, eeprofile, cprofile, SecConst.USER_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsacaid);
        log.debug("created user: foo, foo123, C=SE, CN=qc");

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // FileOutputStream fos = new FileOutputStream("cert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        String dn = cert.getSubjectDN().getName();
        assertEquals(CertTools.stringToBCDNString("cn=qc,c=SE"), CertTools.stringToBCDNString(dn));
        assertEquals("rfc822name=qc@primekey.se", QCStatementExtension.getQcStatementAuthorities(cert));
        Collection<String> ids = QCStatementExtension.getQcStatementIds(cert);
        assertTrue(ids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
        String limit = QCStatementExtension.getQcStatementValueLimit(cert);
        assertEquals("50000 SEK", limit);

        // Clean up
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTQC");
        certificateProfileSession.removeCertificateProfile(admin, "TESTQC");

        log.trace("<test10TestQcCert()");
    }

    /**
     * Tests creting a certificate with QC statement
     * 
     */
    @Test
    public void test11TestValidityOverride() throws Exception {
        log.trace(">test11TestValidityOverrideAndCardNumber()");

        createUsers();

        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTVALOVERRIDE");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowValidityOverride(false);
        certprof.setValidity(298);
        certprof.setUseCardNumber(true);
        certificateProfileSession.addCertificateProfile(admin, "TESTVALOVERRIDE", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId("TESTVALOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTVALOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        profile.setUse(EndEntityProfile.CARDNUMBER, 0, true);
        endEntityProfileSession.addEndEntityProfile(admin, "TESTVALOVERRIDE", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTVALOVERRIDE");
        // Change a user that we know...
        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,CN=validityoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(UserDataConstants.STATUS_NEW);
        user.setCardNumber("123456789");
        userAdminSession.changeUser(admin, user, false);
        // userAdminSession.changeUser(admin, "foo", "foo123",
        // "C=SE,CN=validityoverride",
        // null,
        // "foo@anatom.nu", false,
        // eeprofile,
        // cprofile,
        // SecConst.USER_ENDUSER,
        // SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW,
        // rsacaid);
        log.debug("created user: foo, foo123, C=SE, CN=validityoverride");
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 10);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, null, cal.getTime());
        assertNotNull("Failed to create certificate", cert);
        String dn = cert.getSubjectDN().getName();
        assertEquals(CertTools.stringToBCDNString("cn=validityoverride,c=SE"), CertTools.stringToBCDNString(dn));
        Date notAfter = cert.getNotAfter();
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 297);
        // Override was not enabled, the cert should have notAfter more than 297
        // days in the future (298 to be exact)
        assertTrue(notAfter.compareTo(cal.getTime()) > 0);
        cal.add(Calendar.DAY_OF_MONTH, 2);
        // Override was not enabled, the cert should have notAfter less than 299
        // days in the future (298 to be exact)
        assertTrue(notAfter.compareTo(cal.getTime()) < 0);

        // Check card number extension as well
        String cardNumber = SeisCardNumberExtension.getSeisCardNumber(cert);
        assertEquals("123456789", cardNumber);

        // Change so that we allow override of validity time
        CertificateProfile prof = certificateProfileSession.getCertificateProfile(cprofile);
        prof.setAllowValidityOverride(true);
        prof.setValidity(3065);
        prof.setUseCardNumber(false);
        certificateProfileSession.changeCertificateProfile(admin, "TESTVALOVERRIDE", prof);
        cal = Calendar.getInstance();
        Calendar notBefore = Calendar.getInstance();
        notBefore.add(Calendar.DAY_OF_MONTH, 2);
        cal.add(Calendar.DAY_OF_MONTH, 10);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, notBefore.getTime(), cal.getTime());
        assertNotNull("Failed to create certificate", cert);
        assertEquals(CertTools.stringToBCDNString("cn=validityoverride,c=SE"), CertTools.stringToBCDNString(dn));
        notAfter = cert.getNotAfter();
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 11);
        // Override was enabled, the cert should have notAfter less than 11 days
        // in the future (10 to be exact)
        assertTrue(notAfter.compareTo(cal.getTime()) < 0);
        notAfter = cert.getNotBefore();
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 1);
        // Override was enabled, the cert should have notBefore more than 1 days
        // in the future (2 to be exact)
        assertTrue(notAfter.compareTo(cal.getTime()) > 0);
        cal.add(Calendar.DAY_OF_MONTH, 2);
        assertTrue(notAfter.compareTo(cal.getTime()) < 0);

        // Check that card number extension is not present
        cardNumber = SeisCardNumberExtension.getSeisCardNumber(cert);
        assertNull(cardNumber);

        // Verify that we can not get a certificate that has notBefore befor the
        // current time
        // and that we can not get a certificate valid longer than the
        // certificate profile allows.
        prof = certificateProfileSession.getCertificateProfile(cprofile);
        prof.setValidity(50);
        certificateProfileSession.changeCertificateProfile(admin, "TESTVALOVERRIDE", prof);
        notBefore = Calendar.getInstance();
        notBefore.add(Calendar.DAY_OF_MONTH, -2);
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 200);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, notBefore.getTime(), cal.getTime());
        assertNotNull("Failed to create certificate", cert);
        assertEquals(CertTools.stringToBCDNString("cn=validityoverride,c=SE"), CertTools.stringToBCDNString(dn));
        Date certNotBefore = cert.getNotBefore();
        // Override was enabled, and we can not get a certificate valid before
        // current time
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, -1);
        // the certificate should be valid 2 days before current date...
        assertTrue(certNotBefore.compareTo(cal.getTime()) < 0);
        cal.add(Calendar.DAY_OF_MONTH, -2);
        assertTrue(certNotBefore.compareTo(cal.getTime()) > 0);
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 47);
        notAfter = cert.getNotAfter();
        // Override was enabled, the cert should have notAfter more than 47 days
        // in the future (50 days starting from -2 days since notBefore was set
        // before current date)
        // since we requested 200 and validity is 50
        assertTrue(notAfter.compareTo(cal.getTime()) > 0);
        cal.add(Calendar.DAY_OF_MONTH, 2);
        // Since we are not allowed to request validity longer than the
        // certificate profile allows, validity is less than 51 days, even
        // though we requested 200
        assertTrue(notAfter.compareTo(cal.getTime()) < 0);

        // Clean up
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTVALOVERRIDE");
        certificateProfileSession.removeCertificateProfile(admin, "TESTVALOVERRIDE");

        log.trace("<test11TestValidityOverride()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */ 
    @Test
    public void test12SignSessionECDSAWithRSACA() throws Exception {
        log.trace(">test12SignSessionECDSAWithRSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test12SignSessionECDSAWithRSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test13TestBCPKCS10ECDSAWithRSACA() throws Exception {
        log.trace(">test13TestBCPKCS10ECDSAWithRSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), ecdsakeys
                .getPublic(), new DERSet(), ecdsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test13TestBCPKCS10ECDSAWithRSACA()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test14SignSessionECDSAWithECDSACA() throws Exception {
        log.trace(">test14SignSessionECDSAWithECDSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "fooecdsa", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'fooecdsa' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "fooecdsa", "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test14SignSessionECDSAWithECDSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test15TestBCPKCS10ECDSAWithECDSACA() throws Exception {
        log.trace(">test15TestBCPKCS10ECDSAWithECDSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "fooecdsa", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=fooecdsa"),
                ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("fooecdsa");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test15TestBCPKCS10ECDSAWithECDSACA()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test16SignSessionECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test16SignSessionECDSAWithECDSAImplicitlyCACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "fooecdsaimpca", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'fooecdsaimpca' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "fooecdsaimpca", "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(ecdsaimplicitlycacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test16SignSessionECDSAWithECDSAImplicitlyCACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA()");
        
        createUsers();

        userAdminSession.setUserStatus(admin, "fooecdsaimpca", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=fooecdsaimpca"),
                ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("fooecdsaimpca");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            cert.verify(ecdsaimplicitlycacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test18SignSessionRSAMGF1WithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test18SignSessionRSAWithRSASha256WithMGF1CA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foorsamgf1ca", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foorsamgf1ca' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, rsakeys.getPrivate(), rsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, false);
        try {
            selfcert.verify(selfcert.getPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        X509Certificate retcert = (X509Certificate) signSession.createCertificate(admin, "foorsamgf1ca", "foo123", selfcert);
        // RSA with MGF1 is not supported by sun, so we must transfer this
        // (serialized) cert to a BC cert
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(retcert.getEncoded());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        // FileOutputStream fos = new FileOutputStream("/tmp/testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            assertTrue("Public key is not RSA", false);
        }
        try {
            cert.verify(rsamgf1cacacert.getPublicKey());
        } catch (Exception e) {
            // e.printStackTrace();
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // 1.2.840.113549.1.1.10 is SHA256WithRSAAndMGF1
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgName());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgName());

        log.trace("<test18SignSessionRSAWithRSASha256WithMGF1CA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test19TestBCPKCS10RSAWithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test19TestBCPKCS10RSAWithRSASha256WithMGF1CA()");
        
        createUsers();

        userAdminSession.setUserStatus(admin, "foorsamgf1ca", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foorsamgf1ca' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, CertTools
                .stringToBcX509Name("C=SE, O=AnaTom, CN=foorsamgf1ca"), rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foorsamgf1ca");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        // X509Certificate cert =
        // CertTools.getCertfromByteArray(retcert.getEncoded());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        // FileOutputStream fos = new FileOutputStream("/tmp/testcert1.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            assertTrue("Public key is not RSA", false);
        }
        try {
            cert.verify(rsamgf1cacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // 1.2.840.113549.1.1.10 is SHA256WithRSAAndMGF1
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgName());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgName());

        log.trace("<test19TestBCPKCS10RSAWithRSASha256WithMGF1CA()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test20MultiRequests() throws Exception {
        log.trace(">test20MultiRequests()");

        createUsers();

        // Test that it works correctly with end entity profiles using the
        // counter
        int pid = 0;

        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, "" + rsacaid);
        profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
        profile.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "3");
        endEntityProfileSession.addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
        pid = endEntityProfileSession.getEndEntityProfileId(admin, "TESTREQUESTCOUNTER");

        // Change already existing user
        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, null, SecConst.USER_ENDUSER, pid, SecConst.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userAdminSession.changeUser(admin, user, false);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        // create first cert
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);
        // log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "C=SE,O=AnaTom,CN=foo");
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // It should only work once, not twice times
        boolean authstatus = false;
        try {
            cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        } catch (AuthStatusException e) {
            authstatus = true;
        }
        assertTrue("Should have failed to create cert", authstatus);

        // Change already existing user to add extended information with counter
        ExtendedInformation ei = new ExtendedInformation();
        int allowedrequests = 2;
        ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
        user.setExtendedinformation(ei);
        user.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user, false);

        // create first cert
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);
        // log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "C=SE,O=AnaTom,CN=foo");
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        String serno = cert.getSerialNumber().toString(16);

        // It should work to get two certificates
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);
        // log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "C=SE,O=AnaTom,CN=foo");
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        String serno1 = cert.getSerialNumber().toString(16);
        assertFalse(serno1.equals(serno));

        // It should only work twice, not three times
        authstatus = false;
        try {
            cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        } catch (AuthStatusException e) {
            authstatus = true;
        }
        assertTrue("Should have failed to create cert", authstatus);

        log.trace("<test20MultiRequests()");
    }

    public void test21CVCertificate() throws Exception {
        log.trace(">test21CVCertificate()");

        createUsers();

        EndEntityInformation user = new EndEntityInformation("cvc", "C=SE,CN=TESTCVC", cvccaid, null, null, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("cvc");
        userAdminSession.addUser(admin, user, false);
        userAdminSession.setUserStatus(admin, "cvc", UserDataConstants.STATUS_NEW);
        userAdminSession.setPassword(admin, "cvc", "foo123");
        log.debug("Reset status of 'cvc' to NEW");
        // user that we know exists...
        Certificate cert = (Certificate) signSession.createCertificate(admin, "cvc", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);
        log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(CertTools.getSubjectDN(cert), "CN=TESTCVC,C=SE");
        assertEquals("CVC", cert.getType());
        assertEquals(CertTools.getIssuerDN(cert), CertTools.getSubjectDN(cvccacert));
        try {
            cert.verify(cvccacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        // log.debug(cert.toString());
        // Check role
        CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
        String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("IS", role);
        PublicKey pk = cvcert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey epk = (RSAPublicKey) pk;
            assertEquals(epk.getAlgorithm(), "RSA");
            int len = KeyTools.getKeyLength(epk);
            assertEquals(1024, len);
        } else {
            assertTrue("Public key is not RSA", false);
        }

        // 
        // Same thing but with ECC keys
        EndEntityInformation userec = new EndEntityInformation("cvcec", "C=SE,CN=TCVCEC", cvccaecid, null, null, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        userec.setPassword("cvc");
        userAdminSession.addUser(admin, userec, false);
        userAdminSession.setUserStatus(admin, "cvcec", UserDataConstants.STATUS_NEW);
        userAdminSession.setPassword(admin, "cvcec", "foo123");
        log.debug("Reset status of 'cvcec' to NEW");
        // user that we know exists...
        Certificate certec = (Certificate) signSession.createCertificate(admin, "cvcec", "foo123", ecdsasecpkeys.getPublic());
        assertNotNull("Failed to create cert", certec);
        log.debug("Cert=" + certec.toString());
        // Normal DN order
        assertEquals(CertTools.getSubjectDN(certec), "CN=TCVCEC,C=SE");
        assertEquals("CVC", certec.getType());
        assertEquals(CertTools.getIssuerDN(certec), CertTools.getSubjectDN(cvcdveccert));
        try {
            // Here we need the CVCA certificate as well to enrich the DV public
            // key with
            PublicKey pkec = cvcdveccert.getPublicKey();
            pkec = KeyTools.getECPublicKeyWithParams(pkec, cvcaeccert.getPublicKey());
            certec.verify(pkec);
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        cvcert = (CardVerifiableCertificate) certec;
        role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
        assertEquals("IS", role);
        pk = cvcert.getPublicKey();
        if (pk instanceof ECPublicKey) {
            ECPublicKey epk = (ECPublicKey) pk;
            assertEquals(epk.getAlgorithm(), "ECDSA");
            int len = KeyTools.getKeyLength(epk);
            assertEquals(0, len); // the DVCA does not include all EC parameters
            // in the public key, so we don't know the key
            // length
        } else {
            assertTrue("Public key is not ECC", false);
        }

        log.trace("<test21CVCertificate()");
    }

    @Test
    public void test22DnOrder() throws Exception {
        log.trace(">test22DnOrder()");

        createUsers();

        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTDNORDER");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfileSession.addCertificateProfile(admin, "TESTDNORDER", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId("TESTDNORDER");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTDNORDER");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTDNORDER", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTDNORDER");

        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,O=PrimeKey,CN=dnorder", rsacaid, null, "foo@primekey.se", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setStatus(UserDataConstants.STATUS_NEW);
        // Change a user that we know...
        userAdminSession.changeUser(admin, user, false);
        log.debug("created user: foo, foo123, C=SE,O=PrimeKey,CN=dnorder");
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        String dn = cert.getSubjectDN().getName();
        // This is the reverse order than what is displayed by openssl
        assertEquals("C=SE, O=PrimeKey, CN=dnorder", dn);

        // Change to X509 DN order
        certprof.setUseLdapDnOrder(false);
        certificateProfileSession.changeCertificateProfile(admin, "TESTDNORDER", certprof);
        userAdminSession.changeUser(admin, user, false);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        dn = cert.getSubjectDN().getName();
        // This is the reverse order than what is displayed by openssl
        assertEquals("CN=dnorder, O=PrimeKey, C=SE", dn);

        // Clean up
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTDNORDER");
        certificateProfileSession.removeCertificateProfile(admin, "TESTDNORDER");

        log.trace("<test22DnOrder()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test23SignSessionDSAWithRSACA() throws Exception {
        log.trace(">test23SignSessionDSAWithRSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, dsakeys.getPrivate(), dsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey ecpk = (DSAPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        // FileOutputStream fos = new FileOutputStream("testcert1615.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test23SignSessionDSAWithRSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test24TestBCPKCS10DSAWithRSACA() throws Exception {
        log.trace(">test24TestBCPKCS10DSAWithRSACA()");
        
        createUsers();

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"), dsakeys
                .getPublic(), new DERSet(), dsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey dsapk = (DSAPublicKey) pk;
            assertEquals(dsapk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test24TestBCPKCS10DSAWithRSACA()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test25SignSessionDSAWithDSACA() throws Exception {
        log.trace(">test25SignSessionDSAWithDSACA()");

        createUsers();

        userAdminSession.setUserStatus(admin, "foodsa", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foodsa' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, dsakeys.getPrivate(), dsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foodsa", "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey dsapk = (DSAPublicKey) pk;
            assertEquals(dsapk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        try {
            cert.verify(dsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        // FileOutputStream fos = new FileOutputStream("testcert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test25SignSessionDSAWithDSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void test26TestBCPKCS10DSAWithDSACA() throws Exception {
        log.trace(">test26TestBCPKCS10DSAWithDSACA()");
        
        createUsers();

        userAdminSession.setUserStatus(admin, "foodsa", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foodsa' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foodsa"), dsakeys
                .getPublic(), new DERSet(), dsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foodsa");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey dsapk = (DSAPublicKey) pk;
            assertEquals(dsapk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        try {
            cert.verify(dsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test26TestBCPKCS10DSAWithDSACA()");
    }

    @Test
    public void test28TestDNOverride() throws Exception {
    	
        createUsers();

        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTDNOVERRIDE");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        // Default profile does not allow DN override
        certprof.setValidity(298);
        certificateProfileSession.addCertificateProfile(admin, "TESTDNOVERRIDE", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId("TESTDNOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTDNOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTDNOVERRIDE", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTDNOVERRIDE");
        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,CN=dnoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(UserDataConstants.STATUS_NEW);
        // Change a user that we know...
        userAdminSession.changeUser(admin, user, false);

        // Create a P10 with strange order DN
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", new X509Name("CN=foo,C=SE, Name=AnaTom, O=My org"), rsakeys.getPublic(),
                new DERSet(), rsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);

        // PKCS10RequestMessage p10 = new PKCS10RequestMessage(iep10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=dnoverride,C=SE", cert.getSubjectDN().getName());

        // Change so that we allow override of validity time
        CertificateProfile prof = certificateProfileSession.getCertificateProfile(cprofile);
        prof.setAllowDNOverride(true);
        certificateProfileSession.changeCertificateProfile(admin, "TESTDNOVERRIDE", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=foo,C=SE,Name=AnaTom,O=My org", cert.getSubjectDN().getName());

    } // test28TestDNOverride

    @Test
    public void test29TestExtensionOverride() throws Exception {
    	
        createUsers();

        final String altnames = "dNSName=foo1.bar.com,dNSName=foo2.bar.com,dNSName=foo3.bar.com,dNSName=foo4.bar.com,dNSName=foo5.bar.com,dNSName=foo6.bar.com,dNSName=foo7.bar.com,dNSName=foo8.bar.com,dNSName=foo9.bar.com,dNSName=foo10.bar.com,dNSName=foo11.bar.com,dNSName=foo12.bar.com,dNSName=foo13.bar.com,dNSName=foo14.bar.com,dNSName=foo15.bar.com,dNSName=foo16.bar.com,dNSName=foo17.bar.com,dNSName=foo18.bar.com,dNSName=foo19.bar.com,dNSName=foo20.bar.com,dNSName=foo21.bar.com";
        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTEXTENSIONOVERRIDE");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        // Default profile does not allow Extension override
        certprof.setValidity(298);
        certificateProfileSession.addCertificateProfile(admin, "TESTEXTENSIONOVERRIDE", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId("TESTEXTENSIONOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTEXTENSIONOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTEXTENSIONOVERRIDE", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTEXTENSIONOVERRIDE");
        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,CN=extoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(UserDataConstants.STATUS_NEW);
        // Change a user that we know...
        userAdminSession.changeUser(admin, user, false);

        // Create a P10 with extensions, in this case altNames with a lot of DNS
        // names
        ASN1EncodableVector extensionattr = new ASN1EncodableVector();
        extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        // AltNames
        // String[] namearray = altnames.split(",");
        GeneralNames san = CertTools.getGeneralNamesFromAltName(altnames);
        ByteArrayOutputStream extOut = new ByteArrayOutputStream();
        DEROutputStream derOut = new DEROutputStream(extOut);
        try {
            derOut.writeObject(san);
        } catch (IOException e) {
            throw new IllegalArgumentException("error encoding value: " + e);
        }
        // Extension request attribute is a set of X509Extensions
        // ASN1EncodableVector x509extensions = new ASN1EncodableVector();
        // An X509Extensions is a sequence of Extension which is a sequence of
        // {oid, X509Extension}
        // ASN1EncodableVector extvalue = new ASN1EncodableVector();
        Vector<DERObjectIdentifier> oidvec = new Vector<DERObjectIdentifier>();
        oidvec.add(X509Extensions.SubjectAlternativeName);
        Vector<X509Extension> valuevec = new Vector<X509Extension>();
        valuevec.add(new X509Extension(false, new DEROctetString(extOut.toByteArray())));
        X509Extensions exts = new X509Extensions(oidvec, valuevec);
        extensionattr.add(new DERSet(exts));
        // Complete the Attribute section of the request, the set (Attributes)
        // contains one sequence (Attribute)
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(extensionattr));
        DERSet attributes = new DERSet(v);
        // Create PKCS#10 certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", new X509Name("C=SE,CN=extoverride"), rsakeys.getPublic(), attributes,
                rsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        byte[] p10bytes = bOut.toByteArray();
        // FileOutputStream fos = new FileOutputStream("/tmp/foo.der");
        // fos.write(p10bytes);
        // fos.close();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(p10bytes);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        // See if the request message works...
        X509Extensions p10exts = p10.getRequestExtensions();
        assertNotNull(p10exts);
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=extoverride,C=SE", cert.getSubjectDN().getName());
        // check altNames, should be none
        Collection<List<?>> c = cert.getSubjectAlternativeNames();
        assertNull(c);

        // Change so that we allow override of validity time
        CertificateProfile prof = certificateProfileSession.getCertificateProfile(cprofile);
        prof.setAllowExtensionOverride(true);
        certificateProfileSession.changeCertificateProfile(admin, "TESTEXTENSIONOVERRIDE", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=extoverride,C=SE", cert.getSubjectDN().getName());
        // check altNames, should be one altName
        c = cert.getSubjectAlternativeNames();
        assertNotNull(c);
        assertEquals(21, c.size());
        String retAltNames = CertTools.getSubjectAlternativeName(cert);
        List<String> originalNames = Arrays.asList(altnames.split(","));
        List<String> returnNames = Arrays.asList(retAltNames.split(", "));
        assertTrue(originalNames.containsAll(returnNames));
    } // test29TestExtensionOverride
    @Test
    public void test30OfflineCA() throws Exception {
    	
        createUsers();

        // user that we know exists...
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // Set CA to offline
        CAInfo inforsa = caSession.getCAInfo(admin, rsacaid);
        inforsa.setStatus(SecConst.CA_OFFLINE);
        caAdminSession.editCA(admin, inforsa);

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        boolean thrown = false;
        try {
            cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        } catch (Exception e) {
            thrown = true;
        }
        assertTrue(thrown);

        inforsa.setStatus(SecConst.CA_ACTIVE);
        caAdminSession.editCA(admin, inforsa);
    }

    @Test
    public void test31TestProfileSignatureAlgorithm() throws Exception {
    	
        createUsers();

        // Create a good certificate profile (good enough), using QC statement
        certificateProfileSession.removeCertificateProfile(admin, "TESTSIGALG");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        // Default profile uses "inherit from CA"
        certificateProfileSession.addCertificateProfile(admin, "TESTSIGALG", certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId("TESTSIGALG");

        // Create a good end entity profile (good enough)
        endEntityProfileSession.removeEndEntityProfile(admin, "TESTSIGALG");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        endEntityProfileSession.addEndEntityProfile(admin, "TESTSIGALG", profile);
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(admin, "TESTSIGALG");
        EndEntityInformation user = new EndEntityInformation("foo", "C=SE,CN=testsigalg", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(UserDataConstants.STATUS_NEW);
        // Change a user that we know...
        userAdminSession.changeUser(admin, user, false);

        // Create a P10
        // Create PKCS#10 certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA", new X509Name("C=SE,CN=testsigalg"), rsakeys.getPublic(), null, rsakeys
                .getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        byte[] p10bytes = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(p10bytes);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        // See if the request message works...
        ResponseMessage resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=testsigalg,C=SE", cert.getSubjectDN().getName());
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getSignatureAlgorithm(cert));

        // Change so that we can override signature algorithm
        CertificateProfile prof = certificateProfileSession.getCertificateProfile(cprofile);
        prof.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        certificateProfileSession.changeCertificateProfile(admin, "TESTSIGALG", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, X509ResponseMessage.class, null);
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=testsigalg,C=SE", cert.getSubjectDN().getName());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getSignatureAlgorithm(cert));
    } // test31TestProfileSignatureAlgorithm

    @Test
    public void test32TestCertReqHistory() throws Exception {

        createUsers();

        // Configure CA not to store certreq history
        CAInfo cainfo = caSession.getCAInfo(admin, rsacaid);
        cainfo.setUseCertReqHistory(true);
        cainfo.setDoEnforceUniquePublicKeys(false);
        caAdminSession.editCA(admin, cainfo);

        // New random username and create cert
        String username = genRandomUserName();
        userAdminSession.addUser(admin, username, "foo123", "C=SE,O=AnaTom,CN=" + username, null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        // Check that certreq history was created
        List<CertReqHistory> history = certReqHistorySession.retrieveCertReqHistory(admin, username);
        assertEquals(1, history.size());

        userAdminSession.deleteUser(admin, username);

        // Configure CA not to store certreq history
        cainfo.setUseCertReqHistory(false);
        caAdminSession.editCA(admin, cainfo);
        // New random username and create cert
        username = genRandomUserName();
        userAdminSession.addUser(admin, username, "foo123", "C=SE,O=AnaTom,CN=" + username, null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
        cert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        // Check that certreq history was not created
        history = certReqHistorySession.retrieveCertReqHistory(admin, username);
        assertEquals(0, history.size());

        userAdminSession.deleteUser(admin, username);

        // Reset CA info
        cainfo.setUseCertReqHistory(true);
        caAdminSession.editCA(admin, cainfo);
    } // test32TestCertReqHistory

    /**
     * Test several cases where certificate generation should fail.
     */
    @Test
    public void test33certCreationErrorHandling() throws Exception {
        log.trace(">test33certCreationErrorHandling");
        
        createUsers();

        log.debug("Trying to use a certificate that isn't selfsigned for certificate renewal.");
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        final X509Certificate notSelfSignedCert = CertTools.genSelfCert("CN=notSelfSigned", 1, null, rsakeys.getPrivate(), rsakeys2.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        try {
            signSession.createCertificate(admin, "foo", "foo123", notSelfSignedCert);
            assertFalse("Tried to create cert from old certificate that wasn't self signed! Did not throw SignRequestSignatureException.", true);
        } catch (SignRequestSignatureException e) {
        	log.info("Got expected exception: " + e.getMessage());
        }
        log.trace("<test33certCreationErrorHandling");
    }

    /**
     * Tests that if the PrivateKeyUsagePeriod extension is not set in the profile
     * it will not be in the certificate.
     * @throws Exception In case of error.
     */
    @Test
    public void test34privateKeyUsagePeriod_unused() throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(false, 0L, false, 0L);        
        assertNull("Has not the extension", cert.getExtensionValue("2.5.29.16"));
    }
    
    /**
     * Tests setting different notBefore dates. 
     * @throws Exception In case of error.
     */
    @Test
    public void test35privateKeyUsagePeriod_notBefore() throws Exception {
        createUsers();

    	// A: Only PrivateKeyUsagePeriod.notBefore with same as cert
    	privateKeyUsageTestStartOffset(0L);
    	
        // B: Only PrivateKeyUsagePeriod.notBefore starting 33 days after cert
    	privateKeyUsageTestStartOffset(33 * 24 * 3600L);
    	
    	// C: Only PrivateKeyUsagePeriod.notBefore starting 5 years after cert
    	privateKeyUsageTestStartOffset(5 * 365 * 24 * 3600L);
    	
    	// D: Only PrivateKeyUsagePeriod.notBefore starting 1 second after cert
    	privateKeyUsageTestStartOffset(1L);
        
    	// E: Only PrivateKeyUsagePeriod.notBefore starting 5 years before cert
    	privateKeyUsageTestStartOffset(-5 * 365 * 24 * 3600L);
    	
    	// F: Only PrivateKeyUsagePeriod.notBefore starting 33 days before cert
    	privateKeyUsageTestStartOffset(-33 * 24 * 3600L);
    	
    	// G: Only PrivateKeyUsagePeriod.notBefore starting 1 second before cert
    	privateKeyUsageTestStartOffset(-1L);
    }
    
    /**
     * Tests setting different notAfter dates.
     * @throws Exception In case of error.
     */
    @Test
    public void test36privateKeyUsagePeriod_notAfter() throws Exception {
        createUsers();

        // 1: Only PrivateKeyUsagePeriod.notAfter 33 days after issuance
    	privateKeyUsageTestValidityLength(33 * 24 * 3600L);
    	
    	// 2: Only PrivateKeyUsagePeriod.notAfter 5 years after issuance
    	privateKeyUsageTestValidityLength(5 * 365 * 24 * 3600L);
    	
    	// 3: :Only PrivateKeyUsagePeriod.notAfter 1 second after issuance
    	privateKeyUsageTestValidityLength(1L);
        
    	// 4: Only PrivateKeyUsagePeriod.notAfter with zero validity length (might not be a correct case)
    	privateKeyUsageTestValidityLength(0L);
    }
    
    /**
     * Tests the combinations of different notBefore and notAfter dates.
     * @throws Exception In case of error.
     */
    @Test
    public void test37privateKeyUsagePeriod_both() throws Exception {
        createUsers();

    	// A: 1, 2, 3, 4
    	privateKeyUsageTestBoth(0L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(0L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(0L, 1L);
    	privateKeyUsageTestBoth(0L, 0L);
    	
    	// B: 1, 2, 3, 4
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 1L);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 0L);
    	
    	// C: 1, 2, 3, 4
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 1L);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 0L);
    	
    	// D: 1, 2, 3, 4
    	privateKeyUsageTestBoth(1L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(1L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(1L, 1L);
    	privateKeyUsageTestBoth(1L, 0L);
        
    	// E: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 1L);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 0L);
    	
    	// F: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 1L);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 0L);
    	
    	// G: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-1L, 33 * 24 * 3600L);
    	privateKeyUsageTestBoth(-1L, 5 * 365 * 24 * 3600L);
    	privateKeyUsageTestBoth(-1L, 1L);
    	privateKeyUsageTestBoth(-1L, 0L);
    }
    
    private void privateKeyUsageTestStartOffset(final long startOffset) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(true, startOffset, false, 0L);        
        assertNotNull("Has not the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notBefore", ext.getNotBefore());
        assertNull("Has no notAfter", ext.getNotAfter());
        assertEquals("notBefore " + startOffset + " seconds after ca cert", cert.getNotBefore().getTime() + startOffset * 1000, ext.getNotBefore().getDate().getTime());
    }
    
    private void privateKeyUsageTestValidityLength(final long length) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(false, 0L, true, length);        
        assertNotNull("Has the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notAfter", ext.getNotAfter());
        assertNull("Has no notBefore", ext.getNotBefore());
        assertEquals("notAfter " + length + " seconds after issue time", cert.getNotBefore().getTime() + length * 1000, ext.getNotAfter().getDate().getTime());
    }
    
    private void privateKeyUsageTestBoth(final long startOffset, final long length) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(true, startOffset, true, length);        
        assertNotNull("Has the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notBefore", ext.getNotBefore());
        assertNotNull("Has notAfter", ext.getNotAfter());
        assertEquals("notBefore " + startOffset + " seconds after ca cert", cert.getNotBefore().getTime() + startOffset * 1000, ext.getNotBefore().getDate().getTime());
        assertEquals("notAfter " + length + " seconds after notBefore", ext.getNotBefore().getDate().getTime() + length * 1000, ext.getNotAfter().getDate().getTime());
    }
    
    private X509Certificate privateKeyUsageGetCertificate(final boolean useStartOffset, final long startOffset, final boolean usePeriod, final long period) throws Exception {
    	
    	certificateProfileSession.removeCertificateProfile(admin, CERTPROFILE_PRIVKEYUSAGEPERIOD);
    	final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	certProfile.setUsePrivateKeyUsagePeriodNotBefore(useStartOffset);
    	certProfile.setPrivateKeyUsagePeriodStartOffset(startOffset);
    	certProfile.setUsePrivateKeyUsagePeriodNotAfter(usePeriod);
    	certProfile.setPrivateKeyUsagePeriodLength(period);
    	certificateProfileSession.addCertificateProfile(admin, CERTPROFILE_PRIVKEYUSAGEPERIOD, certProfile);
    	final int certProfileId = certificateProfileSession.getCertificateProfileId(CERTPROFILE_PRIVKEYUSAGEPERIOD);
    	endEntityProfileSession.removeEndEntityProfile(admin, EEPROFILE_PRIVKEYUSAGEPERIOD);
        final EndEntityProfile eeProfile = new EndEntityProfile();
        eeProfile.addField(DnComponents.COUNTRY);
        eeProfile.addField(DnComponents.COMMONNAME);
        eeProfile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        eeProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfileId));
        endEntityProfileSession.addEndEntityProfile(admin, EEPROFILE_PRIVKEYUSAGEPERIOD, eeProfile);
        final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(admin, EEPROFILE_PRIVKEYUSAGEPERIOD);
        final EndEntityInformation user = new EndEntityInformation(USER_PRIVKEYUSAGEPERIOD, DN_PRIVKEYUSAGEPERIOD, rsacaid, null, "fooprivatekeyusae@example.com", SecConst.USER_ENDUSER, eeProfileId, certProfileId,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(UserDataConstants.STATUS_NEW);
        userAdminSession.changeUser(admin, user, false);
        
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, USER_PRIVKEYUSAGEPERIOD, "foo123", rsakeyPrivKeyUsagePeriod.getPublic());
        assertNotNull("Failed to create certificate", cert);
//        FileOutputStream fos = new FileOutputStream("cert.crt");
//        fos.write(cert.getEncoded());
//        fos.close();
//        System.out.println(cert);
        String dn = cert.getSubjectDN().getName();
        assertEquals(CertTools.stringToBCDNString(DN_PRIVKEYUSAGEPERIOD), CertTools.stringToBCDNString(dn));
        return cert;
    }

}
