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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.rmi.RemoteException;
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

import javax.ejb.DuplicateKeyException;
import javax.ejb.EJB;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.cert.QCStatementExtension;
import org.ejbca.util.cert.SeisCardNumberExtension;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;


/**
 * Tests signing session.
 * 
 * Since all the CAs from "TestCAs" is required, you should run it manually before running this test and "RemoveCAs" after.
 *
 * @version $Id$
 */
public class SignSessionTest extends CaTestCase {
    static byte[] keytoolp10 = Base64.decode(("MIIBbDCB1gIBADAtMQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY+ATE4ZB0oKfmXStu8J+do0GhTag6rOGtoydI" +
            "eNX9DdytlsmXDyONKl8746478/3HXdx9rA0RevUizKSataMpDsb3TjprRjzBTvYPZSIfzko6s8g6" +
            "AZLO07xCFOoDmyRzb9k/KEZsMls0ujx79CQ9p5K4rg2ksjmDeW7DaPMphQIDAQABoAAwDQYJKoZI" +
            "hvcNAQEFBQADgYEAyJVobqn6wGRoEsdHxjoqPXw8fLrQyBGEwXccnVpI4kv9iIZ45Xres0LrOwtS" +
            "kFLbpn0guEzhxPBbL6mhhmDDE4hbbHJp1Kh6gZ4Bmbb5FrwpvUyrSjTIwwRC7GAT00A1kOjl9jCC" +
            "XCfJkJH2QleCy7eKANq+DDTXzpEOvL/UqN0=").getBytes());
    static byte[] oldbcp10 = Base64.decode(("MIIBbDCB1gIBADAtMQswCQYDVQQGEwJTRTEPMA0GA1UEChMGQW5hVG9tMQ0wCwYDVQQDEwRUZXN0" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzN9nDdwmq23/RLGisvR3CRO9JSem2QZ7JC7nr" +
            "NlbxQBLVqlkypT/lxMMur+lTX1S+jBaqXjtirhZTVaV5C/+HObWZ5vrj30lmsCdgzFybSzVxBz0l" +
            "XC0UEDbgBml/hO70cSDdmyw3YE9g5eH3wdYs2FCTzexRF3kNAVHNUa8svwIDAQABoAAwDQYJKoZI" +
            "hvcNAQEFBQADgYEAm6uRSyEmyCcs652Ttg2npm6JZPFT2qwSl4dviyIKJbn6j+meCzvn2TMP10d8" +
            "7Ak5sv5NJew1XGkM4mGpF9cfcVshxLVlW+cgq0749fWbyS8KlgQP/ANh3DkLl8k5E+3Wnbi0JjCV" +
            "Xe1s44+K2solX8jOtryoR4TMJ6p9HpsuO68=").getBytes());
    static byte[] iep10 = Base64.decode(("MIICnTCCAgYCAQAwGzEZMBcGA1UEAxMQNkFFSzM0N2Z3OHZXRTQyNDCBnzANBgkq" +
            "hkiG9w0BAQEFAAOBjQAwgYkCgYEAukW70HN9bt5x2AiSZm7y8GXQuyp1jN2OIvqU" +
            "sr0dzLIOFt1H8GPJkL80wx3tLDj3xJfWJdww3TqExsxMSP+qScoYKIOeNBb/2OMW" +
            "p/k3DThCOewPebmt+M08AClq5WofXTG+YxyJgXWbMTNfXKIUyR0Ju4Spmg6Y4eJm" +
            "GXTG7ZUCAwEAAaCCAUAwGgYKKwYBBAGCNw0CAzEMFgo1LjAuMjE5NS4yMCAGCisG" +
            "AQQBgjcCAQ4xEjAQMA4GA1UdDwEB/wQEAwIE8DCB/wYKKwYBBAGCNw0CAjGB8DCB" +
            "7QIBAR5cAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwBy" +
            "AHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAu" +
            "ADADgYkAjuYPzZPpbLgCWYnXoNeX2gS6nuI4osrWHlQQKcS67VJclhELlnT3hBb9" +
            "Blr7I0BsJ/lguZvZFTZnC1bMeNULRg17bhExTg+nUovzPcJhMvG7G3DR17PrJ7V+" +
            "egHAsQV4dQC2hOGGhOnv88JhP9Pwpso3t2tqJROa5ZNRRSJSkw8AAAAAAAAAADAN" +
            "BgkqhkiG9w0BAQQFAAOBgQCL5k4bJt265j63qB/9GoQb1XFOPSar1BDFi+veCPA2" +
            "GJ/vRXt77Vcr4inx9M51iy87FNcGGsmyesBoDg73p06UxpIDhkL/WpPwZAfQhWGe" +
            "o/gWydmP/hl3uEfE0E4WG02UXtNwn3ziIiJM2pBCGQQIN2rFggyD+aTxwAwOU7Z2" + "fw==").getBytes());
    static byte[] openscep = Base64.decode(("MIIFSwYJKoZIhvcNAQcCoIIFPDCCBTgCAQExDjAMBggqhkiG9w0CBQUAMIICMwYJ" +
            "KoZIhvcNAQcBoIICJASCAiAwggIcBgkqhkiG9w0BBwOgggINMIICCQIBADGB1TCB" +
            "0gIBADA7MC8xDzANBgNVBAMTBlRlc3RDQTEPMA0GA1UEChMGQW5hVG9tMQswCQYD" +
            "VQQGEwJTRQIIbzEhUVZYO3gwDQYJKoZIhvcNAQEBBQAEgYDJP3tsx1KMC+Ws3gcV" +
            "gpvatMgxocUrKS2Z5BRj7z8HE/BySwa40fwzpBXq3xhakclrdK9D6Bb7I2oTqaNo" +
            "y25tk2ykow8px1HEerGg5eCIDeAwX4IGurKn+ajls4vWntybgtosAFPLuBO2sdfy" +
            "VhTv+iFxkl+lZgcRfpJhmqfOJjCCASoGCSqGSIb3DQEHATARBgUrDgMCBwQIapUt" +
            "FKgA/KmAggEIpzjb5ONkiT7gPs5VeQ6a2e3IdXMgZTRknqZZRRzRovKwp17LJPkA" +
            "AF9vQKCk6IQwM1dY4NAhu/mCvkfQwwVgML+rbsx7cYH5VuMxw6xw79CnGZbcgOoE" +
            "lhfYR9ytfZFAVjs8TF/cx1GfuxxN/3RdXzwIFmvPRX1SPh83ueMbGTHjmk0/kweE" +
            "9XcLkI85jTyG/Dsq3mUlWDS4qQg4sSbFAvkHgmCl0DQd2qW3eV9rCDbfPNjc+2dq" +
            "nG5EwjX1UVYS2TSWy7vu6MQvKtEWFP4B10+vGBcVE8fZ4IxL9TDQ4UMz3gfFIQSc" +
            "Moq4lw7YKmywbbyieGGYJuXDX/0gUBKj/MrP9s3L12bLoIIBajCCAWYwggEQoAMC" +
            "AQMCIDNGREQzNUM5NzZDODlENjcwRjNCM0IxOTgxQjhDMzA2MA0GCSqGSIb3DQEB" +
            "BAUAMCwxCzAJBgNVBAYTAlNFMQ8wDQYDVQQKEwZBbmFUb20xDDAKBgNVBAMTA2Zv" +
            "bzAeFw0wMzA2MTkwODQ3NDlaFw0wMzA3MTkwODQ3NDlaMCwxCzAJBgNVBAYTAlNF" +
            "MQ8wDQYDVQQKEwZBbmFUb20xDDAKBgNVBAMTA2ZvbzBcMA0GCSqGSIb3DQEBAQUA" +
            "A0sAMEgCQQDLfHDEOse6Mbi02egr2buI9mgWC0ur9dvGmLiIxmNg1TNhn1WHj5Zy" +
            "VsjKyLoVuVqgGRPYVA73ItANF8RNBAt9AgMBAAEwDQYJKoZIhvcNAQEEBQADQQCw" +
            "9kQsl3M0Ag1892Bu3izeZOYKpze64kJ7iGuYmN8atkdO8Rpp4Jn0W6vvUYQcat2a" +
            "Jzf6h3xfEQ7m8CzvaQ2/MYIBfDCCAXgCAQEwUDAsMQswCQYDVQQGEwJTRTEPMA0G" +
            "A1UEChMGQW5hVG9tMQwwCgYDVQQDEwNmb28CIDNGREQzNUM5NzZDODlENjcwRjNC" +
            "M0IxOTgxQjhDMzA2MAwGCCqGSIb3DQIFBQCggcEwEgYKYIZIAYb4RQEJAjEEEwIx" +
            "OTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0wMzA2" +
            "MTkwODQ3NDlaMB8GCSqGSIb3DQEJBDESBBCevtHE4n3my5B7Q+MiKj04MCAGCmCG" +
            "SAGG+EUBCQUxEgQQwH1TAMlSzz1d3SNXoOARkTAwBgpghkgBhvhFAQkHMSITIDNG" +
            "REQzNUM5NzZDODlENjcwRjNCM0IxOTgxQjhDMzA2MA0GCSqGSIb3DQEBAQUABEAW" +
            "r+9YB3t1750Aj4bm5JAHv80VhzkrPmVLZqsJdC2DGn3UQFp1FhXo4od2xGpeg+pZ" +
            "b0B6kUt+uxvuq3PbagLi").getBytes());
    static byte[] keytooldsa = Base64.decode(("MIICNjCCAfQCAQAwMTERMA8GA1UEAxMIRFNBIFRlc3QxDzANBgNVBAoTBkFuYXRvbTELMAkGA1UE" +
            "BhMCU0UwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/" +
            "gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfG" +
            "G/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCFQCXYFCPFSMLzLKS" +
            "uYKi64QL8Fgc9QKBgQD34aCF1ps93su8q1w2uFe5eZSvu/o66oL5V0wLPQeCZ1FZV4661FlP5nEH" +
            "EIGAtEkWcSPoTCgWE7fPCTKMyKbhPBZ6i1R8jSjgo64eK7OmdZFuo38L+iE1YvH7YnoBJDvMpPG+" +
            "qFGQiaiD3+Fa5Z8GkotmXoB7VSVkAUw7/s9JKgOBhQACgYEAiVCUaC95mHaU3C9odWcuJ8j3fT6z" +
            "bSR02CVFC0F6QO5s2Tx3JYWrm5aAjWkXWJfeYOR6qBSwX0R1US3rDI0Kepsrdco2q7wGSo+235KL" +
            "Yfl7tQ9RLOKUGX/1c5+XuvN1ZbGy0yUw3Le16UViahWmmx6FM1sW6M48U7C/CZOyoxagADALBgcq" +
            "hkjOOAQDBQADLwAwLAIUQ+S2iFA1y7dfDWUCg7j1Nc8RW0oCFFhnDlU69xFRMeXXn1C/Oi+8pwrQ").getBytes());
    private static final Logger log = Logger.getLogger(SignSessionTest.class);
    private static KeyPair rsakeys=null;
    private static KeyPair rsakeys2=null;
    private static KeyPair ecdsakeys=null;
    private static KeyPair ecdsasecpkeys=null;
    private static KeyPair ecdsaimplicitlyca=null;
    private static KeyPair dsakeys=null;
    private static int rsacaid = 0;
    private static int rsareversecaid = 0;
    private static int ecdsacaid = 0;
    private static int ecdsaimplicitlycacaid = 0;
    private static int rsamgf1cacaid = 0;
    private static int cvccaid = 0;
    private static int cvccaecid = 0;
    private static int dsacaid = 0;

    X509Certificate rsacacert = null;
    X509Certificate rsarevcacert = null;
    X509Certificate ecdsacacert = null;
    X509Certificate ecdsaimplicitlycacacert = null;
    X509Certificate rsamgf1cacacert = null;
    Certificate cvccacert = null;
    Certificate cvcdveccert = null;
    Certificate cvcaeccert = null;
    X509Certificate dsacacert = null;
    private final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

    @EJB
    private CertificateStoreSessionRemote certificateStoreSession;

    @EJB
    private RaAdminSessionRemote raAdminSession;
    
    @EJB
    private SignSessionRemote signSession;

    @EJB
    private UserAdminSessionRemote userAdminSession;

    /**
     * Creates a new TestSignSession object.
     * 
     * @param name
     *            name
     */
    public SignSessionTest(String name) throws Exception {
        super(name);

        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
        if (rsakeys == null) {
            rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
        if (rsakeys2 == null) {
            rsakeys2 = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
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
        assertTrue("Could not create TestCA.", createTestCA());
        CAInfo inforsa = caAdminSessionRemote.getCAInfo(admin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();
        CAInfo inforsareverse = caAdminSessionRemote.getCAInfo(admin, "TESTRSAREVERSE");
        assertTrue("No active RSA Reverse CA! Must have at least one active reverse CA to run tests!", inforsareverse != null);
        rsareversecaid = inforsareverse.getCAId();
        CAInfo infoecdsa = caAdminSessionRemote.getCAInfo(admin, "TESTECDSA");
        assertTrue("No active ECDSA CA! Must have at least one active CA to run tests!", infoecdsa != null);
        ecdsacaid = infoecdsa.getCAId();
        CAInfo infoecdsaimplicitlyca = caAdminSessionRemote.getCAInfo(admin, "TESTECDSAImplicitlyCA");
        assertTrue("No active ECDSA ImplicitlyCA CA! Must have at least one active CA to run tests!", infoecdsaimplicitlyca != null);
        ecdsaimplicitlycacaid = infoecdsaimplicitlyca.getCAId();
        CAInfo inforsamgf1ca = caAdminSessionRemote.getCAInfo(admin, "TESTSha256WithMGF1");
        assertTrue("No active RSA MGF1 CA! Must have at least one active CA to run tests!", inforsamgf1ca != null);
        rsamgf1cacaid = inforsamgf1ca.getCAId();
        CAInfo infocvcca = caAdminSessionRemote.getCAInfo(admin, "TESTDV-D");
        assertTrue("No active CVC CA! Must have at least one active CA to run tests!", infocvcca != null);
        cvccaid = infocvcca.getCAId();
        CAInfo infocvccaec = caAdminSessionRemote.getCAInfo(admin, "TESTDVECC-D");
        assertTrue("No active CVC EC CA! Must have at least one active CA to run tests!", infocvccaec != null);
        cvccaecid = infocvccaec.getCAId();
        CAInfo infodsa = caAdminSessionRemote.getCAInfo(admin, "TESTDSA");
        assertTrue("No active DSA CA! Must have at least one active CA to run tests!", infodsa != null);
        dsacaid = infodsa.getCAId();
        Collection coll = inforsa.getCertificateChain();
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

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * creates new user
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test01CreateNewUser() throws Exception {
        log.trace(">test01CreateNewUser()");

        certificateStoreSession.removeCertificateProfile(admin, "FOOCERTPROFILE");
        final EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        certprof.setAllowKeyUsageOverride(true);
        certificateStoreSession.addCertificateProfile(admin, "FOOCERTPROFILE", certprof);
        final int fooCertProfile = certificateStoreSession.getCertificateProfileId(admin, "FOOCERTPROFILE");

        raAdminSession.removeEndEntityProfile(admin, "FOOEEPROFILE");
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        raAdminSession.addEndEntityProfile(admin, "FOOEEPROFILE", profile);
        final int fooEEProfile = raAdminSession.getEndEntityProfileId(admin, "FOOEEPROFILE");

        // Make user that we know...
        boolean userExists = false;
        try {
            userAdminSession.addUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo", null, "foo@anatom.se", false, fooEEProfile, fooCertProfile,
                    SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
            log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User foo already exists, resetting status.");
            userAdminSession.changeUser(admin, "foo", "foo123", "C=SE,O=AnaTom,CN=foo", null, "foo@anatom.se", false, fooEEProfile, fooCertProfile,
                    SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsacaid);
            log.debug("Reset status to NEW");
        }
        userExists = false;
        try {
            userAdminSession.addUser(admin, "foorev", "foo123", "C=SE,O=AnaTom,CN=foorev", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsareversecaid);
            log.debug("created user: foorev, foo123, C=SE, O=AnaTom, CN=foorev");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User foorev already exists, resetting status.");
            userAdminSession.changeUser(admin, "foorev", "foo123", "C=SE,O=AnaTom,CN=foorev", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, UserDataConstants.STATUS_NEW, rsareversecaid);
            log.debug("Reset status to NEW");
        }
        userExists = false;
        try {
            userAdminSession.addUser(admin, "fooecdsa", "foo123", "C=SE,O=AnaTom,CN=fooecdsa", null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, ecdsacaid);
            log.debug("created user: fooecdsa, foo123, C=SE, O=AnaTom, CN=fooecdsa");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User fooecdsa already exists, resetting status.");
            userAdminSession.setUserStatus(admin, "fooecdsa", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        userExists = false;
        try {
            userAdminSession.addUser(admin, "fooecdsaimpca", "foo123", "C=SE,O=AnaTom,CN=fooecdsaimpca", null, "foo@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0,
                    ecdsaimplicitlycacaid);
            log.debug("created user: fooecdsaimpca, foo123, C=SE, O=AnaTom, CN=fooecdsaimpca");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User fooecdsaimpca already exists, resetting status.");
            userAdminSession.setUserStatus(admin, "fooecdsaimpca", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        userExists = false;
        try {
            userAdminSession.addUser(admin, "foorsamgf1ca", "foo123", "C=SE,O=AnaTom,CN=foorsamgf1ca", null, "foo@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsamgf1cacaid);
            log.debug("created user: foorsamgf1ca, foo123, C=SE, O=AnaTom, CN=foorsamgf1ca");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User foorsamgf1ca already exists, resetting status.");
            userAdminSession.setUserStatus(admin, "foorsamgf1ca", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        userExists = false;
        try {
            userAdminSession.addUser(admin, "foodsa", "foo123", "C=SE,O=AnaTom,CN=foodsa", null, "foodsa@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, dsacaid);
            log.debug("created user: foodsa, foo123, C=SE, O=AnaTom, CN=foodsa");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User foodsa already exists, resetting status.");
            userAdminSession.setUserStatus(admin, "foodsa", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        log.trace("<test01CreateNewUser()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test02SignSession() throws Exception {
        log.trace(">test02SignSession()");

        // user that we know exists...
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        // Normal DN order
        assertEquals(cert.getSubjectX500Principal().getName(), "C=SE,O=AnaTom,CN=foo");
        try {
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
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
    public void test03TestBCPKCS10() throws Exception {
        log.trace(">test03TestBCPKCS10()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10,
                Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.trace("<test03TestBCPKCS10()");
    }

    /**
     * tests keytool pkcs10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test04TestKeytoolPKCS10() throws Exception {
        log.trace(">test04TestKeytoolPKCS10()");

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(keytoolp10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test05TestIEPKCS10() throws Exception {
        log.trace(">test05TestIEPKCS10()");

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        PKCS10RequestMessage p10 = new PKCS10RequestMessage(iep10);
        p10.setUsername("foo");
        p10.setPassword("foo123");
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        log.trace("<test05TestIEPKCS10()");
    }

    /**
     * test to set specific key usage
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test06KeyUsage() throws Exception {
        log.trace(">test06KeyUsage()");

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        // Create an array for KeyUsage acoording to
        // X509Certificate.getKeyUsage()
        boolean[] keyusage1 = new boolean[9];
        Arrays.fill(keyusage1, false);
        // digitalSignature
        keyusage1[0] = true;
        // keyEncipherment
        keyusage1[2] = true;

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), keyusage1);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        boolean[] retKU = cert.getKeyUsage();
        assertTrue("Fel KeyUsage, digitalSignature finns ej!", retKU[0]);
        assertTrue("Fel KeyUsage, keyEncipherment finns ej!", retKU[2]);
        assertTrue("Fel KeyUsage, cRLSign finns!", !retKU[6]);

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        boolean[] keyusage2 = new boolean[9];
        Arrays.fill(keyusage2, false);
        // keyCertSign
        keyusage2[5] = true;
        // cRLSign
        keyusage2[6] = true;

        X509Certificate cert1 = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), keyusage2);
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
    public void test07DSAKey() throws Exception {
        log.trace(">test07DSAKey()");

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");

        try {
            PKCS10RequestMessage p10 = new PKCS10RequestMessage(keytooldsa);
            p10.setUsername("foo");
            p10.setPassword("foo123");
            IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test08SwedeChars() throws Exception {
        log.trace(">test08SwedeChars()");
        // Make user that we know...
        boolean userExists = false;
        try {
            // We use unicode encoding for the three swedish character åäö
            userAdminSession.addUser(admin, "swede", "foo123", "C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6", null, "swede@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
            log.debug("created user: swede, foo123, C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6");
        } catch (RemoteException re) {
            userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.debug("user swede already exists: swede, foo123, C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6");

            userAdminSession.setUserStatus(admin, "swede", UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

        // user that we know exists...; use new key so that the check that two
        // don't prevent the creation of the certificate.
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "swede", "foo123", rsakeys2.getPublic());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        assertEquals("Wrong DN med swedechars", CertTools.stringToBCDNString("C=SE, O=\u00E5\u00E4\u00F6, CN=\u00E5\u00E4\u00F6"), CertTools.getSubjectDN(cert));
        // FileOutputStream fos = new FileOutputStream("/tmp/swedecert.crt");
        // fos.write(cert.getEncoded());
        // fos.close();
        log.trace("<test08SwedeChars()");
    }

    /**
     * Tests multiple instances of one altName
     * 
     */
    public void test09TestMultipleAltNames() throws Exception {
        log.trace(">test09TestMultipleAltNames()");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTMULALTNAME");
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
        raAdminSession.addEndEntityProfile(admin, "TESTMULALTNAME", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTMULALTNAME");

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
        ArrayList list = CertTools.getPartsFromDN(altNames, CertTools.UPN);
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
        raAdminSession.removeEndEntityProfile(admin, "TESTMULALTNAME");

        log.trace("<test09TestMultipleAltNames()");
    }

    /**
     * Tests creting a certificate with QC statement
     * 
     */
    public void test10TestQcCert() throws Exception {
        log.trace(">test10TestQcCert()");

        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTQC");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        certprof.setUseQCStatement(true);
        certprof.setQCStatementRAName("rfc822Name=qc@primekey.se");
        certprof.setUseQCEtsiQCCompliance(true);
        certprof.setUseQCEtsiSignatureDevice(true);
        certprof.setUseQCEtsiValueLimit(true);
        certprof.setQCEtsiValueLimit(50000);
        certprof.setQCEtsiValueLimitCurrency("SEK");
        certificateStoreSession.addCertificateProfile(admin, "TESTQC", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTQC");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTQC");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        raAdminSession.addEndEntityProfile(admin, "TESTQC", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTQC");

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
        Collection ids = QCStatementExtension.getQcStatementIds(cert);
        assertTrue(ids.contains(RFC3739QCObjectIdentifiers.id_qcs_pkixQCSyntax_v1.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD.getId()));
        assertTrue(ids.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
        String limit = QCStatementExtension.getQcStatementValueLimit(cert);
        assertEquals("50000 SEK", limit);

        // Clean up
        raAdminSession.removeEndEntityProfile(admin, "TESTQC");
        certificateStoreSession.removeCertificateProfile(admin, "TESTQC");

        log.trace("<test10TestQcCert()");
    }

    /**
     * Tests creting a certificate with QC statement
     * 
     */
    public void test11TestValidityOverride() throws Exception {
        log.trace(">test11TestValidityOverrideAndCardNumber()");

        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTVALOVERRIDE");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        certprof.setAllowValidityOverride(false);
        certprof.setValidity(298);
        certprof.setUseCardNumber(true);
        certificateStoreSession.addCertificateProfile(admin, "TESTVALOVERRIDE", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTVALOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTVALOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        profile.setUse(EndEntityProfile.CARDNUMBER, 0, true);
        raAdminSession.addEndEntityProfile(admin, "TESTVALOVERRIDE", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTVALOVERRIDE");
        try {
            // Change a user that we know...
            UserDataVO user = new UserDataVO("foo", "C=SE,CN=validityoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
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
        } catch (RemoteException re) {
            assertTrue("User foo does not exist, or error changing user", false);
        }
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 10);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, null,
                cal.getTime());
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
        CertificateProfile prof = certificateStoreSession.getCertificateProfile(admin, cprofile);
        prof.setAllowValidityOverride(true);
        prof.setValidity(3065);
        prof.setUseCardNumber(false);
        certificateStoreSession.changeCertificateProfile(admin, "TESTVALOVERRIDE", prof);
        cal = Calendar.getInstance();
        Calendar notBefore = Calendar.getInstance();
        notBefore.add(Calendar.DAY_OF_MONTH, 2);
        cal.add(Calendar.DAY_OF_MONTH, 10);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, notBefore.getTime(),
                cal.getTime());
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
        prof = certificateStoreSession.getCertificateProfile(admin, cprofile);
        prof.setValidity(50);
        certificateStoreSession.changeCertificateProfile(admin, "TESTVALOVERRIDE", prof);
        notBefore = Calendar.getInstance();
        notBefore.add(Calendar.DAY_OF_MONTH, -2);
        cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 200);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic(), -1, notBefore.getTime(),
                cal.getTime());
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
        raAdminSession.removeEndEntityProfile(admin, "TESTVALOVERRIDE");
        certificateStoreSession.removeCertificateProfile(admin, "TESTVALOVERRIDE");

        log.trace("<test11TestValidityOverride()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test12SignSessionECDSAWithRSACA() throws Exception {
        log.trace(">test12SignSessionECDSAWithRSACA()");

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
    public void test13TestBCPKCS10ECDSAWithRSACA() throws Exception {
        log.trace(">test13TestBCPKCS10ECDSAWithRSACA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test14SignSessionECDSAWithECDSACA() throws Exception {
        log.trace(">test14SignSessionECDSAWithECDSACA()");

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
    public void test15TestBCPKCS10ECDSAWithECDSACA() throws Exception {
        log.trace(">test15TestBCPKCS10ECDSAWithECDSACA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test16SignSessionECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test16SignSessionECDSAWithECDSAImplicitlyCACA()");

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
    public void test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test18SignSessionRSAMGF1WithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test18SignSessionRSAWithRSASha256WithMGF1CA()");

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
    public void test19TestBCPKCS10RSAWithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test19TestBCPKCS10RSAWithRSASha256WithMGF1CA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test20MultiRequests() throws Exception {
        log.trace(">test20MultiRequests()");

        // Test that it works correctly with end entity profiles using the
        // counter
        int pid = 0;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.addField(DnComponents.COMMONNAME);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, "" + rsacaid);
            profile.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
            profile.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, "3");
            raAdminSession.addEndEntityProfile(admin, "TESTREQUESTCOUNTER", profile);
            pid = raAdminSession.getEndEntityProfileId(admin, "TESTREQUESTCOUNTER");
        } catch (EndEntityProfileExistsException pee) {
            assertTrue("Can not create end entity profile", false);
        }

        // Change already existing user
        UserDataVO user = new UserDataVO("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, null, SecConst.USER_ENDUSER, pid, SecConst.CERTPROFILE_FIXED_ENDUSER,
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
        ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(allowedrequests));
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

        UserDataVO user = new UserDataVO("cvc", "C=SE,CN=TESTCVC", cvccaid, null, null, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
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
        UserDataVO userec = new UserDataVO("cvcec", "C=SE,CN=TCVCEC", cvccaecid, null, null, SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
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

    public void test22DnOrder() throws Exception {
        log.trace(">test22DnOrder()");

        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTDNORDER");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        certificateStoreSession.addCertificateProfile(admin, "TESTDNORDER", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTDNORDER");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTDNORDER");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        raAdminSession.addEndEntityProfile(admin, "TESTDNORDER", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTDNORDER");

        UserDataVO user = new UserDataVO("foo", "C=SE,O=PrimeKey,CN=dnorder", rsacaid, null, "foo@primekey.se", SecConst.USER_ENDUSER, eeprofile, cprofile,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setStatus(UserDataConstants.STATUS_NEW);
        try {
            // Change a user that we know...
            userAdminSession.changeUser(admin, user, false);
            log.debug("created user: foo, foo123, C=SE,O=PrimeKey,CN=dnorder");
        } catch (RemoteException re) {
            assertTrue("User foo does not exist, or error changing user", false);
        }
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        String dn = cert.getSubjectDN().getName();
        // This is the reverse order than what is displayed by openssl
        assertEquals("C=SE, O=PrimeKey, CN=dnorder", dn);

        // Change to X509 DN order
        certprof.setUseLdapDnOrder(false);
        certificateStoreSession.changeCertificateProfile(admin, "TESTDNORDER", certprof);
        userAdminSession.changeUser(admin, user, false);
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        dn = cert.getSubjectDN().getName();
        // This is the reverse order than what is displayed by openssl
        assertEquals("CN=dnorder, O=PrimeKey, C=SE", dn);

        // Clean up
        raAdminSession.removeEndEntityProfile(admin, "TESTDNORDER");
        certificateStoreSession.removeCertificateProfile(admin, "TESTDNORDER");

        log.trace("<test22DnOrder()");
    }

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test23SignSessionDSAWithRSACA() throws Exception {
        log.trace(">test23SignSessionDSAWithRSACA()");

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
    public void test24TestBCPKCS10DSAWithRSACA() throws Exception {
        log.trace(">test24TestBCPKCS10DSAWithRSACA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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
    public void test25SignSessionDSAWithDSACA() throws Exception {
        log.trace(">test25SignSessionDSAWithDSACA()");

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
    public void test26TestBCPKCS10DSAWithDSACA() throws Exception {
        log.trace(">test26TestBCPKCS10DSAWithDSACA()");
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
        IResponseMessage resp = signSession.createCertificate(admin, p10, Class.forName("org.ejbca.core.protocol.X509ResponseMessage"));
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

    /**
     * creates cert
     * 
     * @throws Exception
     *             if en error occurs...
     */
    public void test27IssuanceRevocationReason() throws Exception {
        log.trace(">test27IssuanceRevocationReason()");

        // Test that it works correctly with end entity profiles using the
        // counter
        int pid = 0;
        try {
            EndEntityProfile profile = new EndEntityProfile();
            profile.addField(DnComponents.ORGANIZATION);
            profile.addField(DnComponents.COUNTRY);
            profile.addField(DnComponents.COMMONNAME);
            profile.setValue(EndEntityProfile.AVAILCAS, 0, "" + rsacaid);
            profile.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, true);
            profile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
            raAdminSession.addEndEntityProfile(admin, "TESTISSUANCEREVREASON", profile);
            pid = raAdminSession.getEndEntityProfileId(admin, "TESTISSUANCEREVREASON");
        } catch (EndEntityProfileExistsException pee) {
            assertTrue("Can not create end entity profile", false);
        }

        // Change already existing user
        UserDataVO user = new UserDataVO("foo", "C=SE,O=AnaTom,CN=foo", rsacaid, null, null, SecConst.USER_ENDUSER, pid, SecConst.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userAdminSession.changeUser(admin, user, false);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        // create first cert
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);

        // Check that it is active
        boolean isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertFalse(isRevoked);

        // Now add extended information with the revocation reason
        ExtendedInformation ei = new ExtendedInformation();
        ei.setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, "" + RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
        user.setExtendedinformation(ei);
        userAdminSession.changeUser(admin, user, false);
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        // create first cert
        cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create cert", cert);

        // Check that it is revoked
        CertificateStatus rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, rev.revocationReason);
        log.trace("<test27IssuanceRevocationReason()");
    }

    public void test28TestDNOverride() throws Exception {
        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTDNOVERRIDE");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        // Default profile does not allow DN override
        certprof.setValidity(298);
        certificateStoreSession.addCertificateProfile(admin, "TESTDNOVERRIDE", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTDNOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTDNOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        raAdminSession.addEndEntityProfile(admin, "TESTDNOVERRIDE", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTDNOVERRIDE");
        UserDataVO user = new UserDataVO("foo", "C=SE,CN=dnoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
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
        IResponseMessage resp = signSession.createCertificate(admin, p10,
                Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=dnoverride,C=SE", cert.getSubjectDN().getName());

        // Change so that we allow override of validity time
        CertificateProfile prof = certificateStoreSession.getCertificateProfile(admin, cprofile);
        prof.setAllowDNOverride(true);
        certificateStoreSession.changeCertificateProfile(admin, "TESTDNOVERRIDE", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=foo,C=SE,Name=AnaTom,O=My org", cert.getSubjectDN().getName());

    } // test28TestDNOverride

    public void test29TestExtensionOverride() throws Exception {
        final String altnames = "dNSName=foo1.bar.com,dNSName=foo2.bar.com,dNSName=foo3.bar.com,dNSName=foo4.bar.com,dNSName=foo5.bar.com,dNSName=foo6.bar.com,dNSName=foo7.bar.com,dNSName=foo8.bar.com,dNSName=foo9.bar.com,dNSName=foo10.bar.com,dNSName=foo11.bar.com,dNSName=foo12.bar.com,dNSName=foo13.bar.com,dNSName=foo14.bar.com,dNSName=foo15.bar.com,dNSName=foo16.bar.com,dNSName=foo17.bar.com,dNSName=foo18.bar.com,dNSName=foo19.bar.com,dNSName=foo20.bar.com,dNSName=foo21.bar.com";
        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTEXTENSIONOVERRIDE");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        // Default profile does not allow Extension override
        certprof.setValidity(298);
        certificateStoreSession.addCertificateProfile(admin, "TESTEXTENSIONOVERRIDE", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTEXTENSIONOVERRIDE");

        // Create a good end entity profile (good enough), allowing multiple UPN
        // names
        raAdminSession.removeEndEntityProfile(admin, "TESTEXTENSIONOVERRIDE");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        raAdminSession.addEndEntityProfile(admin, "TESTEXTENSIONOVERRIDE", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTEXTENSIONOVERRIDE");
        UserDataVO user = new UserDataVO("foo", "C=SE,CN=extoverride", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
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
        String[] namearray = altnames.split(",");
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
        Vector oidvec = new Vector();
        oidvec.add(X509Extensions.SubjectAlternativeName);
        Vector valuevec = new Vector();
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
        IResponseMessage resp = signSession.createCertificate(admin, p10,
                Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=extoverride,C=SE", cert.getSubjectDN().getName());
        // check altNames, should be none
        Collection c = cert.getSubjectAlternativeNames();
        assertNull(c);

        // Change so that we allow override of validity time
        CertificateProfile prof = certificateStoreSession.getCertificateProfile(admin, cprofile);
        prof.setAllowExtensionOverride(true);
        certificateStoreSession.changeCertificateProfile(admin, "TESTEXTENSIONOVERRIDE", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=extoverride,C=SE", cert.getSubjectDN().getName());
        // check altNames, should be one altName
        c = cert.getSubjectAlternativeNames();
        assertNotNull(c);
        assertEquals(21, c.size());
        String retAltNames = CertTools.getSubjectAlternativeName(cert);
        List originalNames = Arrays.asList(altnames.split(","));
        List returnNames = Arrays.asList(retAltNames.split(", "));
        assertTrue(originalNames.containsAll(returnNames));
    } // test29TestExtensionOverride

    public void test30OfflineCA() throws Exception {
        // user that we know exists...
        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // Set CA to offline
        CAInfo inforsa = caAdminSessionRemote.getCAInfo(admin, rsacaid);
        inforsa.setStatus(SecConst.CA_OFFLINE);
        caAdminSessionRemote.editCA(admin, inforsa);

        userAdminSession.setUserStatus(admin, "foo", UserDataConstants.STATUS_NEW);
        boolean thrown = false;
        try {
            cert = (X509Certificate) signSession.createCertificate(admin, "foo", "foo123", rsakeys.getPublic());
        } catch (Exception e) {
            thrown = true;
        }
        assertTrue(thrown);

        inforsa.setStatus(SecConst.CA_ACTIVE);
        caAdminSessionRemote.editCA(admin, inforsa);
    }

    public void test31TestProfileSignatureAlgorithm() throws Exception {
        // Create a good certificate profile (good enough), using QC statement
        certificateStoreSession.removeCertificateProfile(admin, "TESTSIGALG");
        EndUserCertificateProfile certprof = new EndUserCertificateProfile();
        // Default profile uses "inherit from CA"
        certificateStoreSession.addCertificateProfile(admin, "TESTSIGALG", certprof);
        int cprofile = certificateStoreSession.getCertificateProfileId(admin, "TESTSIGALG");

        // Create a good end entity profile (good enough)
        raAdminSession.removeEndEntityProfile(admin, "TESTSIGALG");
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(cprofile));
        raAdminSession.addEndEntityProfile(admin, "TESTSIGALG", profile);
        int eeprofile = raAdminSession.getEndEntityProfileId(admin, "TESTSIGALG");
        UserDataVO user = new UserDataVO("foo", "C=SE,CN=testsigalg", rsacaid, null, "foo@anatom.nu", SecConst.USER_ENDUSER, eeprofile, cprofile,
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
        IResponseMessage resp = signSession.createCertificate(admin, p10,
                Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=testsigalg,C=SE", cert.getSubjectDN().getName());
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CertTools.getSignatureAlgorithm(cert));

        // Change so that we can override signature algorithm
        CertificateProfile prof = certificateStoreSession.getCertificateProfile(admin, cprofile);
        prof.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        certificateStoreSession.changeCertificateProfile(admin, "TESTSIGALG", prof);

        userAdminSession.changeUser(admin, user, false);
        resp = signSession.createCertificate(admin, p10, Class.forName(org.ejbca.core.protocol.X509ResponseMessage.class.getName()));
        cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        assertEquals("CN=testsigalg,C=SE", cert.getSubjectDN().getName());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CertTools.getSignatureAlgorithm(cert));
    } // test31TestProfileSignatureAlgorithm

    public void test32TestCertReqHistory() throws Exception {

        // Configure CA not to store certreq history
        CAInfo cainfo = caAdminSessionRemote.getCAInfo(admin, rsacaid);
        cainfo.setUseCertReqHistory(true);
        cainfo.setDoEnforceUniquePublicKeys(false);
        caAdminSessionRemote.editCA(admin, cainfo);

        // New random username and create cert
        String username = genRandomUserName();
        userAdminSession.addUser(admin, username, "foo123", "C=SE,O=AnaTom,CN=" + username, null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        // Check that certreq history was created
        List history = certificateStoreSession.getCertReqHistory(admin, username);
        assertEquals(1, history.size());

        userAdminSession.deleteUser(admin, username);

        // Configure CA not to store certreq history
        cainfo.setUseCertReqHistory(false);
        caAdminSessionRemote.editCA(admin, cainfo);
        // New random username and create cert
        username = genRandomUserName();
        userAdminSession.addUser(admin, username, "foo123", "C=SE,O=AnaTom,CN=" + username, null, "foo@anatom.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, rsacaid);
        cert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        // Check that certreq history was not created
        history = certificateStoreSession.getCertReqHistory(admin, username);
        assertEquals(0, history.size());

        userAdminSession.deleteUser(admin, username);

        // Reset CA info
        cainfo.setUseCertReqHistory(true);
        caAdminSessionRemote.editCA(admin, cainfo);
    } // test32TestCertReqHistory

    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");

        // Delete test end entity profile
        try {
            raAdminSession.removeEndEntityProfile(admin, "TESTREQUESTCOUNTER");
        } catch (Exception e) { /* ignore */
        }
        try {
            raAdminSession.removeEndEntityProfile(admin, "TESTISSUANCEREVREASON");
        } catch (Exception e) { /* ignore */
        }
        try {
            raAdminSession.removeEndEntityProfile(admin, "TESTDNOVERRIDE");
        } catch (Exception e) { /* ignore */
        }
        try {
            certificateStoreSession.removeCertificateProfile(admin, "TESTDNOVERRIDE ");
        } catch (Exception e) { /* ignore */
        }
        raAdminSession.removeEndEntityProfile(admin, "FOOEEPROFILE");
        certificateStoreSession.removeCertificateProfile(admin, "FOOCERTPROFILE");
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
            userAdminSession.deleteUser(admin, "fooecdsaimpca");
            log.debug("deleted user: fooecdsaimpca, foo123, C=SE, O=AnaTom, CN=foo");
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

        removeTestCA();
        log.trace("<test99CleanUp()");
    }

    /**
     * Tests scep message
     */
    /*
     * public void test10TestOpenScep() throws Exception {
     * log.trace(">test10TestOpenScep()"); UserDataPK pk = new
     * UserDataPK("foo"); UserDataRemote data = userhome.findByPrimaryKey(pk);
     * data.setStatus(UserDataRemote.STATUS_NEW);
     * log.debug("Reset status of 'foo' to NEW"); IResponseMessage resp =
     * remote.createCertificate(admin, new ScepRequestMessage(openscep), -1,
     * Class.forName("org.ejbca.core.protocol.ScepResponseMessage"));
     * assertNotNull("Failed to create certificate", resp); byte[] msg =
     * resp.getResponseMessage(); log.debug("Message: "+new
     * String(Base64.encode(msg,true)));
     * assertNotNull("Failed to get encoded response message", msg);
     * log.trace("<test10TestOpenScep()"); }
     */
}
