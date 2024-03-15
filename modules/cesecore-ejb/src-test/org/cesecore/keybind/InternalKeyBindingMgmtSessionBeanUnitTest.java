package org.cesecore.keybind;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.pinning.TrustEntry;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.*;

@RunWith(EasyMockRunner.class)
public class InternalKeyBindingMgmtSessionBeanUnitTest {

    @Mock
    private CaSessionLocal caSession;
    @Mock
    private CertificateDataSessionLocal certificateDataSession;

    @TestSubject
    private final InternalKeyBindingMgmtSessionBean keyBindingMgmtSessionBean = new InternalKeyBindingMgmtSessionBean();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void getTrustEntriesAll() throws Exception {
        //Should return all CAs including active versions of renewed ones
        //given
        List<Integer> allCAs = List.of(1, 2);
        expect(caSession.getAllCaIds()).andReturn(allCAs);

        final CAInfo caInfo1 = X509CAInfo.getDefaultX509CAInfo("cn=1", "CA1", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                0, generateCertificateChain("cn=1"), null);
        final CAInfo caInfo2 = X509CAInfo.getDefaultX509CAInfo("cn=2", "CA2", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                0, generateCertificateChain("cn=2"), null);
        expect(caSession.getCAInfoInternal(1)).andReturn(caInfo1);
        expect(caSession.getCAInfoInternal(2)).andReturn(caInfo2);
        replay(caSession);

        expect(certificateDataSession.findActiveBySubjectDnAndType(caInfo1.getSubjectDN(),
                Arrays.asList(CertificateConstants.CERTTYPE_SUBCA, CertificateConstants.CERTTYPE_ROOTCA)))
                .andReturn(generateCertificateChain("cn=1"));
        expect(certificateDataSession.findActiveBySubjectDnAndType(caInfo2.getSubjectDN(),
                Arrays.asList(CertificateConstants.CERTTYPE_SUBCA, CertificateConstants.CERTTYPE_ROOTCA)))
                .andReturn(new ArrayList<>());
        replay(certificateDataSession);

        InternalKeyBinding keyBinding = new AuthenticationKeyBinding();
        //when
        List<TrustEntry> trustEntries = keyBindingMgmtSessionBean.getTrustEntries(keyBinding);
        //then
        assertEquals("",3,  trustEntries.size());
    }

    @Test
    public void getTrustEntriesReferenced() throws Exception {
        //Should return all CAs mentioned as trusted including active versions of renewed ones

        //given
        final CAInfo caInfo1 = X509CAInfo.getDefaultX509CAInfo("cn=1", "CA1", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                0, generateCertificateChain("cn=1"), null);
        expect(caSession.getCAInfoInternal(caInfo1.getCAId())).andReturn(caInfo1);
        expect(caSession.getCAInfoInternal(1)).andReturn(caInfo1);
        replay(caSession);
        expect(certificateDataSession.findActiveBySubjectDnAndType(caInfo1.getSubjectDN(),
                Arrays.asList(CertificateConstants.CERTTYPE_SUBCA, CertificateConstants.CERTTYPE_ROOTCA)))
                .andReturn(generateCertificateChain("cn=1"));
        replay(certificateDataSession);
        InternalKeyBinding keyBinding = new AuthenticationKeyBinding();
        final List<InternalKeyBindingTrustEntry> trustList = new ArrayList<InternalKeyBindingTrustEntry>();
        trustList.add(new InternalKeyBindingTrustEntry(caInfo1.getCAId(), null));
        keyBinding.setTrustedCertificateReferences(trustList);
        //when
        List<TrustEntry> trustEntries = keyBindingMgmtSessionBean.getTrustEntries(keyBinding);
        //then
        assertEquals("",2,  trustEntries.size());
    }

    @Test
    public void getTrustEntriesTrustedWithSerial() throws Exception {
        //Should return all CAs mentioned as trusted with serial, including active versions of renewed ones
        //Should return all CAs mentioned as trusted including active versions of renewed ones

        //given
        final CAInfo caInfo1 = X509CAInfo.getDefaultX509CAInfo("cn=1", "CA1", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "3650d",
                0, generateCertificateChain("cn=1"), null);
        expect(caSession.getCAInfoInternal(caInfo1.getCAId())).andReturn(caInfo1);
        expect(caSession.getCAInfoInternal(1)).andReturn(caInfo1);
        replay(caSession);
        expect(certificateDataSession.findActiveBySubjectDnAndType(caInfo1.getSubjectDN(),
                Arrays.asList(CertificateConstants.CERTTYPE_SUBCA, CertificateConstants.CERTTYPE_ROOTCA)))
                .andReturn(generateCertificateChain("cn=1"));
        replay(certificateDataSession);
        InternalKeyBinding keyBinding = new AuthenticationKeyBinding();
        final List<InternalKeyBindingTrustEntry> trustList = new ArrayList<InternalKeyBindingTrustEntry>();
        trustList.add(new InternalKeyBindingTrustEntry(caInfo1.getCAId(), BigInteger.valueOf(1234567L)));
        keyBinding.setTrustedCertificateReferences(trustList);
        //when
        List<TrustEntry> trustEntries = keyBindingMgmtSessionBean.getTrustEntries(keyBinding);
        //then
        assertEquals("",2,  trustEntries.size());
    }

    private List<Certificate>  generateCertificateChain(String subjectDn) throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert(subjectDn, 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
       return List.of(certificate);
    }
}