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
package org.ejbca.jscep;

import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CertStore;

import javax.security.auth.callback.CallbackHandler;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.ScepConfiguration;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.inspect.CertStoreInspector;
import org.jscep.client.inspect.DefaultCertStoreInspectorFactory;
import org.jscep.client.verification.OptimisticCertificateVerifier;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestRule;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Provides basic RA testing on the getCACerts operation using jscep
 */
public class GetCaCertsJscepSystemTest extends JscepTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GetCaCertsJscepSystemTest"));

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Rule
    public TestName testName = new TestName();

    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private String scepAlias;
    private String caName;
    private String caDn;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setup() throws AuthorizationDeniedException, CertificateProfileExistsException {
        scepAlias = (testName.getMethodName()).substring(0, 31);
        caName = testName.getMethodName();
        caDn = "CN=" + caName;
        //Set up a SCEP alias
        ScepConfiguration scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.addAlias(scepAlias);
        scepConfiguration.initialize(scepAlias);
        scepConfiguration.setRAMode(scepAlias, true);
        scepConfiguration.setRADefaultCA(scepAlias, caName);
        scepConfiguration.setRANameGenerationScheme(scepAlias, "DN");
        scepConfiguration.setRANameGenerationParameters(scepAlias, "CN");
        scepConfiguration.setRAAuthpassword(scepAlias, "none");
        scepConfiguration.setRAEndEntityProfile(scepAlias, "EMPTY");
        scepConfiguration.setRACertProfile(scepAlias, "ENDUSER");
        scepConfiguration.setIncludeCA(scepAlias, true);
        scepConfiguration.setReturnCaChainInGetCaCert(scepAlias, true);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);

    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        ScepConfiguration scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.removeAlias(scepAlias);
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
    }

    /**
     * Test getting the encryption certificate of a root without key encipherment set
    
     */
    @Test
    public void testgetCaCertRootCaWithoutKeyEncipherment() throws CertificateProfileExistsException, AuthorizationDeniedException,
            CryptoTokenOfflineException, CAExistsException, InvalidAlgorithmException, MalformedURLException, URISyntaxException, ClientException {

        String certificateProfileName = testName.getMethodName() + "_CP";
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        certificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        certificateProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
        certificateProfile.setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
        certificateProfile.setKeyUsage(CertificateConstants.CRLSIGN, true);
        int certificateProfileId = certificateProfileSession.addCertificateProfile(admin, certificateProfileName, certificateProfile);

        //Set up the CA
        final X509CAInfo x509ca = JscepTestUtils.createTestX509RootCA(caName, caDn, "foo123".toCharArray(), "2048", certificateProfileId);

        try {
            //Set up jscep
            final CallbackHandler handler = new DefaultCallbackHandler(new OptimisticCertificateVerifier());
            final URL url = getUrl(scepAlias);
            Client client = new Client(url, handler);
            CertStore certStore = client.getCaCertificate();
            //Use jsceps default certstore inspector factory
            DefaultCertStoreInspectorFactory defaultCertStoreInspectorFactory = new DefaultCertStoreInspectorFactory();
            CertStoreInspector certStoreInspector = defaultCertStoreInspectorFactory.getInstance(certStore);
            assertEquals("The root certificate was not returned as a recipient", x509ca.getCertificateChain().get(0),
                    certStoreInspector.getRecipient());
        } finally {
            JscepTestUtils.removeCa(caName);
            certificateProfileSession.removeCertificateProfile(admin, certificateProfileName);
        }
    }

    /**
     * Same test as above (no KE keyUsage) but with a root and a subca.
     * 
     * This test is an oddity and proves a strange behavior in Android's SCEP client, in that using the default cert inspector the chosen recipient cert is chosen at random,
     * given a root and a sub which both lack the Key Encipherment Key Usage. 
     * 
     * 
     */
    @Test
    @Ignore //This test gives different results each time, and exists primarily to demonstrate some weirdness in jscep's default behavior
    public void testgetCaCertSubCaWithoutKeyEncipherment()
            throws CertificateProfileExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CAExistsException,
            InvalidAlgorithmException, MalformedURLException, URISyntaxException, ClientException, CADoesntExistsException {
        //Set up the Root CA
        final String rootCaName = caName + "_Root";
        final String rootCaDn = "CN=" + rootCaName;

        String rootCertificateProfileName = testName.getMethodName() + "_CP";
        CertificateProfile rootCertificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        rootCertificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        rootCertificateProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
        rootCertificateProfile.setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
        rootCertificateProfile.setKeyUsage(CertificateConstants.CRLSIGN, true);
        int rootCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, rootCertificateProfileName, rootCertificateProfile);

        //Set up the CA
        final X509CAInfo x509caRoot = JscepTestUtils.createTestX509RootCA(rootCaName, rootCaDn, "foo123".toCharArray(), "2048",
                rootCertificateProfileId);

        String subCertificateProfileName = testName.getMethodName() + "_CP_SUB";
        CertificateProfile subCertificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        subCertificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        subCertificateProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
        subCertificateProfile.setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
        subCertificateProfile.setKeyUsage(CertificateConstants.CRLSIGN, true);
        int subCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, subCertificateProfileName, subCertificateProfile);

        final X509CAInfo x509ca = JscepTestUtils.createTestX509CA(caName, caDn, "foo123".toCharArray(), x509caRoot.getCAId(), "2048",
                subCertificateProfileId);

        try {
            //Set up jscep
            final CallbackHandler handler = new DefaultCallbackHandler(new OptimisticCertificateVerifier());
            final URL url = getUrl(scepAlias);
            Client client = new Client(url, handler);
            
            
            CertStore certStore = client.getCaCertificate();
            //Use jsceps default certstore inspector factory
            DefaultCertStoreInspectorFactory defaultCertStoreInspectorFactory = new DefaultCertStoreInspectorFactory();
            CertStoreInspector certStoreInspector = defaultCertStoreInspectorFactory.getInstance(certStore);
            assertEquals("The sub ca certificate was not returned as a recipient", x509ca.getCertificateChain().get(0),
                    certStoreInspector.getRecipient());
        } finally {
            JscepTestUtils.removeCa(caName);
            JscepTestUtils.removeCa(rootCaName);
            certificateProfileSession.removeCertificateProfile(admin, rootCertificateProfileName);
            certificateProfileSession.removeCertificateProfile(admin, subCertificateProfileName);
        }
    }
    
    /**
     * Same test as above, but this time we give the sub ca cert the jscep's expected key usage
     * 
     * 
     */
    @Test
    public void testgetCaCertSubCaWithKeyEncipherment()
            throws CertificateProfileExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CAExistsException,
            InvalidAlgorithmException, MalformedURLException, URISyntaxException, ClientException, CADoesntExistsException {
        //Set up the Root CA
        final String rootCaName = caName + "_Root";
        final String rootCaDn = "CN=" + rootCaName;

        String rootCertificateProfileName = testName.getMethodName() + "_CP";
        CertificateProfile rootCertificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        rootCertificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, false);
        rootCertificateProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, true);
        rootCertificateProfile.setKeyUsage(CertificateConstants.KEYCERTSIGN, true);
        rootCertificateProfile.setKeyUsage(CertificateConstants.CRLSIGN, true);
        int rootCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, rootCertificateProfileName, rootCertificateProfile);

        //Set up the CA
        final X509CAInfo x509caRoot = JscepTestUtils.createTestX509RootCA(rootCaName, rootCaDn, "foo123".toCharArray(), "2048",
                rootCertificateProfileId);

        String subCertificateProfileName = testName.getMethodName() + "_CP_SUB";
        CertificateProfile subCertificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        /*
         * This is based on how the recipient is defined in DefaultCertStoreInspector in jscep. jscep (3.0) will not recognize a recipient/encryption
         * cert unless it has this exact key usage. 
         * 
         * boolean digitalSignature = false;
         * boolean nonRepudiation = false;
         * boolean keyEncipherment = true;
         * boolean dataEncipherment = false; 
         */
        subCertificateProfile.setKeyUsage(CertificateConstants.DIGITALSIGNATURE, false);
        subCertificateProfile.setKeyUsage(CertificateConstants.NONREPUDIATION, false);
        subCertificateProfile.setKeyUsage(CertificateConstants.KEYENCIPHERMENT, true);     
        subCertificateProfile.setKeyUsage(CertificateConstants.DATAENCIPHERMENT, false);
        int subCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, subCertificateProfileName, subCertificateProfile);

        final X509CAInfo x509ca = JscepTestUtils.createTestX509CA(caName, caDn, "foo123".toCharArray(), x509caRoot.getCAId(), "2048",
                subCertificateProfileId);

        try {
            //Set up jscep
            final CallbackHandler handler = new DefaultCallbackHandler(new OptimisticCertificateVerifier());
            final URL url = getUrl(scepAlias);
            Client client = new Client(url, handler);
            
            
            CertStore certStore = client.getCaCertificate();
            //Use jsceps default certstore inspector factory
            DefaultCertStoreInspectorFactory defaultCertStoreInspectorFactory = new DefaultCertStoreInspectorFactory();
            CertStoreInspector certStoreInspector = defaultCertStoreInspectorFactory.getInstance(certStore);
            assertEquals("The sub ca certificate was not returned as a recipient", x509ca.getCertificateChain().get(0),
                    certStoreInspector.getRecipient());
        } finally {
            JscepTestUtils.removeCa(caName);
            JscepTestUtils.removeCa(rootCaName);
            certificateProfileSession.removeCertificateProfile(admin, rootCertificateProfileName);
            certificateProfileSession.removeCertificateProfile(admin, subCertificateProfileName);
        }
    }

}
