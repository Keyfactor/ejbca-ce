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
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import javax.xml.ws.soap.SOAPFaultException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.CesecoreException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test of certificate extensions with values from WS.
 * 
 * @version $Id$
 */
public class CertificateExtensionTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(CertificateExtensionTest.class);
    private static final String WS_ADMIN_ROLENAME = "CertificateExtensionTest";	
    private static final String TEST_CERTIFICATE_PROFILE = "certExtensionTestCertificateProfile";
    private static final String TEST_USER = "certExtension";
    private static final String TEST_END_ENTITY_PROFILE = "certExtensionTestEndEntityProfile";
    private static final String sOID_one = "1.2.3.4";
    private static final String sOID_several = "1.2.3.5";
    private static final String sOID_wildcard = "1.2.*.4";
    private static final int nrOfValues = 3;
    private static final Random random = new Random();

    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private AvailableCustomCertificateExtensionsConfiguration cceConfigBackup;
    private static List<File> fileHandles = new ArrayList<File>();

    @BeforeClass
    public static void setupAccessRights() throws Exception{
        adminBeforeClass();
        fileHandles = setupAccessRights(WS_ADMIN_ROLENAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
        cleanUpAdmins(WS_ADMIN_ROLENAME);
    }

    @Before
    public void setUp() throws Exception {
        adminSetUpAdmin();
        cceConfigBackup = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfigBackup);
        certificateProfileSession.removeCertificateProfile(intAdmin, TEST_CERTIFICATE_PROFILE);
        endEntityProfileSession.removeEndEntityProfile(intAdmin, TEST_END_ENTITY_PROFILE);
        try {
            endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_USER, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {}
    }


    @Test
    public void getCertSuccess() throws Exception {
        populateCustomCertExtensions();
        addProfiles(2);
        
        final byte[] values[] = getRandomValues(nrOfValues);
        final byte[] value[] = getRandomValues(1);
        
        final List<ExtendedInformationWS> lei = new LinkedList<ExtendedInformationWS>();
        for(int i=0; i < values.length; i++ ) {
            final ExtendedInformationWS ei = new ExtendedInformationWS();
            ei.setName(sOID_several + ".value" + Integer.toString(i+1));
            ei.setValue(new String(Hex.encode((new DEROctetString(values[i])).getEncoded())));
            lei.add(ei);
        }
        if (value[0] != null && value[0].length > 0) {
            final ExtendedInformationWS ei = new ExtendedInformationWS();
            ei.setName(sOID_one);
            ei.setValue(new String(Hex.encode((new DEROctetString(value[0])).getEncoded())));
            lei.add(ei);
        }
        addUserWithExtensions(lei);
        
        X509Certificate cert = getCertificateWithExtension(true);
        
        checkExtension(value, cert.getExtensionValue(sOID_one), sOID_one);
        checkExtension(values, cert.getExtensionValue(sOID_several), sOID_several);

    }

    @Test
    public void getCertFail() throws Exception {
        populateCustomCertExtensions();
        addProfiles(2);
        
        final byte[] values[] = getRandomValues(nrOfValues);
        final byte[] value[] = new byte[1][0];
        
        final List<ExtendedInformationWS> lei = new LinkedList<ExtendedInformationWS>();
        for(int i=0; i < values.length; i++) {
            final ExtendedInformationWS ei = new ExtendedInformationWS();
            ei.setName(sOID_several + ".value" + Integer.toString(i+1));
            ei.setValue(new String(Hex.encode((new DEROctetString(values[i])).getEncoded())));
            lei.add(ei);
        }
        if (value[0]!=null && value[0].length > 0) {
            final ExtendedInformationWS ei = new ExtendedInformationWS();
            ei.setName(sOID_one);
            ei.setValue(new String( Hex.encode((new DEROctetString(value[0])).getEncoded())));
            lei.add(ei);
        }
        addUserWithExtensions(lei);
        getCertificateWithExtension(false);
    }

    @Test
    public void subjectAltNameExtensionTest() throws Exception {
        addProfiles(2);
        if (certificateProfileSession.getCertificateProfileId(TEST_CERTIFICATE_PROFILE) != 0) {
            certificateProfileSession.removeCertificateProfile(intAdmin, TEST_CERTIFICATE_PROFILE);
        }
        final int ctpid; 
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfile.setUseCertificateTransparencyInCerts(true);
        certificateProfileSession.addCertificateProfile(intAdmin, TEST_CERTIFICATE_PROFILE, certProfile);
        ctpid = certificateProfileSession.getCertificateProfileId(TEST_CERTIFICATE_PROFILE);
        if (endEntityProfileSession.getEndEntityProfile(TEST_END_ENTITY_PROFILE) != null) {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, TEST_END_ENTITY_PROFILE);
        }
        final EndEntityProfile endEntityprofile = new EndEntityProfile(true);
        endEntityprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(ctpid));
        endEntityProfileSession.addEndEntityProfile(intAdmin, TEST_END_ENTITY_PROFILE, endEntityprofile);
        final UserDataVOWS userData = new UserDataVOWS(TEST_USER, PASSWORD, true, "C=SE, CN=cert extension test",
                getAdminCAName(), "DNSName=(top.secret).domain.se", "foo@anatom.se", EndEntityConstants.STATUS_NEW,
                UserDataVOWS.TOKEN_TYPE_USERGENERATED, TEST_END_ENTITY_PROFILE, TEST_CERTIFICATE_PROFILE, null);
        ejbcaraws.editUser(userData);

        final X509Certificate cert = getMyCertificate();
        assertNotNull(cert);
        assertEquals("dNSName=top.secret.domain.se", CertTools.getSubjectAlternativeName(cert));  

        // Check that the number-of-redacted-lables-extension was added
        byte[] extValue = cert.getExtensionValue(CertTools.id_ct_redacted_domains);
        assertNotNull("Number of redacted labels (1.3.6.1.4.1.11129.2.4.6) didn't get added", extValue);

        // Check that the number-of-redacted-lables-extension has the write value
        DEROctetString octs = ((DEROctetString) DEROctetString.fromByteArray(extValue));
        ASN1Sequence seq = (ASN1Sequence) DERSequence.fromByteArray(octs.getOctets());
        assertEquals(1, seq.size());
        assertEquals("2", seq.getObjectAt(0).toString());    
    }

    @Test
    public void requestNonRequiredExtensionWithoutExtensionData() throws Exception {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        Properties props = new Properties();
        props.put("critical", "false");
        props.put("dynamic", "true");
        props.put("encoding", "DERIA5STRING");
        // Set extension to non-required
        cceConfig.addCustomCertExtension(1, sOID_one, "SingleExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, false, props);
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfig);
        addProfiles(1);
        // Request no extensions
        addUserWithExtensions(new LinkedList<ExtendedInformationWS>());
        // Expected to succeed
        getCertificateWithExtension(true);
    }
    
    @Test
    public void requestRequiredExtensionWithoutExtensionData() throws Exception {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        Properties props = new Properties();
        props.put("critical", "false");
        props.put("dynamic", "true");
        props.put("encoding", "DERIA5STRING");
        // Set extension to required
        cceConfig.addCustomCertExtension(1, sOID_one, "SingleExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props);
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfig);
        addProfiles(1);
        // Request no extensions
        addUserWithExtensions(new LinkedList<ExtendedInformationWS>());
        // Expected to fail
        getCertificateWithExtension(false);
    }
    
    
    @Test
    public void requestWildcardExtension() throws Exception {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        Properties props = new Properties();
        props.put("critical", "false");
        props.put("dynamic", "true");
        props.put("encoding", "RAW");
        // Create required wild card extension
        cceConfig.addCustomCertExtension(1, sOID_wildcard, "WildcardExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props);
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfig);
        addProfiles(1);
        // Request extension with OID matching wild card
        final List<ExtendedInformationWS> extensionRequestList = new LinkedList<>();
        final byte[] value[] = getRandomValues(1);
        extensionRequestList.add(new ExtendedInformationWS(sOID_one, new String(Hex.encode((new DEROctetString(value[0])).getEncoded()))));
        addUserWithExtensions(extensionRequestList);
        // Expect certificate issuance to succeed
        X509Certificate cert = getCertificateWithExtension(true);
        // Verify extension in certificate
        checkExtension(value, cert.getExtensionValue(sOID_one), sOID_one);
    }
    
    @Test
    public void requestUnmatchableExtensions() throws Exception {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        Properties props = new Properties();
        props.put("critical", "false");
        props.put("dynamic", "true");
        props.put("encoding", "DERIA5STRING");
        // Create required wild card extension
        cceConfig.addCustomCertExtension(1, sOID_one, "SingleExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props);
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfig);
        addProfiles(1);
        // Request two extensions, one matching and one not matching any configuration
        final List<ExtendedInformationWS> extensionRequestList = new LinkedList<>();
        extensionRequestList.add(new ExtendedInformationWS(sOID_one, "matching extension"));
        extensionRequestList.add(new ExtendedInformationWS(sOID_several, "unmatchable extension"));
        addUserWithExtensions(extensionRequestList);
        // Expect failure (issuance rejected)
        getCertificateWithExtension(false);
    }

    private void addProfiles(int numberOfCertificateExtensions) throws Exception {
        final int certProfId; 
        final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final List<Integer> usedCertificateExtensions = new LinkedList<Integer>();
        for (int i = 1; i <= numberOfCertificateExtensions; i++) {
            usedCertificateExtensions.add(i);
        }
        certProfile.setUsedCertificateExtensions(usedCertificateExtensions);
        certificateProfileSession.addCertificateProfile(intAdmin, TEST_CERTIFICATE_PROFILE, certProfile);
        certProfId = certificateProfileSession.getCertificateProfileId(TEST_CERTIFICATE_PROFILE);
        if ( endEntityProfileSession.getEndEntityProfile(TEST_END_ENTITY_PROFILE)!=null ) {
            endEntityProfileSession.removeEndEntityProfile(intAdmin, TEST_END_ENTITY_PROFILE);
        }
        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfId));
        endEntityProfileSession.addEndEntityProfile(intAdmin, TEST_END_ENTITY_PROFILE, endEntityProfile);
    }

    private X509Certificate getCertificateWithExtension(boolean isExpectedToWork) throws Exception {
        final X509Certificate cert = getMyCertificate();
        if (cert==null) {
            assertFalse("Certificate issuance was expected but failed", isExpectedToWork);
            return null;
        }
        assertTrue("Certificate issuance was expected to fail but didn't.", isExpectedToWork);
        return cert;
    }
    
    private void checkExtension(byte[] values[], byte extension[], String sOID) throws IOException {
        assertNotNull(extension);
        final byte octets[]; 
        {
            final ASN1Primitive asn1o = ASN1Primitive.fromByteArray(extension);
            assertNotNull(asn1o);
            log.info("The extension for the OID '"+sOID+"' of class '"+asn1o.getClass().getCanonicalName()+ "' is: "+asn1o);
            assertTrue(asn1o instanceof ASN1OctetString);
            octets = ((ASN1OctetString)asn1o).getOctets();
            if ( values.length==1 ) {
                assertArrayEquals( (new DEROctetString(values[0])).getEncoded(), octets);
                return;
            }
        }
        final ASN1Sequence seq; 
        {
            final ASN1Primitive asn1o = ASN1Primitive.fromByteArray(octets);
            log.info("The contents of the '"+sOID+"' can be decoded to a '"+asn1o.getClass().getCanonicalName()+ "' class.");
            assertTrue(asn1o instanceof ASN1Sequence);
            seq= (ASN1Sequence)asn1o;
        }
        assertEquals(values.length, seq.size());
        for ( int i=0; i < seq.size(); i++ ) {
            final ASN1Primitive derO = seq.getObjectAt(i).toASN1Primitive();
            assertTrue(derO instanceof ASN1OctetString);
            assertArrayEquals((new DEROctetString(values[i])).getEncoded(), ((ASN1OctetString)derO).getOctets());
        }
    }
    
    private byte[][] getRandomValues( int nr) {
        final byte values[][] = new byte[nr][400];
        for (int i=0; i < nr; i++) {
            random.nextBytes(values[i]);
        }
        return values;
    }
    
    private void addUserWithExtensions(final List<ExtendedInformationWS> extendedInformationWS) throws ApprovalException_Exception, 
            AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, UserDoesntFullfillEndEntityProfile_Exception, 
            WaitingForApprovalException_Exception {
        final UserDataVOWS userData = new UserDataVOWS(TEST_USER, PASSWORD, true, "C=SE, CN=cert extension test",
            getAdminCAName(), null, "foo@anatom.se", EndEntityConstants.STATUS_NEW,
            UserDataVOWS.TOKEN_TYPE_USERGENERATED, TEST_END_ENTITY_PROFILE, TEST_CERTIFICATE_PROFILE, null);
        userData.setExtendedInformation(extendedInformationWS);
        ejbcaraws.editUser(userData);
    }
    
    private X509Certificate getMyCertificate() throws GeneralSecurityException, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, 
            NotFoundException_Exception, CesecoreException_Exception, IOException, OperatorCreationException {
        final KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"), keys.getPublic(),
                new DERSet(), keys.getPrivate(), null);

        final CertificateResponse certenv;
        try {
            certenv = ejbcaraws.pkcs10Request(TEST_USER, PASSWORD, new String(Base64.encode(pkcs10.getEncoded())), null,
                    CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (EjbcaException_Exception e) {
            return null;
        } catch (SOAPFaultException e) {
            return null;
        }
        assertNotNull(certenv);
        assertTrue(certenv.getResponseType().equals(CertificateHelper.RESPONSETYPE_CERTIFICATE));
        return (X509Certificate) CertificateHelper.getCertificate(certenv.getData());
    }

    private void populateCustomCertExtensions() throws CertificateExtentionConfigurationException, AuthorizationDeniedException {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration(); 
        Properties props = new Properties();
        props.put("critical", "false");
        props.put("dynamic", "true");
        props.put("encoding", "RAW");
        cceConfig.addCustomCertExtension(1, sOID_one, "SingleExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props);
        props = new Properties();
        props.put("dynamic", "true");
        props.put("nvalues", Integer.toString(nrOfValues));
        props.put("encoding", "DEROCTETSTRING");
        cceConfig.addCustomCertExtension(2, sOID_several, "MultipleExtension", "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension", false, true, props);
        globalConfigurationSession.saveConfiguration(intAdmin, cceConfig);
    }

    @Override
    public String getRoleName() {
        return WS_ADMIN_ROLENAME+"Mgmt";
    }
}
