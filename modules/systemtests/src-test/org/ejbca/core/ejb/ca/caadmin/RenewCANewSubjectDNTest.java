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

package org.ejbca.core.ejb.ca.caadmin;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CANameChangeRenewalException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.crl.PublishingCrlSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the Name Change CA Renewal {@link CAAdminSession.renewCANewSubjectDn}
 * 
 * @version $Id: RenewCANewSubjectDNTest.java 22638 2016-01-22 21:55:34Z marko $
 */
public class RenewCANewSubjectDNTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCANewSubjectDNTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RenewCATest"));
    private static boolean backupEnableIcaoCANameChangeValue = false;

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    private final String newSubjectDN = "CN=NewName";
    private final String newCAName = "NewName";
    private final String newSubjectDN2 = "CN=NewName2";
    private final String newCAName2 = "NewName2";
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        backupEnableIcaoCANameChangeValue = globalConfiguration.getEnableIcaoCANameChange();
        globalConfiguration.setEnableIcaoCANameChange(true);
        globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfiguration.setEnableIcaoCANameChange(backupEnableIcaoCANameChangeValue);
        globalConfigSession.saveConfiguration(internalAdmin, globalConfiguration);
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        removeTestCA(newCAName);
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN); // Make sure CRLs data are deleted where issuerDN=new Subject DN!!!
        removeTestCA(newCAName2);
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN2);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        removeTestCA(newCAName);
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN);
        removeTestCA(newCAName2);
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN2);
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void testRenewNewSubjectDNNewKeys() throws Exception {
        log.trace(">testRenewNewSubjectDNNewKeys()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate caCertificateBeforeRenewal1 = (X509Certificate) info.getCertificateChain().iterator().next();

        //Renewal 1
        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/true, newSubjectDN);
        X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        assertTrue("CA Info NameChanged field is not true after CA name-change renewal with same keys", newinfo.getNameChanged());
        X509Certificate caCertificateAfterRenewal1 = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertFalse("Serial number hasn't changed for CA certificate after CA name-change renewal with new keys",
                caCertificateBeforeRenewal1.getSerialNumber().equals(caCertificateAfterRenewal1.getSerialNumber()));
        assertFalse("Subject DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(caCertificateBeforeRenewal1).equals(CertTools.getSubjectDN(caCertificateAfterRenewal1)));
        assertFalse("Issuer DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(caCertificateBeforeRenewal1).equals(CertTools.getIssuerDN(caCertificateAfterRenewal1)));
        assertFalse("AKI DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getAuthorityKeyId(caCertificateAfterRenewal1), CertTools.getAuthorityKeyId(caCertificateBeforeRenewal1)));
        assertFalse("SKI DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getSubjectKeyId(caCertificateAfterRenewal1), CertTools.getSubjectKeyId(caCertificateBeforeRenewal1)));
        assertFalse("Public Key hasn't changed for CA certificate after CA name-change renewal with new keys", Arrays.equals(caCertificateBeforeRenewal1.getPublicKey().getEncoded(), caCertificateAfterRenewal1.getPublicKey().getEncoded()));

        //Link certificate checks
        byte[] linkCertificateAfterRenewal1Bytes = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
        assertTrue("There is no available link certificate after CA name-change renewal with new keys", linkCertificateAfterRenewal1Bytes != null);
        @SuppressWarnings("deprecation")
        X509Certificate linkCertificateAfterRenewal1 = (X509Certificate) CertTools.getCertfromByteArray(linkCertificateAfterRenewal1Bytes);
        assertFalse("Issuer DN and Subject DN are equal of CA link certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(linkCertificateAfterRenewal1).equals(CertTools.getSubjectDN(linkCertificateAfterRenewal1)));
        assertEquals("Issuer DN of CA link certificate is not equal to Subject DN of old CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(caCertificateBeforeRenewal1), CertTools.getIssuerDN(linkCertificateAfterRenewal1));
        assertEquals("Subject DN of CA link certificate is not equal to Subject DN of new CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(caCertificateAfterRenewal1), CertTools.getSubjectDN(linkCertificateAfterRenewal1));
        assertTrue("AKI of CA link certificate is not equal to SKI of old CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getAuthorityKeyId(linkCertificateAfterRenewal1), CertTools.getSubjectKeyId(caCertificateBeforeRenewal1)));
        assertTrue("SKI of CA link certificate is not equal to SKI of new CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getSubjectKeyId(linkCertificateAfterRenewal1), CertTools.getSubjectKeyId(caCertificateAfterRenewal1)));
        assertTrue("Link certificate doesn't have Name Change extension after CA name-change renewal with new keys",
                linkCertificateAfterRenewal1.getExtensionValue(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover.getId()) != null);

        //Renewal 2: Renew CA with name change again and check that the link certificate has been signed with previous CA (and not with the first one)
        caAdminSession.renewCANewSubjectDn(internalAdmin, newinfo.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/true, newSubjectDN2);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName2);
        X509Certificate caCertificateAfterRenewal2 = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        X509Certificate linkCertificateAfterRenewal2 = (X509Certificate) CertTools.getCertfromByteArray(caAdminSession.getLatestLinkCertificate(newinfo2.getCAId()));

        assertFalse("Issuer DN and Subject DN are equal of CA link certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(linkCertificateAfterRenewal2).equals(CertTools.getSubjectDN(linkCertificateAfterRenewal2)));
        assertEquals("Issuer DN of CA link certificate is not equal to Subject DN of old CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(caCertificateAfterRenewal1), CertTools.getIssuerDN(linkCertificateAfterRenewal2));
        assertEquals("Subject DN of CA link certificate is not equal to Subject DN of new CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(caCertificateAfterRenewal2), CertTools.getSubjectDN(linkCertificateAfterRenewal2));
        assertTrue("AKI of CA link certificate is not equal to SKI of old CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getAuthorityKeyId(linkCertificateAfterRenewal2), CertTools.getSubjectKeyId(caCertificateAfterRenewal1)));
        assertTrue("SKI of CA link certificate is not equal to SKI of new CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getSubjectKeyId(linkCertificateAfterRenewal2), CertTools.getSubjectKeyId(caCertificateAfterRenewal2)));
        assertTrue("Link certificate doesn't have Name Change extension after CA name-change renewal with new keys",
                linkCertificateAfterRenewal1.getExtensionValue(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover.getId()) != null);

        log.trace("<testRenewNewSubjectDNNewKeys()");
    }
    
    @Test
    public void testRenewNewSubjectDNSameKeys() throws Exception {
        log.trace(">testRenewNewSubjectDNSameKeys()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        byte[] orgkey = orgcert.getPublicKey().getEncoded();

        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/false, /*customNotBefore=*/null,
                /*createLinkCertificates=*/true, newSubjectDN);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        assertTrue("CA Info NameChanged field is not true after CA name-change renewal with same keys", newinfo2.getNameChanged());
        X509Certificate newcertsamekeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertFalse("Serial number hasn't changed for CA certificate after CA name-change renewal with same keys",
                orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        assertFalse("Subject DN hasn't changed for CA certificate after CA name-change renewal with same keys",
                CertTools.getSubjectDN(orgcert).equals(CertTools.getSubjectDN(newcertsamekeys)));
        assertFalse("Issuer DN hasn't changed for CA certificate after CA name-change renewal with same keys",
                CertTools.getIssuerDN(orgcert).equals(CertTools.getIssuerDN(newcertsamekeys)));
        assertTrue("AKI DN has changed for CA certificate after CA name-change renewal with same keys",
                Arrays.equals(CertTools.getAuthorityKeyId(newcertsamekeys), CertTools.getAuthorityKeyId(orgcert)));
        assertTrue("SKI DN has changed for CA certificate after CA name-change renewal with same keys",
                Arrays.equals(CertTools.getSubjectKeyId(newcertsamekeys), CertTools.getSubjectKeyId(orgcert)));
        byte[] newkey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue("Public Key has changed for CA certificate after CA name-change renewal with same keys", Arrays.equals(orgkey, newkey));

        //Link certificate checks
        byte[] latestLinkCertificateRaw = caAdminSession.getLatestLinkCertificate(newinfo2.getCAId());
        assertTrue("There is no available link certificate after CA name-change renewal with same keys", latestLinkCertificateRaw != null);
        @SuppressWarnings("deprecation")
        X509Certificate latestLinkCertificate = (X509Certificate) CertTools.getCertfromByteArray(latestLinkCertificateRaw);
        assertFalse("Issuer DN and Subject DN are equal of CA link certificate after CA name-change renewal with same keys",
                CertTools.getIssuerDN(latestLinkCertificate).equals(CertTools.getSubjectDN(latestLinkCertificate)));
        assertTrue("Issuer DN of CA link certificate is not equal to Subject DN of old CA certificate after CA name-change renewal with same keys",
                CertTools.getIssuerDN(latestLinkCertificate).equals(CertTools.getSubjectDN(orgcert)));
        assertTrue("Subject DN of CA link certificate is not equal to Subject DN of new CA certificate after CA name-change renewal with same keys",
                CertTools.getSubjectDN(latestLinkCertificate).equals(CertTools.getSubjectDN(newcertsamekeys)));
        assertTrue("AKI of CA link certificate is not equal to SKI of old CA certificate after CA name-change renewal with same keys",
                Arrays.equals(CertTools.getAuthorityKeyId(latestLinkCertificate), CertTools.getSubjectKeyId(orgcert)));
        assertTrue("SKI of CA link certificate is not equal to SKI of new CA certificate after CA name-change renewal with same keys",
                Arrays.equals(CertTools.getSubjectKeyId(latestLinkCertificate), CertTools.getSubjectKeyId(newcertsamekeys)));
        assertTrue("Link certificate doesn't have Name Change extension after CA name-change renewal with same keys",
                latestLinkCertificate.getExtensionValue(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover.getId()) != null);

        log.trace("<testRenewNewSubjectDNSameKeys()");
    }
    
    /** CAInfo NameChanged field MUST be false if the CA hasn't gone through Name Change*/
    @Test
    public void testCANameChangedField() throws Exception {
        log.trace(">testCAInfoNameChangedField()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        
        caAdminSession.renewCA(internalAdmin, info.getCAId(), /*regenerateKeys=*/false, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false);
        X509CAInfo newinfo1 = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        assertFalse("CA Info NameChanged field is true after CA renewal (No Name Change process)", newinfo1.getNameChanged());

        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/false, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false, newSubjectDN);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        assertTrue("CA Info NameChanged field is false after CA Name Change Renewal", newinfo2.getNameChanged());

        log.trace("<testCAInfoNameChangedField()");
    }

 
    @Test
    public void testFullCRLNumberingAfterRenewNewSubjectDN() throws Exception {
        log.trace(">testFullCRLNumberingAfterRenewNewSubjectDN()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        
        //Make sure that CA that has gone through Name Change continue CRL numbering
        // Using full CRLs should be the use case that is the most common when doing CA Name Change, so make sure full crl number is the latest
        publishingCrlSession.forceCRL(internalAdmin, info.getCAId());
        int crlFullNumberBeforeRenaming = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), false);
        final int crlDeltaNumberBeforeRenaming = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), true);        
        if (crlFullNumberBeforeRenaming <= 1 && crlDeltaNumberBeforeRenaming <= 1) {
            // If only an initial CRL was generated, force another one so we have CRL number > 1
            publishingCrlSession.forceCRL(internalAdmin, info.getCAId());
            int newNumber = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), false);
            assertTrue("After CRL generation, full CRL number did not increase",
                    newNumber == Math.max(crlFullNumberBeforeRenaming, crlDeltaNumberBeforeRenaming) + 1);
            crlFullNumberBeforeRenaming = newNumber;
        }
        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false, newSubjectDN);
        final int crlFullNumberAfterRenaming = crlStoreSession.getLastCRLNumber(newSubjectDN, false);
        assertEquals("After CA Name Change, CA doesn't continue CRL numbering",
                Math.max(crlFullNumberBeforeRenaming, crlDeltaNumberBeforeRenaming) + 1, crlFullNumberAfterRenaming);
        
        //Make sure that CA that has gone through Name Change can issue CRLs with right numbering
        final int crlDeltaNumberAfterRenaming = crlStoreSession.getLastCRLNumber(newSubjectDN, true);
        X509CAInfo newinfo1 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        boolean crlGenerated = publishingCrlSession.forceCRL(internalAdmin, newinfo1.getCAId());
        assertTrue("CRL are not generated for renewed CA after forceCRL operation", crlGenerated);
        final int crlFullNumberAfterForceCRL = crlStoreSession.getLastCRLNumber(newSubjectDN, false);
        assertEquals("Unexpected CRL number value " + crlFullNumberAfterForceCRL + " after forceCRL for renewed CA with new name. Should be " + (Math.max(crlFullNumberAfterRenaming, crlDeltaNumberAfterRenaming) + 1 + 1),
                Math.max(crlFullNumberAfterRenaming, crlDeltaNumberAfterRenaming) + 1, crlFullNumberAfterForceCRL);
        
        // Do the same but when deltaCRLNumber is the latest
        // Clean up first
        publishingCrlSession.forceDeltaCRL(internalAdmin, info.getCAId());
        int crlFullNumberBeforeRenaming2 = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), false);
        final int crlDeltaNumberBeforeRenaming2 = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), true);
        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false, newSubjectDN2);
        final int crlFullNumberAfterRenaming2 = crlStoreSession.getLastCRLNumber(newSubjectDN2, false);
        assertEquals("After CA Name Change, CA doesn't continue CRL numbering",
                Math.max(crlFullNumberBeforeRenaming2, crlDeltaNumberBeforeRenaming2) + 1, crlFullNumberAfterRenaming2);

        log.trace("<testFullCRLNumberingAfterRenewNewSubjectDN()");
    }
    
    @Test
    public void testNewCANameNotSameAsCurrent() throws Exception{
        log.trace(">testNewCANotSameAsCurrent()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");

        try {
            caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/false, /*customNotBefore=*/null,
                    /*createLinkCertificates=*/true, "CN=TEST");
            fail("CANameChangeRenewalException is not thrown for CA-new-name-same-as-current error");
        } catch (CANameChangeRenewalException e) {
            //Good
        } catch (Exception e){
            fail("The exception " + e.getMessage() + " is thrown instead of the CANameChangeRenewalException for CA-new-name-same-as-current error");
        }
        
        log.trace("<testNewCANotSameAsCurrent()");
    }
    
    @Test
    public void testNewCANameDoesNotExist() throws Exception{
        log.trace(">testNewCANameDoesNotExist()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");

        String cAName = "testNewCANameDoesNotExist";
        createTestCA(cAName);
        try {
            caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/false, /*customNotBefore=*/null,
                    /*createLinkCertificates=*/true, "CN=testNewCANameDoesNotExist");
            fail("CANameChangeRenewalException is not thrown for CA-new-name-already-exists error");
        } catch (CANameChangeRenewalException e) {
            //Good
        } catch (Exception e){
            fail("The exception " + e.getMessage() + " is thrown instead of the CANameChangeRenewalException for CA-new-name-already-exists error");
        } finally {
            removeTestCA(cAName);
        }
        
        log.trace("<testNewCANameDoesNotExist()");
    }
}
