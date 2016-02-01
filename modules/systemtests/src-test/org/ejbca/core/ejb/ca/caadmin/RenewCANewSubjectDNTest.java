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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
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
        internalCertificateStoreSession.removeCRLs(internalAdmin, newSubjectDN);    //Make sure CRLs data are deleted where issuerDN=new Subject DN!!!
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        removeTestCA(newCAName);
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void testRenewNewSubjectDNNewKeys() throws Exception {
        log.trace(">testRenewNewSubjectDNNewKeys()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        byte[] orgkey = orgcert.getPublicKey().getEncoded();

        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/true, newSubjectDN);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        assertTrue("CA Info NameChanged field is not true after CA name-change renewal with same keys", newinfo2.getNameChanged());
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertFalse("Serial number hasn't changed for CA certificate after CA name-change renewal with new keys",
                orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        assertFalse("Subject DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(orgcert).equals(CertTools.getSubjectDN(newcertnewkeys)));
        assertFalse("Issuer DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(orgcert).equals(CertTools.getIssuerDN(newcertnewkeys)));
        assertFalse("AKI DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getAuthorityKeyId(newcertnewkeys), CertTools.getAuthorityKeyId(orgcert)));
        assertFalse("SKI DN hasn't changed for CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getSubjectKeyId(newcertnewkeys), CertTools.getSubjectKeyId(orgcert)));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse("Public Key hasn't changed for CA certificate after CA name-change renewal with new keys", Arrays.equals(orgkey, newkey));

        //Link certificate checks
        byte[] latestLinkCertificateRaw = caAdminSession.getLatestLinkCertificate(newinfo2.getCAId());
        assertTrue("There is no available link certificate after CA name-change renewal with new keys", latestLinkCertificateRaw != null);
        @SuppressWarnings("deprecation")
        X509Certificate latestLinkCertificate = (X509Certificate) CertTools.getCertfromByteArray(latestLinkCertificateRaw);
        assertFalse("Issuer DN and Subject DN are equal of CA link certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(latestLinkCertificate).equals(CertTools.getSubjectDN(latestLinkCertificate)));
        assertTrue("Issuer DN of CA link certificate is not equal to Subject DN of old CA certificate after CA name-change renewal with new keys",
                CertTools.getIssuerDN(latestLinkCertificate).equals(CertTools.getSubjectDN(orgcert)));
        assertTrue("Subject DN of CA link certificate is not equal to Subject DN of new CA certificate after CA name-change renewal with new keys",
                CertTools.getSubjectDN(latestLinkCertificate).equals(CertTools.getSubjectDN(newcertnewkeys)));
        assertTrue("AKI of CA link certificate is not equal to SKI of old CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getAuthorityKeyId(latestLinkCertificate), CertTools.getSubjectKeyId(orgcert)));
        assertTrue("SKI of CA link certificate is not equal to SKI of new CA certificate after CA name-change renewal with new keys",
                Arrays.equals(CertTools.getSubjectKeyId(latestLinkCertificate), CertTools.getSubjectKeyId(newcertnewkeys)));
        assertTrue("Link certificate doesn't have Name Change extension after CA name-change renewal with new keys",
                latestLinkCertificate.getExtensionValue(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover.getId()) != null);
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
        final int crlFullNumberBeforeRenaming = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), false);
        final int crlDeltaNumberBeforeRenaming = crlStoreSession.getLastCRLNumber(info.getSubjectDN(), true);
        caAdminSession.renewCANewSubjectDn(internalAdmin, info.getCAId(), /*regenerateKeys=*/true, /*customNotBefore=*/null,
                /*createLinkCertificates=*/false, newSubjectDN);
        final int crlFullNumberAfterRenaming = crlStoreSession.getLastCRLNumber(newSubjectDN, false);
        assertTrue("After CA Name Change, CA doesn't continue CRL numbering",
                crlFullNumberAfterRenaming == Math.max(crlFullNumberBeforeRenaming, crlDeltaNumberBeforeRenaming) + 1);
        
        //Make sure that CA that has gone through Name Change can issue CRLs with right numbering
        final int crlDeltaNumberAfterRenaming = crlStoreSession.getLastCRLNumber(newSubjectDN, true);
        X509CAInfo newinfo1 = (X509CAInfo) caSession.getCAInfo(internalAdmin, newCAName);
        boolean crlGenerated = publishingCrlSession.forceCRL(internalAdmin, newinfo1.getCAId());
        assertTrue("CRL are not generated for renewed CA after forceCRL operation", crlGenerated);
        final int crlFullNumberAfterForceCRL = crlStoreSession.getLastCRLNumber(newSubjectDN, false);
        assertTrue("Unexpected CRL number value " + crlFullNumberAfterForceCRL + " after forceCRL for renewed CA with new name. Should be " + (Math.max(crlFullNumberAfterRenaming, crlDeltaNumberAfterRenaming) + 1 + 1),
                crlFullNumberAfterForceCRL == Math.max(crlFullNumberAfterRenaming, crlDeltaNumberAfterRenaming) + 1);
        
        log.trace("<testFullCRLNumberingAfterRenewNewSubjectDN()");
    }
}
