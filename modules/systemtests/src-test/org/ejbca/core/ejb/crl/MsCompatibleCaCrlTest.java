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

package org.ejbca.core.ejb.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;

public class MsCompatibleCaCrlTest {

    private static final Logger log = Logger.getLogger(PartitionedCrlSystemTest.class);

    private static final String TEST_NAME = "MsCompatibleCaCrlTest";
    private static final String TEST_CA_NAME = TEST_NAME + "_CA";
    private static final String CA_DN = "CN=" + TEST_CA_NAME + ",OU=QA,O=TEST,C=SE";
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(TEST_NAME);

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateSessionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    
    private int caId;
    private int caTokenId;
    
    @Before
    public void beforeClass() throws Exception {
        CaTestCase.createTestCA(TEST_CA_NAME, 1024, CA_DN, CAInfo.SELFSIGNED, null);
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_CA_NAME);
        caId = caInfo.getCAId();
        caTokenId = caInfo.getCAToken().getCryptoTokenId();
        // Set common settings to all tests CA
        caInfo.setUseCRLNumber(true);
        caInfo.setMsCaCompatible(true);
        caAdminSession.editCA(admin, caInfo);
    }
    
    @After
    public void afterClass() throws Exception {
        log.trace(">afterClass");
        cleanupTestCase();
        log.trace("<afterClass");
    }
    
    @Test
    public void testPartitionCrlSettingsSetInMsCompatabilityMode() throws Exception {
        // Given (Renew CA, with new key pair and MS compatibility mode enabled)
        caAdminSession.renewCA(admin, caId, true, null, true);
        
        // Then (Partition CRLs should be enabled "under the hood")
        X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, caId);
        assertTrue("Partitioned CRLs was not enabled after re-keying MS compatible CA", 
                caInfo.getUsePartitionedCrl());
        assertEquals("Wrong number of CRL partitions set after MS Compatible CA re-keying", 
                1, caInfo.getCrlPartitions());
        assertEquals("Wrong number of suspended CRL partitions set after MS Compatible CA re-keying", 
                0, caInfo.getSuspendedCrlPartitions());
        
        // Another re-key (Should suspend active partition and open a new one)
        caAdminSession.renewCA(admin, caId, true, null, true);
        caInfo = (X509CAInfo) caSession.getCAInfo(admin, caId);
        assertEquals("Wrong number of CRL partitions set after MS Compatible CA re-keying", 
                2, caInfo.getCrlPartitions());
        assertEquals("Wrong number of suspended CRL partitions set after MS Compatible CA re-keying", 
                1, caInfo.getSuspendedCrlPartitions());
    }
    
    @Test
    public void testCrlPartitionShiftUponRekey() throws Exception {
        // Given (Renew CA, with new key pair, MS compatibility mode enabled and generate new CRL)
        caAdminSession.renewCA(admin, caId, true, null, true);
        publishingCrlSession.forceCRL(admin, caId);
        
        // Then (Initial CRL and CRL new CRL partition should exist)
        assertNotNull("Initial CRL not found after CA renewal", crlStoreSession.getCRL(CA_DN, -1, 1));
        assertNotNull("Initial CRL not recreated after CA renewal", crlStoreSession.getCRL(CA_DN, -1, 2));
        assertNotNull("CRL partition not created after CA renewal", crlStoreSession.getCRL(CA_DN, 1, 1));

    }
    
    @Test
    public void testDontPartitionSameCaKey() throws Exception {
        // Given (Renew the CA with existing key pair)
        final String currentCrlSignKey = caSession.getCAInfo(admin, caId).getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        caAdminSession.renewCA(admin, caId, currentCrlSignKey, null, true);
        publishingCrlSession.forceCRL(admin, caId);
        
        // Then (New CRL partition should not be created)
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, caId);
        assertNull("CRL partition created after CA renewal with same CRL sign key", crlStoreSession.getCRL(CA_DN, 1, 1));
        assertFalse("Partitioned CRLs was enabled after renewing MS compatible CA with the same CRL sign key", 
                caInfo.getUsePartitionedCrl());
        assertFalse("'Issuing Distribution Point on CRLs' was enabled after renewing MS compatible CA with the same CRL sign key", 
                caInfo.getUseCrlDistributionPointOnCrl());
        assertEquals("Wrong number of CRL partitions set after MS Compatible CA renewal", 
                0, caInfo.getCrlPartitions());
        assertEquals("Wrong number of suspended CRL partitions set after MS Compatible CA renewal", 
                0, caInfo.getSuspendedCrlPartitions());
    }
    
    @Test
    public void testSignCrlWithKeyCorrespondingToPartition() throws Exception {
        // Given (Renew CA twice, with new key pair, MS compatibility mode enabled and generate new CRLs)
        final String crlSignKeyAlias0 = caSession.getCAInfo(admin, caId).getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        caAdminSession.renewCA(admin, caId, true, null, true);
        final String crlSignKeyAlias1 = caSession.getCAInfo(admin, caId).getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        caAdminSession.renewCA(admin, caId, true, null, true);
        final String crlSignKeyAlias2 = caSession.getCAInfo(admin, caId).getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
        publishingCrlSession.forceCRL(admin, caId);
        
        // Then (We should now have 3 partitions, each containing a CRL, signed by different keys.)
        byte[] partitionedCrl0 = crlStoreSession.getCRL(CA_DN, -1, 1);
        byte[] partitionedCrl1 = crlStoreSession.getCRL(CA_DN, 1, 1);
        byte[] partitionedCrl2 = crlStoreSession.getCRL(CA_DN, 2, 1);
        
        final String crlAuthorityKeyId0 = new String(Hex.encode(CertTools.getAuthorityKeyId(CertTools.getCRLfromByteArray(partitionedCrl0))));
        final String crlAuthorityKeyId1 = new String(Hex.encode(CertTools.getAuthorityKeyId(CertTools.getCRLfromByteArray(partitionedCrl1))));
        final String crlAuthorityKeyId2 = new String(Hex.encode(CertTools.getAuthorityKeyId(CertTools.getCRLfromByteArray(partitionedCrl2))));
        
        
        // Expect
        // These two assertions aren't really relevant for this test. However, without them we may get false positives.
        assertNotEquals("CRL Sign key was not updated upon CA renewal", crlSignKeyAlias0, crlSignKeyAlias1);
        assertNotEquals("CRL Sign key was not updated upon CA renewal", crlSignKeyAlias1, crlSignKeyAlias2);
        // The CRL for each partition should have been signed with its corresponding crlSignKey
        assertEquals("CRL was not signed by the expected key", 
                cryptoTokenSession.getKeyPairInfo(admin, caTokenId, crlSignKeyAlias0).getSubjectKeyID(), crlAuthorityKeyId0);
        assertEquals("CRL was not signed by the expected key", 
                cryptoTokenSession.getKeyPairInfo(admin, caTokenId, crlSignKeyAlias1).getSubjectKeyID(), crlAuthorityKeyId1);
        assertEquals("CRL was not signed by the expected key", 
                cryptoTokenSession.getKeyPairInfo(admin, caTokenId, crlSignKeyAlias2).getSubjectKeyID(), crlAuthorityKeyId2);
    }
    
    
    private static void cleanupTestCase() throws AuthorizationDeniedException {
        CaTestCase.removeTestCA(TEST_CA_NAME);
        internalCertificateSessionSession.removeCertificatesBySubject(CA_DN);
        internalCertificateSessionSession.removeCRLs(admin, CA_DN);
    }
}
