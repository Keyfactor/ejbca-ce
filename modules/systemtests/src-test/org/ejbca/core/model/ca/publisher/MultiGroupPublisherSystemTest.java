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
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.mock.publisher.MockedThrowAwayRevocationPublisher;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests that the interaction between MultiGroupPublisher and the publisher queue works.
 *
 * @version $Id$
 */
public class MultiGroupPublisherSystemTest {

    private static final Logger log = Logger.getLogger(MultiGroupPublisherSystemTest.class);

    private static final String MGP_PUBLISHER_NAME = "MultiGroupPublisherSystemTest_MultiGroupPublisher";
    private static final String LDAP_PUBLISHER1_NAME = "MultiGroupPublisherSystemTest_LdapPublisher1";
    private static final String LDAP_PUBLISHER2_NAME = "MultiGroupPublisherSystemTest_LdapPublisher2";
    private static final String CUSTOM_PUBLISHER1_NAME = "MultiGroupPublisherSystemTest_CustomPublisher1";
    private static final String CERT_PROFILE_NAME = "MultiGroupPublisherSystemTest_CertProfile";
    private static final String CA_NAME = "MultiGroupPublisherSystemTest_CA";
    private static final String CA_DN = "CN=MultiGroupPublisherSystemTest_Test,O=Test";
    private static final String ENDENTITY_PROFILE_NAME = "MultiGroupPublisherSystemTest_EEP";
    private static final String USER_NAME = "MultiGroupPublisherSystemTest_User";
    private static final String USER_DN = "CN=MultiGroupPublisherSystemTest_User,O=Test";

    /*
        Corresponding private key is:
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDqq+4CNSFplxu3
        MrSzY06S3heosO/mmeDQ63oeWzak7S5+RAfqlg607TrrIkw+UZRf/s7T53U1QpT9
        sQU81dxosESW2IcX4spSAwS3lUYYMuKqVG9P0WiEFFTpY+6P8Fs5Wu16T2nJx2Mq
        SqaekucglU+DKQa85agZ4GAkrHTB2fkDD/sa4vv0BjpLyjy0dIHuH9z8RDBJd4Cb
        fobxWnC/JnFLzKEHJKXso30vGLFB/hx/M3XTni2l6FG7lbZRE6FvPz8KPuUuSBdV
        hRBgDPGMK9Wd8p3winw0ME96BxHT2IRUCLM2KQSZok2WIWWeMpfD0cIpMcHyto8c
        OOMYg/ABAgMBAAECggEBANuYvaVFMJoNdDsPcPb489sNhxgtUqD4197Iq8LiWhUl
        eb9gTAQiHWsDH4JO2wfp8S2PVN4Ilq6bOq7XSu5ttc4lPFnoDyqz592sw2pDfo9A
        dskrL+qCLAqEuByajfAV3FekldtBmt3d/hbiOl7jWvMrpXc4Gf0D7zUfuPg4hR2r
        39GIjTmdUml1e5SgwYxWgGqbJ6nHcxFgVnJjjK4SPPiX7QQHjhTLzCj3okJATSvr
        KDYrd0XOLgrSzhWetOBim5GzCibEgR5bDvDzrdjCV/dFftIOznnBiOb9wyqVcC21
        HLhTy0zclJZSuYsvUkctl55x2ZNy6ItEzBdyPRBS2QECgYEA92MnWYd17GLQBsOC
        OuoobLGHt0nuQ+pVn0sQoF7/wEo/ce59Q0WZw1cehaCID8aWSB4KvtjyxjHm1T1+
        eOUUbCotqIGAkPBZNRFhOoGK2fo9mk4lknDWFvO+b1ju2Qjs0PZqLpCI30RZswfY
        gjbVED+VxwDtoS06RPuW8UOD77ECgYEA8tdyYrFf6VkM8A/c0URq3IYLL9cunkuf
        up+SGaz0GbWSWyEYzp3F6AUhNBO3QibRyVQj/vO77DFvGt6bTkX3c8zZZufbep8W
        CbfFWZjc1Lgy9SwNraDGFnrLkromCjgJbsZ0qd78WMyNOfDkQnbKQ3ZJLiZbPt0Q
        oKb6cmyt6VECgYEArV4nbW6pDYgSEStiULdYrROc8K429BF8/60zcbAhuzhNTiK8
        VjComWSsVykxMR0SpGepUCXpvUurYTU/NKoVrdfBN53J48kMO0x6vu2ZyTi9gy3Q
        1teMsXkPtCi2+hJvI+IMd6WCxjS4R+bvrBGRL1ngNR5JafKwKzfFiD6wb4ECgYEA
        ooEqOoEX/b9puPvkeOWf3RKWSd1lhOh2axx9WFE0yD+JQRJU128dELbeEUtgRxRT
        Lrbvn5zbFKPABesRYr/PZ96dXQ+q/9OVm8sudVal8HOTJh3kyVvdMw3ZTMbkzdHR
        /h8v0r01gPbhSvS4ywFTOPHe5tMkHF0y007qKcgwWQECgYB0u68vS7j0HwcLOf6d
        BK7z/J0BqfN55zvQ5enf+TkTRyhQ5AiVNylpiEaZmga8+cwQ0fchSP8wd6pniOrz
        I3+LrVbTNlCB44W0rKk2AOJZ9jGOlsFsB9mIfWJ8HX+CejrKKVmAMT7kyPFCeeaZ
        G0Y1+MpCq1/shzjDtSD0qWX8Dg==
        -----END PRIVATE KEY-----
     */
    private static final String USER_PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n" + 
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6qvuAjUhaZcbtzK0s2NO\n" + 
            "kt4XqLDv5png0Ot6Hls2pO0ufkQH6pYOtO066yJMPlGUX/7O0+d1NUKU/bEFPNXc\n" + 
            "aLBEltiHF+LKUgMEt5VGGDLiqlRvT9FohBRU6WPuj/BbOVrtek9pycdjKkqmnpLn\n" + 
            "IJVPgykGvOWoGeBgJKx0wdn5Aw/7GuL79AY6S8o8tHSB7h/c/EQwSXeAm36G8Vpw\n" + 
            "vyZxS8yhBySl7KN9LxixQf4cfzN1054tpehRu5W2UROhbz8/Cj7lLkgXVYUQYAzx\n" + 
            "jCvVnfKd8Ip8NDBPegcR09iEVAizNikEmaJNliFlnjKXw9HCKTHB8raPHDjjGIPw\n" + 
            "AQIDAQAB\n" + 
            "-----END PUBLIC KEY-----\n";

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken("MultiGroupPublisherSystemTest");
    private static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private static PublisherQueueProxySessionRemote publisherQueueProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);


    private static int publisherA1Id;
    private static int publisherA2Id;
    private static int publisherB1Id;
    private static int multiGroupPublisherId; 
    private static int certiciateProfileId;
    private static int endEntityProfileId;

    /**
     * Sets up a MultiGroupPublisher that has two publisher groups:
     *   group 1: two LDAP publishers, using queue
     *   group 2: one custom publisher, using queue
     *  And a certificate profile and CA using this publisher.
     */
    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass");
        CryptoProviderTools.installBCProviderIfNotAvailable();
        cleanup();

        // we will just test that the queue works for the LdapPublishers and CustomPublisher
        log.debug("Creating LDAP publishers");
        final LdapPublisher publisherA1 = new LdapPublisher();
        publisherA1.setDescription("Test LDAP Publisher");
        publisherA1.setUseQueueForCertificates(true);
        publisherA1.setUseQueueForCRLs(true);
        publisherA1.setOnlyUseQueue(true);
        publisherA1.setKeepPublishedInQueue(true);
        publisherA1Id = publisherSession.addPublisher(alwaysAllowToken, LDAP_PUBLISHER1_NAME, publisherA1);
        publisherA2Id = publisherSession.addPublisher(alwaysAllowToken, LDAP_PUBLISHER2_NAME, (BasePublisher) publisherA1.clone());

        log.debug("Creating Custom publisher");
        final CustomPublisherContainer publisherB1 = new CustomPublisherContainer();
        publisherB1.setDescription("Test Custom Publisher");
        publisherB1.setUseQueueForCertificates(true);
        publisherB1.setUseQueueForCRLs(true);
        publisherB1.setOnlyUseQueue(true);
        publisherB1.setKeepPublishedInQueue(true);
        publisherB1.setClassPath(MockedThrowAwayRevocationPublisher.class.getName());
        publisherB1Id = publisherSession.addPublisher(alwaysAllowToken, CUSTOM_PUBLISHER1_NAME, publisherB1);

        log.debug("Creating Multi Group Publisher");
        final MultiGroupPublisher multiGroupPublisher = MultiGroupPublisherBuilder
                .builder()
                .withAllFlagsToFalse()
                .description("Test Multi Group Publisher")
                .addPublisherGroup(Arrays.asList(publisherA1Id, publisherA2Id))
                .addPublisherGroup(Collections.singleton(publisherB1Id))
                .build();
        multiGroupPublisherId = publisherSession.addPublisher(alwaysAllowToken, MGP_PUBLISHER_NAME, multiGroupPublisher);
        log.debug("Created multi group publisher with ID " + multiGroupPublisherId);

        log.debug("Creating Certificate Profile");
        final CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProf.setPublisherList(Collections.singletonList(multiGroupPublisherId));
        certiciateProfileId = certificateProfileSession.addCertificateProfile(alwaysAllowToken, CERT_PROFILE_NAME, certProf);

        log.debug("Creating CA");
        final X509CA ca = CaTestUtils.createX509Ca(alwaysAllowToken, CA_NAME, CA_NAME, CA_DN);
        final CAInfo cainfo = ca.getCAInfo();
        cainfo.setCertificateProfileId(certiciateProfileId);
        caSession.editCA(alwaysAllowToken, cainfo);

        log.debug("Creating End Entity Profile");
        final EndEntityProfile eeProf = new EndEntityProfile();
        eeProf.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        eeProf.setAvailableCAs(Collections.singletonList(ca.getCAId()));
        eeProf.setAvailableCertificateProfileIds(Collections.singletonList(certiciateProfileId));
        eeProf.addField(DnComponents.ORGANIZATION);
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(alwaysAllowToken, ENDENTITY_PROFILE_NAME, eeProf);
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        log.trace(">afterClass");
        cleanup();
        log.trace("<afterClass");
    }

    /**
     * Tests publishing to a MultiGroupPublisher that has been set up in {@link #beforeClass}
     */
    @Test
    public void publishMultiGroup() throws Exception {
        try {
            // Issue a cert, which should cause publishing to happen
            final EndEntityInformation userdata = new EndEntityInformation();
            userdata.setUsername(USER_NAME);
            userdata.setDN(USER_DN);
            userdata.setPassword("foo123");
            userdata.setEndEntityProfileId(endEntityProfileId);
            userdata.setCertificateProfileId(certiciateProfileId);
            userdata.setCAId(CertTools.stringToBCDNString(CA_DN).hashCode());
            userdata.setTokenType(EndEntityConstants.TOKEN_USERGEN);
            userdata.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            final ExtendedInformation extendedinformation = new ExtendedInformation();
            extendedinformation.setMaxLoginAttempts(2);
            userdata.setExtendedInformation(extendedinformation);
            endEntityManagementSession.addUser(alwaysAllowToken, userdata, true);
            byte[] pubKeyBytes = KeyTools.getBytesFromPEM(USER_PUBLIC_KEY_PEM, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
            final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(pubKeyBytes);
            final PublicKeyWrapper pubKeyWrapper = new PublicKeyWrapper(pubKey);
            final Certificate cert = signSession.createCertificate(alwaysAllowToken, USER_NAME, "foo123", pubKeyWrapper);

            // Check the publisher queue
            // - LDAP 1 and LDAP 2 make up a group, and a random one of them should receive a queue entry.
            // - Custom Publisher B1 make up a group on it's own, and should always receive an entry.
            assertEquals("Multi Group Publisher should not have any entries in queue.", 0, publisherQueueProxySession.getPendingEntriesCountForPublisher(multiGroupPublisherId));
            final Collection<PublisherQueueData> entriesA1 = publisherQueueProxySession.getPendingEntriesForPublisher(publisherA1Id);
            final Collection<PublisherQueueData> entriesA2 = publisherQueueProxySession.getPendingEntriesForPublisher(publisherA2Id);
            assertTrue("Extranous / left over queue entries for " + LDAP_PUBLISHER1_NAME, entriesA1.size() <= 1);
            assertTrue("Extranous / left over queue entries for " + LDAP_PUBLISHER2_NAME, entriesA2.size() <= 1);
            assertEquals("Exactly one of the LDAP publishers should receive an entry in its queue.",
                    1, entriesA1.size() + entriesA2.size());
            final Collection<PublisherQueueData> entriesB1 = publisherQueueProxySession.getPendingEntriesForPublisher(publisherB1Id);
            assertEquals("Custom Publisher should always", 1,  entriesB1.size());

            // Check contents of queue data for LDAP publisher
            final String expectedFingerprint = CertTools.getFingerprintAsString(cert);
            final PublisherQueueData entryA = (entriesA1.isEmpty() ? entriesA2.iterator().next() : entriesA1.iterator().next());
            assertTrue("pulisherId is wrong", entryA.getPublisherId() == publisherA1Id || entryA.getPublisherId() == publisherA2Id);
            checkQueueData(entryA, expectedFingerprint);
            // Check contents of queue data for custom publisher
            final PublisherQueueData entryB = entriesB1.iterator().next();
            assertEquals("pulisherId is wrong", publisherB1Id, entryB.getPublisherId());
            checkQueueData(entryB, expectedFingerprint);
        } finally {
            cleanupEndEntity();
            final Collection<PublisherQueueData> toClean = new ArrayList<>();
            toClean.addAll(publisherQueueProxySession.getPendingEntriesForPublisher(publisherA1Id));
            toClean.addAll(publisherQueueProxySession.getPendingEntriesForPublisher(publisherA2Id));
            toClean.addAll(publisherQueueProxySession.getPendingEntriesForPublisher(publisherB1Id));
            for (final PublisherQueueData queueData : toClean) {
                publisherQueueProxySession.removeQueueData(queueData.getPk());
            }
        }
    }
    
    /**
     * Does a check of all columns except pk (primary key) and publisherId
     * @param entry Database row the check.
     * @param expectedFingerprint Fingerprint to check for.
     */
    private void checkQueueData(final PublisherQueueData entry, final String expectedFingerprint) {
        assertEquals("fingerprint is wrong",  expectedFingerprint, entry.getFingerprint());
        assertEquals("publishStatus is wrong", PublisherConst.STATUS_PENDING, entry.getPublishStatus());
        assertEquals("publishType is wrong", PublisherConst.PUBLISH_TYPE_CERT, entry.getPublishType());
        assertEquals("tryCounter is wrong", 0, entry.getTryCounter());
        assertTrue("timeCreated is suspiciously early", entry.getTimeCreated().after(new Date(System.currentTimeMillis() - 3*60*1000)));
        assertTrue("timeCreated is in the future", entry.getTimeCreated().before(new Date(System.currentTimeMillis()+1)));
        assertEquals("lastUpdate is wrong", new Date(0), entry.getLastUpdate());
        final PublisherQueueVolatileInformation volatileData = entry.getVolatileData();        
        assertNotNull("volatileData should not be null", volatileData);
        assertEquals("wrong username in volatileData", USER_NAME, volatileData.getUsername());
        assertEquals("wrong user DN in volatileData", USER_DN, volatileData.getUserDN());
        assertEquals("wrong password in volatileData", "foo123", volatileData.getPassword());
        final ExtendedInformation extendedinformation = volatileData.getExtendedInformation();
        assertEquals("wrong extendedinformation.getMaxLoginAttempts() in volatileData", 2, extendedinformation.getMaxLoginAttempts());
    }

    /**
     * Tests that you can't remove a publisher that's referenced by a multi group publisher
     */
    @Test
    public void disallowedRemoval() {
        try {
            publisherSession.removePublisher(alwaysAllowToken, LDAP_PUBLISHER1_NAME);
            fail("Should throw when trying to delete publisher that is in use by a multi group publisher");
        } catch (AuthorizationDeniedException e) {
            assertTrue("Exception message say that the publisher is in use by " + MGP_PUBLISHER_NAME + ". Message was: " + e.getMessage(), e.getMessage().contains("publisher '" + MGP_PUBLISHER_NAME + "'"));
        }
    }

    private static void cleanup() throws AuthorizationDeniedException {
        log.debug("Cleaning up");
        cleanupEndEntity();
        internalCertificateStoreSession.removeCertificatesBySubject(CA_DN);
        endEntityProfileSession.removeEndEntityProfile(alwaysAllowToken, ENDENTITY_PROFILE_NAME);
        CaTestUtils.removeCa(alwaysAllowToken, CA_NAME, CA_NAME);
        certificateProfileSession.removeCertificateProfile(alwaysAllowToken, CERT_PROFILE_NAME);
        publisherSession.removePublisher(alwaysAllowToken, MGP_PUBLISHER_NAME);
        publisherSession.removePublisher(alwaysAllowToken, LDAP_PUBLISHER1_NAME);
        publisherSession.removePublisher(alwaysAllowToken, LDAP_PUBLISHER2_NAME);
        publisherSession.removePublisher(alwaysAllowToken, CUSTOM_PUBLISHER1_NAME);
    }
    
    private static void cleanupEndEntity() throws AuthorizationDeniedException {
        internalCertificateStoreSession.removeCertificatesBySubject(USER_DN);
        try {
            endEntityManagementSession.deleteUser(alwaysAllowToken, USER_NAME);
        } catch (NoSuchEndEntityException e) {
            // NOPMD ignored
        } catch (CouldNotRemoveEndEntityException e) {
            log.warn("Could not delete user: " + e, e);
        }
    }

    
}
