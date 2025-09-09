/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.ocsp.OcspRequestSignerStatusTestSessionRemote;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test of the cache that hold revocation information for certificates that signs OCSP requests.
 * 
 */
public class OcspRequestSignerStatusCacheSystemTest {

    private long defaultConfigurationValue = 60000L;
    private final EjbRemoteHelper ejbRemoteHelper = EjbRemoteHelper.INSTANCE;
   
    private final GlobalConfigurationSessionRemote globalConfigurationSession = ejbRemoteHelper.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final OcspRequestSignerStatusTestSessionRemote ocspRequesSignerStatusTestSession = ejbRemoteHelper.getRemoteSession(OcspRequestSignerStatusTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(OcspRequestSignerStatusCacheSystemTest.class.getName());

    
    @Before
    public void before() {
        ocspRequesSignerStatusTestSession.flush();
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        defaultConfigurationValue = globalOcspConfiguration.getRequestSignserRevocationStatusCacheTime();
    }
    @After
    public void after() throws AuthorizationDeniedException {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setRequestSignserRevocationStatusCacheTime(defaultConfigurationValue);
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, globalOcspConfiguration);
    }

    @Test
    public void testLookupKeyGeneration() {
        final String key1 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        final String key2 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertEquals("Same input should have generated the same key.", key1, key2);
        final String key3 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("2"));
        assertFalse("Different input should not have generated the same key.", key1.equals(key3));
        final String key4 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test2", new BigInteger("1"));
        assertFalse("Different input should not have generated the same key.", key1.equals(key4));
    }

    @Test
    public void testCacheDisabled() throws Exception {        
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setRequestSignserRevocationStatusCacheTime(0);
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, globalOcspConfiguration);
        
        final String key1 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        assertNull("Cache entry should have been expired.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key1, CertificateStatus.OK);
        assertNull("Cache entry should have been expired.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key1, CertificateStatus.REVOKED);
        assertNull("Cache entry should have been expired.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
    }

    @Test
    public void testCacheExpired() throws Exception {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setRequestSignserRevocationStatusCacheTime(1000);
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, globalOcspConfiguration);
        final String key1 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        assertEquals("Cache should have returned non-expired entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
        Thread.sleep(1000);
        // First call should return null to signal to the caller that it should update the cache
        assertNull("Cache entry should have been expired.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        // Second call should return the stale data, since it assumed that the previous caller will update the cache
        assertEquals("Cache should have returned stale entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
    }

    @Test
    public void testCacheEnabled() throws Exception {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setRequestSignserRevocationStatusCacheTime(60000);
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, globalOcspConfiguration);
        final String key1 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        final String key2 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test2", new BigInteger("2"));
        final String key3 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test2", new BigInteger("3"));
        final String key4 = ocspRequesSignerStatusTestSession.createCacheLookupKey("CN=Test3", new BigInteger("1"));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key2));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key3));
        assertNull("Cache should be empty from start.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key4));
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key2, CertificateStatus.OK);
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key3, CertificateStatus.REVOKED);
        ocspRequesSignerStatusTestSession.updateCachedCertificateStatus(key4, CertificateStatus.OK);
        assertEquals("Cache should have returned non-expired entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
        assertEquals("Cache should have returned non-expired entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key2), CertificateStatus.OK);
        assertEquals("Cache should have returned non-expired entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key3), CertificateStatus.REVOKED);
        assertEquals("Cache should have returned non-expired entry.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key4), CertificateStatus.OK);
        ocspRequesSignerStatusTestSession.flush();
        assertNull("Cache should be empty after flush.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key1));
        assertNull("Cache should be empty after flush.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key2));
        assertNull("Cache should be empty after flush.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key3));
        assertNull("Cache should be empty after flush.", ocspRequesSignerStatusTestSession.getCachedCertificateStatus(key4));
    }
}
