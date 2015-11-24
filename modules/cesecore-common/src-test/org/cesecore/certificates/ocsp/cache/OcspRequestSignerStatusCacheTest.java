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

import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.OcspConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test of the cache that hold revocation information for certificates that signs OCSP requests.
 * 
 * @version $Id$
 */
public class OcspRequestSignerStatusCacheTest {

    private String defaultConfigurationValue = null;
    
    @Before
    public void before() {
        OcspRequestSignerStatusCache.INSTANCE.flush();
        defaultConfigurationValue = ConfigurationHolder.getString(OcspConfiguration.REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME);
    }
    @After
    public void after() {
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME, defaultConfigurationValue);
    }

    @Test
    public void testLookupKeyGeneration() {
        final String key1 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        final String key2 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertEquals("Same input should have generated the same key.", key1, key2);
        final String key3 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("2"));
        assertFalse("Different input should not have generated the same key.", key1.equals(key3));
        final String key4 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test2", new BigInteger("1"));
        assertFalse("Different input should not have generated the same key.", key1.equals(key4));
    }

    @Test
    public void testCacheDisabled() throws Exception {
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME, "0");
        final String key1 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        assertNull("Cache entry should have been expired.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key1, CertificateStatus.OK);
        assertNull("Cache entry should have been expired.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key1, CertificateStatus.REVOKED);
        assertNull("Cache entry should have been expired.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
    }

    @Test
    public void testCacheExpired() throws Exception {
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME, "1000");
        final String key1 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        assertEquals("Cache should have returned non-expired entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
        Thread.sleep(1000);
        // First call should return null to signal to the caller that it should update the cache
        assertNull("Cache entry should have been expired.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        // Second call should return the stale data, since it assumed that the previous caller will update the cache
        assertEquals("Cache should have returned stale entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
    }

    @Test
    public void testCacheEnabled() throws Exception {
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME, "60000");
        final String key1 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test1", new BigInteger("1"));
        final String key2 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test2", new BigInteger("2"));
        final String key3 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test2", new BigInteger("3"));
        final String key4 = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey("CN=Test3", new BigInteger("1"));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key2));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key3));
        assertNull("Cache should be empty from start.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key4));
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key1, CertificateStatus.NOT_AVAILABLE);
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key2, CertificateStatus.OK);
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key3, CertificateStatus.REVOKED);
        OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(key4, CertificateStatus.OK);
        assertEquals("Cache should have returned non-expired entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1), CertificateStatus.NOT_AVAILABLE);
        assertEquals("Cache should have returned non-expired entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key2), CertificateStatus.OK);
        assertEquals("Cache should have returned non-expired entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key3), CertificateStatus.REVOKED);
        assertEquals("Cache should have returned non-expired entry.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key4), CertificateStatus.OK);
        OcspRequestSignerStatusCache.INSTANCE.flush();
        assertNull("Cache should be empty after flush.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key1));
        assertNull("Cache should be empty after flush.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key2));
        assertNull("Cache should be empty after flush.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key3));
        assertNull("Cache should be empty after flush.", OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(key4));
    }
}
