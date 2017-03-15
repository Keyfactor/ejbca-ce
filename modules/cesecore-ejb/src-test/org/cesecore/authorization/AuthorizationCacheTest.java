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
package org.cesecore.authorization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationCache.AuthorizationCacheCallback;
import org.junit.Test;

/**
 * Test of the AuthorizationCache.
 * 
 * @version $Id$
 */
public class AuthorizationCacheTest {

    private static final Logger log = Logger.getLogger(AuthorizationCacheTest.class);
    
    @Test
    public void testBasicOperations() throws InterruptedException, AuthenticationFailedException {
        log.trace(">testBasicOperations");
        AuthorizationCache.INSTANCE.reset();
        final AtomicInteger updateNumber = new AtomicInteger(0);
        final AtomicLong keepUnusedEntriesFor = new AtomicLong(3600000L);
        final HashMap<String, Boolean> accessRules1 = new HashMap<>();
        accessRules1.put("/rule1", Boolean.TRUE);
        final AuthenticationToken at1 = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthorizationCacheTest1"));
        final AuthorizationCacheCallback callback = new AuthorizationCacheCallback() {
            @Override
            public HashMap<String, Boolean> loadAccessRules(AuthenticationToken authenticationToken) {
                if (at1==authenticationToken) {
                    return accessRules1;
                }
                return null;
            }
            @Override
            public int getUpdateNumber() {
                return updateNumber.get();
            }
            @Override
            public long getKeepUnusedEntriesFor() {
                return keepUnusedEntriesFor.get();
            }
        };
        // The callback should only populate the cache for one of the tokens
        assertNotNull(AuthorizationCache.INSTANCE.get(at1, callback));
        assertEquals(1, AuthorizationCache.INSTANCE.get(at1, callback).size());
        assertNotNull(AuthorizationCache.INSTANCE.get(null, callback));
        assertEquals(0, AuthorizationCache.INSTANCE.get(null, callback).size());
        assertNotNull(AuthorizationCache.INSTANCE.get(at1, null));
        assertEquals(0, AuthorizationCache.INSTANCE.get(at1, null).size());
        // From a caching perspective all AlwaysAllowLocalAuthenticationToken are the same and the cached object should be returned
        final AuthenticationToken at2 = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthorizationCacheTest2"));
        final AuthorizationCacheCallback callbackEmpty = new AuthorizationCacheCallback() {
            @Override
            public HashMap<String, Boolean> loadAccessRules(AuthenticationToken authenticationToken) {
                return null;
            }
            @Override
            public int getUpdateNumber() {
                return updateNumber.get();
            }
            @Override
            public long getKeepUnusedEntriesFor() {
                return keepUnusedEntriesFor.get();
            }
        };
        assertNotNull(AuthorizationCache.INSTANCE.get(at2, callbackEmpty));
        assertEquals(1, AuthorizationCache.INSTANCE.get(at2, callbackEmpty).size());
        // Without increasing the updateNumer, nothing should happen when the cache is refreshed
        accessRules1.put("/rule2", Boolean.TRUE);
        AuthorizationCache.INSTANCE.refresh(callback);
        assertNotNull(AuthorizationCache.INSTANCE.get(at1, callback));
        assertEquals(1, AuthorizationCache.INSTANCE.get(at1, callback).size());
        updateNumber.incrementAndGet();
        AuthorizationCache.INSTANCE.refresh(callback);
        assertNotNull(AuthorizationCache.INSTANCE.get(at1, callback));
        assertEquals(2, AuthorizationCache.INSTANCE.get(at1, callback).size());
        // When the cache is refreshed, even if the updateNumber is not changed, unused entries will be removed
        accessRules1.clear();
        Thread.sleep(100L);
        AuthorizationCache.INSTANCE.refresh(callback);
        assertEquals(2, AuthorizationCache.INSTANCE.get(at1, callback).size());
        keepUnusedEntriesFor.set(0L);
        Thread.sleep(100L);
        AuthorizationCache.INSTANCE.refresh(callback);
        assertEquals(0, AuthorizationCache.INSTANCE.get(at1, callback).size());
        log.trace("<testBasicOperations");
    }

    /** Verify that only one of many calling threads for a cache entry will do the actual database lookup. */
    @Test
    public void testConcurrentRead() throws InterruptedException {
        log.trace(">testConcurrentRead");
        AuthorizationCache.INSTANCE.reset();
        final AtomicInteger updateNumber = new AtomicInteger(0);
        final AtomicLong keepUnusedEntriesFor = new AtomicLong(3600000L);
        final HashMap<String, Boolean> accessRules1 = new HashMap<>();
        accessRules1.put("/rule1", Boolean.TRUE);
        final AuthenticationToken at1 = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthorizationCacheTest.testConcurrentRead"));
        final int threadCount = 10;
        final CountDownLatch countDownLatchThreadsStarted = new CountDownLatch(threadCount+1);
        final CountDownLatch readTrigger = new CountDownLatch(1);
        final AtomicInteger loadInvocations = new AtomicInteger(0);
        final AuthorizationCacheCallback callback = new AuthorizationCacheCallback() {
            @Override
            public HashMap<String, Boolean> loadAccessRules(AuthenticationToken authenticationToken) {
                loadInvocations.incrementAndGet();
                if (at1==authenticationToken) {
                    countDownLatchThreadsStarted.countDown();
                    try {
                        // Wait for trigger until proceeding
                        readTrigger.await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return accessRules1;
                }
                return null;
            }
            @Override
            public int getUpdateNumber() {
                return updateNumber.get();
            }
            @Override
            public long getKeepUnusedEntriesFor() {
                return keepUnusedEntriesFor.get();
            }
        };
        final List<CacheReaderThread> cacheReaderThreads = new ArrayList<>();
        for (int i=0; i<threadCount; i++) {
            cacheReaderThreads.add(new CacheReaderThread(countDownLatchThreadsStarted, at1, callback));
        }
        for (final CacheReaderThread cacheReaderThread : cacheReaderThreads) {
            cacheReaderThread.start();
        }
        countDownLatchThreadsStarted.await();
        // Before the latch is released, none of the treads should have any result 
        for (final CacheReaderThread cacheReaderThread : cacheReaderThreads) {
            assertNull(cacheReaderThread.result);
        }
        // Only a single thread should have entered the callback section where the access rules are loaded
        assertEquals(1, loadInvocations.get());
        // Release the hounds!
        readTrigger.countDown();
        for (final CacheReaderThread cacheReaderThread : cacheReaderThreads) {
            cacheReaderThread.join();
        }
        // The EXACT same object should have been returned by all threads
        HashMap<String,Boolean> lastResult = null;
        for (final CacheReaderThread cacheReaderThread : cacheReaderThreads) {
            assertNotNull(cacheReaderThread.result);
            assertTrue(lastResult==null || lastResult==cacheReaderThread.result);
            lastResult = cacheReaderThread.result;
        }
        log.trace("<testConcurrentRead");
    }
    
    /** Helper class for retrieving a cache entry in a background thread */
    private class CacheReaderThread extends Thread {
        
        private final CountDownLatch countDownLatch;
        private final AuthenticationToken authenticationToken;
        private final AuthorizationCacheCallback authorizationCacheCallback;
        HashMap<String,Boolean> result = null;
        
        public CacheReaderThread(CountDownLatch countDownLatch, AuthenticationToken authenticationToken, AuthorizationCacheCallback authorizationCacheCallback) {
            this.countDownLatch = countDownLatch;
            this.authenticationToken = authenticationToken;
            this.authorizationCacheCallback = authorizationCacheCallback;
        }

        @Override
        public void run() {
            countDownLatch.countDown();
            try {
                result = AuthorizationCache.INSTANCE.get(authenticationToken, authorizationCacheCallback);
            } catch (AuthenticationFailedException e) {
                log.debug(e.getMessage());
            }
        }
    }
}
