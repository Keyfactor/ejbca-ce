package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Random;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * 
 * @version $Id$
 */
public final class ConcurrentCacheTest {

    private static final Logger log = Logger.getLogger(ConcurrentCacheTest.class);

    // Internal IDs for threads
    private static final int THREAD_ONE = 101;
    private static final int THREAD_TWO = 102;
    private static final int THREAD_RANDOM = 200;
    
    private static final int CONCURRENT_OPEN_TIMEOUT = 2000;
    
    private static final int NUM_RANDOM_THREADS = 100;

    @Test
    public void testSingleThreaded() throws Exception {
        log.trace(">testSingleThreaded");
        final ConcurrentCache<String,Integer> cache = new ConcurrentCache<String,Integer>();
        ConcurrentCache<String,Integer>.Entry entry;
        
        // Create new entry
        entry = cache.openCacheEntry("A", 1);
        assertNotNull("openCacheEntry timed out in single-threaded test", entry);
        assertFalse("isInCache should return false for non-existent entry", entry.isInCache());
        try {
            entry.getValue();
            fail("getValue should throw for non-existent entry");
        } catch (IllegalStateException e) { // NOPMD
        }
        entry.putValue(111);
        entry.setCacheValidity(60*1000);
        entry.close();
        
        // Read it and modify the value
        entry = cache.openCacheEntry("A", 1);
        assertNotNull("openCacheEntry timed out in single-threaded test", entry);
        assertTrue("isInCache should return true for existing entry", entry.isInCache());
        assertEquals(Integer.valueOf(111), entry.getValue());
        entry.putValue(222);
        assertEquals(Integer.valueOf(222), entry.getValue());
        entry.setCacheValidity(60*1000);
        entry.close();
        
        // Read it again and modify the timeout 
        entry = cache.openCacheEntry("A", 1);
        assertNotNull("openCacheEntry timed out in single-threaded test", entry);
        assertTrue("isInCache should return true for existing entry", entry.isInCache());
        assertEquals(Integer.valueOf(222), entry.getValue());
        entry.setCacheValidity(1);
        entry.close();
        
        Thread.sleep(5);
        
        // Try to read it now. It should have expired and a fresh entry should be returned. 
        entry = cache.openCacheEntry("A", 1);
        assertFalse("isInCache should return false for expired entry", entry.isInCache());
        try {
            entry.getValue();
            fail("getValue should throw for expired entry");
        } catch (IllegalStateException e) { // NOPMD
        }
        entry.close();
        log.trace("<testSingleThreaded");
    }
    
    @Test
    public void testDisabled() throws Exception {
        log.trace(">testDisabled");
        final ConcurrentCache<String,Integer> cache = new ConcurrentCache<String,Integer>();
        cache.setEnabled(false);
        ConcurrentCache<String,Integer>.Entry entry;
        
        // Create entries. All operations should be "no-ops"
        for (int i = 0; i < 10; i++) {
            long timeBefore = System.currentTimeMillis();
            entry = cache.openCacheEntry("A", 1);
            assertTrue("openCacheEntry took too long. It should be a no-op when cache is disabled", System.currentTimeMillis() < timeBefore+10);
            assertNotNull("openCacheEntry timed out when cache is disabled", entry);
            assertFalse("isInCache should return false when cache is disabled", entry.isInCache());
            try {
                entry.getValue();
                fail("getValue should throw when caching is disabled");
            } catch (IllegalStateException e) { // NOPMD
            }
            entry.putValue(111);
            entry.setCacheValidity(60*1000);
            entry.close();
            
            // This should have been a no-op
            cache.checkNumberOfEntries(0, 0);
        }
        log.trace("<testDisabled");
    }
    
    @Test
    public void testMultiThreaded() throws Exception {
        log.trace(">testMultiThreaded");
        final ConcurrentCache<String,Integer> cache = new ConcurrentCache<String,Integer>();
        
        final Thread thread1 = new Thread(new CacheTestRunner(cache, THREAD_ONE), "CacheTestThread1");
        final Thread thread2 = new Thread(new CacheTestRunner(cache, THREAD_TWO), "CacheTestThread2");
        
        thread1.start();
        thread2.start();
        
        thread1.join();
        thread2.join();
        
        log.trace("<testMultiThreaded");
    }
    
    @Test(timeout=6000)
    public void testRandomMultiThreaded() throws InterruptedException {
        log.trace(">testRandomMultiThreaded");
        // This tests outputs as LOT of debug/trace messages. JUnit even runs out of heap space if those are enabled.
        Logger.getRootLogger().setLevel(Level.INFO);
        Logger.getLogger(ConcurrentCache.class).setLevel(Level.INFO);
        try {
            final ConcurrentCache<String,Integer> cache = new ConcurrentCache<String,Integer>();
            cache.setMaxEntries(20);
            cache.setCleanupInterval(100); // To stress the system a bit more
            
            final Thread[] threads = new Thread[NUM_RANDOM_THREADS];
            final CacheTestRunner[] runners = new CacheTestRunner[NUM_RANDOM_THREADS];
            for (int i = 0; i < threads.length; i++) {
                runners[i] = new CacheTestRunner(cache, THREAD_RANDOM);
                threads[i] = new Thread(runners[i], "CacheTestThread"+i);
            }
            try {
                log.info("Now starting the threads");
                for (int i = 0; i < threads.length; i++) {
                    threads[i].start();
                }
                
                log.info("All threads started");
                Thread.sleep(2000);
            } finally {
                log.info("Asking threads to stop");
                for (int i = 0; i < threads.length; i++) {
                    runners[i].shouldExit = true;
                }
                
                log.info("Waiting for join of first thread (1 sec timeout)");
                threads[0].join(1000);
                log.info("Waiting for other threads");
                Thread.sleep(100);
                for (int i = 1; i < threads.length; i++) {
                    threads[i].join(1);
                }
            }
            
            long timeout = System.currentTimeMillis() + 2000; // if a thread stops for more than 2 s in cleanup() then that's a problem by itself
            for (int i = 0; i < threads.length; i++) {
                if (threads[i].isAlive() && System.currentTimeMillis() < timeout) {
                    threads[i].join(2000);
                }
                assertFalse("Thread "+i+" was still alive", threads[i].isAlive());
            }
        } finally {
            // Preferably, the log level should be restored to the original value,
            // but neither of the getLevel/getEffectiveLevel methods return the correct value
            // so we hard-code Level.TRACE here.
            Logger.getRootLogger().setLevel(Level.TRACE);
            Logger.getLogger(ConcurrentCache.class).setLevel(Level.TRACE);
            log.trace("<testRandomMultiThreaded");
        }
    }
    
    private static final int MAXENTRIES = 1000000;
    private static final int OVERSHOOT = MAXENTRIES+(MAXENTRIES/2)+1; // overshoot by 50%
    private static final int MIN_ENTRIES_AFTER_CLEANUP = MAXENTRIES - (MAXENTRIES/4); // 75% of maxentries
    
    @Test
    public void testMaxEntries() throws Exception {
        log.trace(">testMaxEntries");
        final ConcurrentCache<String,Integer> cache = new ConcurrentCache<String,Integer>();
        cache.setMaxEntries(MAXENTRIES);
        cache.setCleanupInterval(100);
        ConcurrentCache<String,Integer>.Entry entry;
        
        try {
            Logger.getLogger(ConcurrentCache.class).setLevel(Level.INFO);
            // Create initial entries
            log.debug("Creating initial entries");
            for (int i = 0; i < MAXENTRIES; i++) {
                entry = cache.openCacheEntry(String.valueOf(i), 1);
                assertNotNull("openCacheEntry timed out", entry);
                assertFalse("isInCache should return false for non-existent entry", entry.isInCache());
                entry.putValue(i);
                entry.setCacheValidity(60*1000);
                entry.close();
            }
            
            cache.checkNumberOfEntries(MAXENTRIES, MAXENTRIES);
            
            // Add some more. Cleanup is guaranteed to run if we overshoot by 50%
            log.debug("Creating more entries (to overshoot the limit)");
            for (int i = MAXENTRIES; i <= OVERSHOOT; i++) {
                entry = cache.openCacheEntry(String.valueOf(i), 1);
                assertNotNull("openCacheEntry timed out", entry);
                assertFalse("isInCache should return false for non-existent entry", entry.isInCache());
                entry.putValue(i);
                entry.setCacheValidity(60*1000);
                entry.close();
            }
            
            log.debug("Sleeping to allow for cleanup to run again");
            Thread.sleep(100);
            
            // Access the cache once more to trigger a cleanup
            entry = cache.openCacheEntry(String.valueOf("x"), 1);
            assertNotNull("openCacheEntry timed out", entry);
            assertFalse("isInCache should return false for non-existent entry", entry.isInCache());
            entry.putValue(-123456);
            entry.setCacheValidity(60*1000);
            entry.close();
            
            log.debug("Done creating entries");
            
            // Cleanup should have run now
            cache.checkNumberOfEntries(MIN_ENTRIES_AFTER_CLEANUP, MAXENTRIES-1);
        } finally {
            Logger.getLogger(ConcurrentCache.class).setLevel(Level.TRACE);
            log.trace("<testMaxEntries");
        }
    }
    
    private static final class CacheTestRunner implements Runnable {
        private final int id;
        private final ConcurrentCache<String,Integer> cache;
        
        private final static String[] KEYS = {"A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"};
        public volatile boolean shouldExit = false;
        
        public CacheTestRunner(final ConcurrentCache<String,Integer> cache, final int id) {
            this.cache = cache;
            this.id = id;
        }
        
        @Override
        public void run() {
            ConcurrentCache<String,Integer>.Entry entry;
            
            try {
                switch (id) {
                case THREAD_ONE:
                    // 0 ms
                    entry = cache.openCacheEntry("A", 1);
                    assertFalse("non-existent entry should not be in cache", entry.isInCache());
                    Thread.sleep(200);
                    entry.putValue(123);
                    entry.setCacheValidity(200); // = valid to ~400 ms
                    entry.close();
                    break;
                case THREAD_TWO:
                    Thread.sleep(100);
                    // 100 ms
                    entry = cache.openCacheEntry("A", CONCURRENT_OPEN_TIMEOUT);
                    // 200 ms
                    assertTrue("existing entry should be in cache", entry.isInCache());
                    assertEquals("wrong value of cache entry", Integer.valueOf(123), entry.getValue());
                    entry.close();
                    
                    Thread.sleep(300);
                    
                    // 500 ms
                    entry = cache.openCacheEntry("A", CONCURRENT_OPEN_TIMEOUT);
                    assertFalse("entry should have expired", entry.isInCache());
                    entry.close();
                    break;
                case THREAD_RANDOM:
                    final Random random = new Random(id);
                    final Integer value = Integer.valueOf(id);
                    while (!shouldExit) {
                        final String key = KEYS[random.nextInt(KEYS.length)];
                        entry = cache.openCacheEntry(key, CONCURRENT_OPEN_TIMEOUT);
                        if (entry.isInCache()) {
                            assertNotNull("got null value in cache entry", entry.getValue());
                            if (random.nextInt(10000) == 123) {
                                entry.setCacheValidity(2000+random.nextInt(100));
                            }
                            entry.close();
                        } else {
                            Thread.sleep(1+random.nextInt(50));
                            entry.putValue(value);
                            entry.setCacheValidity(2000+random.nextInt(100));
                            entry.close();
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("invalid test thread id");
                }
            } catch (InterruptedException ie) {
                throw new RuntimeException(ie);
            }
        }
    }

}