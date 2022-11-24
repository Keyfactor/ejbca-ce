/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.token.p11ng.provider;

import org.junit.Test;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.LongRef;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.mock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for @{{@link CryptokiWithCache}.
 */
public class CryptokiWithCacheTest {

    @Test
    public void testFindObjects() {
        final CKA[] ckas = new CKA[] {
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.CLASS, CKO.CERTIFICATE)
        };
        final CryptokiFacade mock = createMock(CryptokiFacade.class);
        final List<Long> expectedObjectRefs = Arrays.asList(1L, 2L);
        expect(mock.findObjects(1L, ckas)).andReturn(expectedObjectRefs).once();
        replay(mock);
        final CryptokiWithCache testMe = new CryptokiWithCache(mock);

        assertFalse("Objects cache should be empty.", testMe.findObjectsInCache(1L, ckas).isPresent());

        assertEquals("The value from the underlying API was not returned correctly.", expectedObjectRefs, testMe.findObjects(1L, ckas));

        final Optional<List<Long>> objectRefsDirectlyFromCache = testMe.findObjectsInCache(1L, ckas);
        assertTrue("Objects should have been cached", objectRefsDirectlyFromCache.isPresent());
        assertEquals("Wrong objects were cached.", expectedObjectRefs, objectRefsDirectlyFromCache.get());

        // This should also return the cached value, the mock will throw an exception if contacted twice
        assertEquals("Wrong objects were cached.", expectedObjectRefs, testMe.findObjects(1L, ckas));

        assertFalse("We cached CKA_TOKEN = true, but a search for CKA_TOKEN = false also gave a cache hit.",
                testMe.findObjectsInCache(1L, new CKA[] {
                        new CKA(CKA.TOKEN, false),
                        new CKA(CKA.CLASS, CKO.CERTIFICATE)
        }).isPresent());

        // TODO This is currently not implemented, but could potentially increase caching performance even more
        /*assertNotNull("Searching for a subset of attributes previously cached should work.", testMe.findObjectsInCache(1L, new CKA[] {
                new CKA(CKA.TOKEN, true)
        }));*/

        assertTrue("Should reuse values from a different session when looking in the cache.",
                testMe.findObjectsInCache(2L, ckas).isPresent());
        assertEquals("Should reuse values across sessions.",
                expectedObjectRefs, testMe.findObjects(2L, ckas));
        verify(mock);
    }

    @Test
    public void testFindObjectsWithTwoValuesInASingleSession() {
        final CKA[] ckas1 = new CKA[] { new CKA(CKA.TOKEN, true) };
        final CKA[] ckas2 = new CKA[] { new CKA(CKA.TOKEN, false) };
        final CryptokiFacade mock = createMock(CryptokiFacade.class);
        expect(mock.findObjects(1L, ckas1)).andReturn(Arrays.asList(1L)).once();
        expect(mock.findObjects(1L, ckas2)).andReturn(Arrays.asList(2L)).once();
        replay(mock);
        final CryptokiWithCache testMe = new CryptokiWithCache(mock);
        testMe.findObjects(1L, ckas1);
        testMe.findObjects(1L, ckas2);
        assertEquals("Should not overwrite values in the cache.", Arrays.asList(1L), testMe.findObjects(1L, ckas1));
        verify(mock);
    }

    @Test
    public void testGetAttributeValue() {
        final CryptokiFacade mock = mock(CryptokiFacade.class);
        expect(mock.getAttributeValue(1L, 1L, CKA.ID)).andReturn(new CKA(CKA.ID, "123")).once();
        expect(mock.getAttributeValue(1L, 1L, CKA.LABEL)).andReturn(new CKA(CKA.ID, "label123")).once();
        final CryptokiWithCache testMe = new CryptokiWithCache(mock);
        replay(mock);

        assertEquals("Wrong attribute value returned from API.", "123",
                testMe.getAttributeValue(1L, 1L, CKA.ID).getValueStr());

        // This should return the cached value, the mock will throw an exception if contacted twice
        assertEquals("Wrong attribute value returned on second API call.", "123",
                testMe.getAttributeValue(1L, 1L, CKA.ID).getValueStr());

        assertEquals("Wrong attribute returned when looking for CKA_LABEL.", "label123",
                testMe.getAttributeValue(1L, 1L, CKA.LABEL).getValueStr());
        assertEquals("Wrong attribute returned on second API call when looking for CKA_LABEL.", "label123",
                testMe.getAttributeValue(1L, 1L, CKA.LABEL).getValueStr());
        verify(mock);
    }

    @Test
    public void testGenerateAndGetKey() {
        final CKA[] dummyTemplate = new CKA[] {
                new CKA(CKA.TOKEN, false),
                new CKA(CKA.TRUSTED, false),
        };
        final CryptokiFacade mock = createNiceMock(CryptokiFacade.class);
        expect(mock.findObjects(1L, dummyTemplate)).andReturn(Arrays.asList(1L)).once();
        replay(mock);
        final CryptokiWithCache testMe = new CryptokiWithCache(mock);
        // Populate the cache with some dummy entries
        testMe.findObjects(1L, dummyTemplate);
        testMe.generateKeyPair(1L, createNiceMock(CKM.class), dummyTemplate, dummyTemplate, new LongRef(), new LongRef());
        assertFalse("Cache should be cleared after generating keys.",
                testMe.findObjectsInCache(1L, dummyTemplate).isPresent());

    }
}
