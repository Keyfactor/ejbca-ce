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
package org.cesecore.authorization.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;

import javax.persistence.EntityManager;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for AccessTreeUpdateSessionBean
 * 
 * Based on cesecore version:
 *      AccessTreeUpdateSessionBeanTest.java 207 2011-01-31 13:36:36Z tomas
 * 
 * @version $Id$
 * 
 */
public class AccessTreeUpdateSessionBeanTest {

    private AccessTreeUpdateSessionBean accessTreeUpdateSessionBean;

    @Before
    public void setUp() {
        accessTreeUpdateSessionBean = new AccessTreeUpdateSessionBean();
    }

    @Test
    public void testGetAccessTreeUpdateDataWithExistingAccessTreeUpdateData() throws SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException {

        AccessTreeUpdateData accessTreeUpdateData = EasyMock.createMock(AccessTreeUpdateData.class);
        EasyMock.replay(accessTreeUpdateData);

        // Use reflection to insert a dummy EntityManager
        EntityManager entityManager = EasyMock.createMock(EntityManager.class);
        EasyMock.expect(entityManager.find(EasyMock.eq(AccessTreeUpdateData.class), EasyMock.anyInt())).andReturn(accessTreeUpdateData);
        EasyMock.replay(entityManager);

        Field entityManagerField = accessTreeUpdateSessionBean.getClass().getDeclaredField("entityManager");
        entityManagerField.setAccessible(true);
        entityManagerField.set(accessTreeUpdateSessionBean, entityManager);

        AccessTreeUpdateData result;

        // First, get a "real" value;
        result = accessTreeUpdateSessionBean.getAccessTreeUpdateData();
        assertEquals(result, accessTreeUpdateData);

        // Run again to make sure that the cache is set.
        result = accessTreeUpdateSessionBean.getAccessTreeUpdateData();
        assertEquals(result, accessTreeUpdateData);

        EasyMock.verify(accessTreeUpdateData, entityManager);
    }

    @Test
    public void testGetAccessTreeUpdateDataWithoutExistingAccessTreeUpdateData() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {

        // Use reflection to insert a dummy EntityManager
        EntityManager entityManager = EasyMock.createMock(EntityManager.class);
        EasyMock.expect(entityManager.find(EasyMock.eq(AccessTreeUpdateData.class), EasyMock.anyInt())).andReturn(null);
        entityManager.persist(EasyMock.anyObject(AccessTreeCache.class));
        EasyMock.replay(entityManager);

        Field entityManagerField = accessTreeUpdateSessionBean.getClass().getDeclaredField("entityManager");
        entityManagerField.setAccessible(true);
        entityManagerField.set(accessTreeUpdateSessionBean, entityManager);
        
        assertNotNull(accessTreeUpdateSessionBean.getAccessTreeUpdateData());

        EasyMock.verify(entityManager);

    }

}
