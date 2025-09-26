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

package org.cesecore.repository;

import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.mock.EntityManagerMock;
import org.ejbca.dto.DummyCert;
import org.ejbca.dto.DummyCertBean;
import org.ejbca.dto.DummyCertConverter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import static org.cesecore.repository.CachedDatabaseUnitTest.getDummyCert;

public class DatabaseUnitTest {

    private EntityManagerMock entityManagerMock;
    private Database database;
    private DummyCert cert1;
    private DummyCert cert2;
    private DummyCertConverter certConverter;
    private AtomicLong nextId;

    private boolean equals(Object o1, Object o2) {
        if (o2 instanceof Long) {
            DummyCertBean certBean1 = (DummyCertBean) o1;
            return Objects.equals(certBean1.getId(), o2);
        }
        DummyCertBean certBean1 = (DummyCertBean) o1;
        DummyCertBean certBean2 = (DummyCertBean) o2;
        return Objects.equals(certBean1.getId(), certBean2.getId()) || Objects.equals(certBean1.getName(), certBean2.getName());
    }

    @Before
    public void setUp() {
        nextId = new AtomicLong(1L);
        entityManagerMock = new EntityManagerMock((o1, o2) -> equals(o1, o2) ? 0 : -1);
        certConverter = new DummyCertConverter();
        database = new Database(
                entityManagerMock,
                DummyCertBean.class,
                certConverter,
                "name",
                () -> nextId.getAndIncrement());
        cert1 = getDummyCert(1L, "name-1", "author-1", 1);
        cert2 = getDummyCert(2L, "name-2", "author-2", 2);
    }

    @Test
    public void testAddNonSynchronized_idAndIndexFree() {
        // Given

        // When
        database.addNonSynchronized(cert1);

        // Then
        Assert.assertEquals(1, entityManagerMock.getTypedQueryMock().getResultList().size());
        assertEquals(cert1, certConverter.toDto((DummyCertBean) entityManagerMock.getTypedQueryMock().getResultList().get(0)));
    }

    @Test(expected = RecordIdAlreadyExistsException.class)
    public void testAddNonSynchronized_idAlreadyUsed() {
        // Given
        final var otherBean = new DummyCertBean();
        otherBean.setId(cert1.id());
        otherBean.setName("name-other");
        entityManagerMock.getTypedQueryMock().getResultList().add(otherBean);

        // When
        database.addNonSynchronized(cert1);
    }

    @Test
    public void testFindByIdNonSynchronized_noMatch() {
        // Given

        // When
        final var actual = database.findByIdNonSynchronized(cert1.id());

        // Then
        assertNull(actual);
    }

    @Test
    public void testFindByIdNonSynchronized_match() {
        // Given
        final var expectedBean = certConverter.toBean(cert1);
        entityManagerMock.getTypedQueryMock().getResultList().add(expectedBean);

        // When
        final var actual = database.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
    }

    @Test
    public void testFindAllNonSynchronized() {
        // Given
        final var expectedBean1 = certConverter.toBean(cert1);
        entityManagerMock.getTypedQueryMock().getResultList().add(expectedBean1);
        final var expectedBean2 = certConverter.toBean(cert2);
        entityManagerMock.getTypedQueryMock().getResultList().add(expectedBean2);

        // When
        final var actual = database.findAllNonSynchronized();

        // Then
        assertNotNull(actual);
        assertEquals(2, actual.size());
        assertEquals(cert1, actual.get(0));
        assertEquals(cert2, actual.get(1));
    }

}
