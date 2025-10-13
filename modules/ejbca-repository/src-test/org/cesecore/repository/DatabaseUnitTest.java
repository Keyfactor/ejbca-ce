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

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.cesecore.dto.DummyCertWithIndex;
import org.cesecore.dto.DummyCertWithIndexBean;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.exception.RecordIndexAlreadyExistsException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import static org.cesecore.repository.util.DtoUtil.getDummyCertWithIndex;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

public class DatabaseUnitTest {

    private EntityManager entityManager;
    private TypedQuery<DummyCertWithIndexBean> query;
    private Map<String, Object> parameters;
    private Database<DummyCertWithIndex, Long, DummyCertWithIndexBean> database;
    private DummyCertWithIndex cert1;
    private DummyCertWithIndex cert2;
    private AtomicLong nextId;
    private List<DummyCertWithIndexBean> beanList;

    private DummyCertWithIndexBean dtoToBean(final DummyCertWithIndex dto) {
        DummyCertWithIndexBean bean = new DummyCertWithIndexBean();
        bean.init(dto);
        return bean;
    }

    private boolean containsId(final Long id) {
        return beanList.stream().anyMatch(bean -> bean.getId().equals(id));
    }

    private boolean equals(Object[] a, Object[] b) {
        for (int i = 0; i < a.length; i++) {
            if (!Objects.equals(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }

    private boolean containsIndex(final DummyCertWithIndex dto) {
        return beanList.stream()
                .map(bean->bean.toDto().indexValues())
                .anyMatch(indexValues -> equals(indexValues, dto.indexValues()));
    }

    @Before
    public void setUp() {
        nextId = new AtomicLong(1L);
        beanList = new ArrayList<>();
        query = Mockito.mock(TypedQuery.class);
        entityManager = Mockito.mock(EntityManager.class);
        parameters = new HashMap<>();
        doAnswer(invocation -> {
            DummyCertWithIndexBean bean = invocation.getArgument(0);
            DummyCertWithIndex dto = bean.toDto();
            if (containsId(dto.getId())) {
                throw new RecordIdAlreadyExistsException("There is already an record with id=" + dto.getId());
            }
            if (containsIndex(dto)) {
                throw new RecordIndexAlreadyExistsException("There is already an record with index. " + dto);
            }
            beanList.add(bean);
            return null;
        }).when(entityManager).persist(any());
        when(entityManager.createQuery(anyString(), eq(DummyCertWithIndexBean.class))).thenReturn(query);
        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Object value = invocation.getArgument(1);
            parameters.put(key, value);
            return query;
        }).when(query).setParameter(anyString(), any());
        when(query.getResultList()).thenReturn(beanList);
        doAnswer(invocation -> {
            final Long id = invocation.getArgument(1);
            return beanList.stream()
                    .filter(bean -> bean.getId().equals(id)).findFirst().orElse(null);
        }).when(entityManager).find(eq(DummyCertWithIndexBean.class), any());
        database = new Database<>(
                entityManager,
                DummyCertWithIndexBean.class,
                DummyCertWithIndexBean::toDto,
                this::dtoToBean,
                () -> nextId.getAndIncrement());
        cert1 = getDummyCertWithIndex(1L, "common-name-1", "name-1", "author-1", 1);
        cert2 = getDummyCertWithIndex(2L, "common-name-2", "name-2", "author-2", 2);
    }

    @Test
    public void testAddNonSynchronized_idAndIndexFree() {
        // Given

        // When
        database.addNonSynchronized(cert1);

        // Then
        assertEquals(1, beanList.size());
        assertEquals(cert1, beanList.get(0).toDto());
    }

    @Test(expected = RecordIdAlreadyExistsException.class)
    public void testAddNonSynchronized_idAlreadyUsed() {
        // Given
        final var dto = cert2.withId(cert1.getId());
        final var bean = new DummyCertWithIndexBean();
        bean.init(dto);
        beanList.add(bean);

        // When
        database.addNonSynchronized(cert1);
    }

    @Test(expected = RecordIndexAlreadyExistsException.class)
    public void testAddNonSynchronized_indexAlreadyUsed() {
        // Given
        final var dto = cert2.withName(cert1.getName());
        final var bean = new DummyCertWithIndexBean();
        bean.init(dto);
        beanList.add(bean);

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
        final var bean = new DummyCertWithIndexBean();
        bean.init(cert1);
        beanList.add(bean);

        // When
        final var actual = database.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
    }

}
