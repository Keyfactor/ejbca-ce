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

package org.cesecore.repository.mock;

import jakarta.persistence.Query;
import jakarta.persistence.TypedQuery;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.util.ReflectionUtil;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class EntityManagerMock<ENTITY> extends BasicEntityManagerMock {

    private Comparator<Object> entityComparator;
    private TypedQueryMock typedQueryMock;
    private DeleteTypedQueryMock deleteTypedQueryMock;
    private List<Object> resultList;

    public EntityManagerMock(final Comparator<Object> entityComparator) {
        this.entityComparator = entityComparator;
        this.typedQueryMock = new TypedQueryMock(this);
        this.deleteTypedQueryMock = new DeleteTypedQueryMock<>(this);
        this.resultList = new ArrayList<>();
    }

    public List<Object> getResultList() {
        return resultList;
    }

    public void setResultList(final List<Object> resultList) {
        this.resultList = resultList;
    }

    public TypedQueryMock getTypedQueryMock() {
        return typedQueryMock;
    }

    public void setTypedQueryMock(TypedQueryMock typedQueryMock) {
        this.typedQueryMock = typedQueryMock;
    }

    @Override
    public void persist(Object o) {
        if (entityComparator == null) {
            typedQueryMock.getResultList().add(o);
        }
        else {
            for (final var entity : typedQueryMock.getResultList()) {
                if (entityComparator.compare(entity, o) == 0) {
                    throw new RecordIdAlreadyExistsException("Entity already persisted!");
                }
            }
            typedQueryMock.getResultList().add((ENTITY) o);
        }
    }

    @Override
    public void remove(Object o) {
        var remaining = new ArrayList<>();
        for (final var entity : resultList) {
            if (!ReflectionUtil.containsValue(entity, o)) {
                remaining.add(entity);
            }
        }
        setResultList(remaining);
        deleteTypedQueryMock.executeUpdate();
    }

    @Override
    public <T> T find(Class<T> aClass, Object o) {
        if (entityComparator == null || o == null) {
            return null;
        }
        for (final var entity : typedQueryMock.getResultList()) {
            if (entityComparator.compare(entity, o) == 0) {
                return (T) entity;
            }
        }
        return null;
    }

    @Override
    public <T> T getReference(Class<T> aClass, Object o) {
        return find(aClass, o);
    }

    @Override
    public void clear() {
        typedQueryMock.getResultList().clear();
    }

    @Override
    public boolean contains(Object o) {
        for (final var entity : typedQueryMock.getResultList()) {
            if (entityComparator.compare(entity, o) == 0) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Query createQuery(String sql) {
        if (sql.trim().toLowerCase().startsWith("delete ")) {
            return deleteTypedQueryMock;
        }
        else {
            return typedQueryMock;
        }
    }

    @Override
    public <T> TypedQuery<T> createQuery(String s, Class<T> aClass) {
        return typedQueryMock;
    }

}
