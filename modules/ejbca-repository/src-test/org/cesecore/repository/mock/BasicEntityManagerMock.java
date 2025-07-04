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

import jakarta.persistence.EntityGraph;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.EntityTransaction;
import jakarta.persistence.FlushModeType;
import jakarta.persistence.LockModeType;
import jakarta.persistence.Query;
import jakarta.persistence.StoredProcedureQuery;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaDelete;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.CriteriaUpdate;
import jakarta.persistence.metamodel.Metamodel;

import java.util.List;
import java.util.Map;

public class BasicEntityManagerMock implements EntityManager {

    @Override
    public void persist(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T merge(T t) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void remove(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T find(Class<T> aClass, Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T find(Class<T> aClass, Object o, Map<String, Object> map) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T find(Class<T> aClass, Object o, LockModeType lockModeType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T find(Class<T> aClass, Object o, LockModeType lockModeType, Map<String, Object> map) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T getReference(Class<T> aClass, Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void flush() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setFlushMode(FlushModeType flushModeType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public FlushModeType getFlushMode() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void lock(Object o, LockModeType lockModeType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void lock(Object o, LockModeType lockModeType, Map<String, Object> map) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void refresh(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void refresh(Object o, Map<String, Object> map) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void refresh(Object o, LockModeType lockModeType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void refresh(Object o, LockModeType lockModeType, Map<String, Object> map) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void detach(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean contains(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public LockModeType getLockMode(Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void setProperty(String s, Object o) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Map<String, Object> getProperties() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createQuery(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> TypedQuery<T> createQuery(CriteriaQuery<T> criteriaQuery) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createQuery(CriteriaUpdate criteriaUpdate) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createQuery(CriteriaDelete criteriaDelete) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> TypedQuery<T> createQuery(String s, Class<T> aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createNamedQuery(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> TypedQuery<T> createNamedQuery(String s, Class<T> aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createNativeQuery(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createNativeQuery(String s, Class aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Query createNativeQuery(String s, String s1) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public StoredProcedureQuery createNamedStoredProcedureQuery(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public StoredProcedureQuery createStoredProcedureQuery(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public StoredProcedureQuery createStoredProcedureQuery(String s, Class... classes) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public StoredProcedureQuery createStoredProcedureQuery(String s, String... strings) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void joinTransaction() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isJoinedToTransaction() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> T unwrap(Class<T> aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Object getDelegate() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isOpen() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public EntityTransaction getTransaction() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public EntityManagerFactory getEntityManagerFactory() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public CriteriaBuilder getCriteriaBuilder() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Metamodel getMetamodel() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> EntityGraph<T> createEntityGraph(Class<T> aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public EntityGraph<?> createEntityGraph(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public EntityGraph<?> getEntityGraph(String s) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public <T> List<EntityGraph<? super T>> getEntityGraphs(Class<T> aClass) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
