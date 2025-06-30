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

import jakarta.persistence.FlushModeType;
import jakarta.persistence.LockModeType;
import jakarta.persistence.Parameter;
import jakarta.persistence.TemporalType;
import jakarta.persistence.TypedQuery;
import org.cesecore.repository.util.ReflectionUtil;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class TypedQueryMock<T> implements TypedQuery<T> {

    private final EntityManagerMock entityManagerMock;
    private int executionResult;
    Map<String, Object> parameters = new HashMap<>();

    public TypedQueryMock(EntityManagerMock entityManagerMock) {
        this.entityManagerMock = entityManagerMock;
    }

    public EntityManagerMock getEntityManagerMock() {
        return entityManagerMock;
    }

    public int getExecutionResult() {
        return executionResult;
    }

    public void setExecutionResult(int executionResult) {
        this.executionResult = executionResult;
    }

    @Override
    public List<T> getResultList() {
        return entityManagerMock.getResultList();
    }

    boolean isIncluded(T result) {
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            try {
                var fieldValue = ReflectionUtil.getFieldValue(result, entry.getKey());
                if (Objects.equals(fieldValue, entry.getValue())) {
                    return true;
                }
            }
            catch (Exception e) {
            }
        }
        return false;
    }

    public List<T> getFilteredResultList() {
        return getResultList().stream()
                .filter(this::isIncluded)
                .toList();
    }

    @Override
    public T getSingleResult() {
        return getResultList().get(0);
    }

    @Override
    public int executeUpdate() {
        return executionResult;
    }

    @Override
    public TypedQuery<T> setParameter(String s, Object o) {
        parameters.put(s, o);
        return this;
    }

    @Override
    public TypedQuery<T> setMaxResults(int i) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getMaxResults() {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setFirstResult(int i) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getFirstResult() {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setHint(String s, Object o) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, Object> getHints() {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T1> TypedQuery<T> setParameter(Parameter<T1> parameter, T1 t1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(Parameter<Calendar> parameter, Calendar calendar, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(Parameter<Date> parameter, Date date, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(String s, Calendar calendar, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(String s, Date date, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(int i, Object o) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(int i, Calendar calendar, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setParameter(int i, Date date, TemporalType temporalType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<Parameter<?>> getParameters() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Parameter<?> getParameter(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> Parameter<T> getParameter(String s, Class<T> aClass) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Parameter<?> getParameter(int i) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> Parameter<T> getParameter(int i, Class<T> aClass) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isBound(Parameter<?> parameter) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> T getParameterValue(Parameter<T> parameter) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object getParameterValue(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Object getParameterValue(int i) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setFlushMode(FlushModeType flushModeType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public FlushModeType getFlushMode() {
        throw new UnsupportedOperationException();
    }

    @Override
    public TypedQuery<T> setLockMode(LockModeType lockModeType) {
        throw new UnsupportedOperationException();
    }

    @Override
    public LockModeType getLockMode() {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T> T unwrap(Class<T> aClass) {
        throw new UnsupportedOperationException();
    }
}
