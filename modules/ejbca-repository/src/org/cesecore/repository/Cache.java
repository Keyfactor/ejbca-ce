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

import org.cesecore.dto.Dto;
import org.cesecore.dto.TimedDto;
import org.cesecore.repository.util.SynchronizationUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public final class Cache<T extends Dto<Id>, Id> implements Repository<T, Id> {

    static final long NEVER_EXPIRE = Long.MAX_VALUE;

    private final Map<Id, TimedDto<T>> idToTimedDtoMap;
    private final Map<Integer, Id> indexToIdMap;
    private final Map<Id, Integer> idToIndexMap;
    private final long expirationTimeMs;
    private final Lock lock;

    static Integer getCacheKey(final Object... values) {
        return values == null || values.length == 0 ? null : Objects.hash(values);
    }

    static String toString(final String[] names, final Object[] values) {
        StringBuilder sb = new StringBuilder();
        String delim = "";
        for (int i = 0; i < names.length; i++) {
            sb.append(delim);
            sb.append(String.format("%s%s=%s", delim, names[i], ""+values[i]));
            delim = ", ";
        }
        return sb.toString();
    }

    public Cache() {
        this(NEVER_EXPIRE);
    }

    public Cache(final long expirationTimeMs) {
        this.idToTimedDtoMap = new LinkedHashMap<>();
        this.indexToIdMap = new HashMap<>();
        this.idToIndexMap = new HashMap<>();
        this.expirationTimeMs = expirationTimeMs;
        this.lock = new ReentrantLock();
    }

    public T addNonSynchronized(T dto) {
        removeByIdNonSynchronized(dto.id());
        var cacheKey = getCacheKey(dto.indexValues());
        removeByIndexNonSynchronized(cacheKey);
        var prevIndex = idToIndexMap.get(dto.id());
        indexToIdMap.remove(prevIndex);
        final var timedDto = new TimedDto<>(dto);
        idToTimedDtoMap.put(dto.id(), timedDto);
        if (cacheKey != null) {
            indexToIdMap.put(cacheKey, dto.id());
            idToIndexMap.put(dto.id(), cacheKey);
        }
        return dto;
    }

    @Override
    public T add(T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->addNonSynchronized(dto));
    }

    boolean isExpired(final long created) {
        return expirationTimeMs > 0 && created + expirationTimeMs < System.currentTimeMillis();
    }

    T getNonExpiredDto(final TimedDto<T> timedDto) {
        return timedDto == null || isExpired(timedDto.created()) ?
                null :
                timedDto.dto();
    }

    T findByIdNonSynchronized(final Id id) {
        return getNonExpiredDto(idToTimedDtoMap.get(id));
    }

    @Override
    public T findById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()-> findByIdNonSynchronized(id));
    }

    public T findByIndexNonSynchronized(final Integer indexKey) {
        final var id = indexToIdMap.get(indexKey);
        final var timedDto = idToTimedDtoMap.get(id);
        return getNonExpiredDto(timedDto);
    }

    @Override
    public T findByIndex(final Object... indexValues) {
        final Integer cacheKey = getCacheKey(indexValues);
        return SynchronizationUtil.synchronizedSupplier(lock, ()->findByIndexNonSynchronized(cacheKey));
    }

    List<T> findAllNonSynchronized() {
        return idToTimedDtoMap
                .values()
                .stream()
                .map(this::getNonExpiredDto)
                .toList();
    }

    @Override
    public List<T> findAll() {
        return SynchronizationUtil.synchronizedSupplier(lock, this::findAllNonSynchronized);
    }

    T removeByIdNonSynchronized(final Id id) {
        final var timedDto = idToTimedDtoMap.remove(id);
        var index = idToIndexMap.remove(id);
        indexToIdMap.remove(index);
        return timedDto == null ?
                null :
                timedDto.dto();
    }

    @Override
    public T addOrUpdate(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->addNonSynchronized(dto));
    }

    @Override
    public void update(final T dto) {
        SynchronizationUtil.synchronizedSupplier(lock, ()->addNonSynchronized(dto));
    }

    @Override
    public T removeById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(this.lock,
                ()->removeByIdNonSynchronized(id));
    }

    T removeByIndexNonSynchronized(final Integer indexKey) {
        if (indexKey == null) {
            return null;
        }
        else {
            var id = indexToIdMap.remove(indexKey);
            idToIndexMap.remove(id);
            final var timedDto = idToTimedDtoMap.remove(id);
            return getNonExpiredDto(timedDto);
        }
    }

    public T removeByIndex(final Object... indexValues) {
        final Integer cacheKey = getCacheKey(indexValues);
        return SynchronizationUtil.synchronizedSupplier(this.lock, ()->removeByIndexNonSynchronized(cacheKey));
    }

    void clearNonSynchronized() {
        idToTimedDtoMap.clear();
        indexToIdMap.clear();
        idToIndexMap.clear();
    }

    void clear() {
        SynchronizationUtil.synchronizedRunnable(this.lock, this::clearNonSynchronized);
    }

    List<T> getExpiredDtoListNonSynchronized() {
        List<T> list = new ArrayList<>();
        for (final var entry : idToTimedDtoMap.entrySet()) {
            if (isExpired(entry.getValue().created())) {
                list.add(entry.getValue().dto());
            }
            else {
                break;
            }
        }
        return list;
    }

    void clearExpiredNonSynchronized() {
        final var list = getExpiredDtoListNonSynchronized();
        for (final var dto : list) {
            removeByIdNonSynchronized(dto.id());
        }
    }

    public void clearExpired() {
        SynchronizationUtil.synchronizedRunnable(this.lock, this::clearExpiredNonSynchronized);
    }

}
