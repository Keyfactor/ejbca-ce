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

import org.apache.log4j.Logger;
import org.cesecore.repository.dto.Dto;
import org.cesecore.repository.dto.TimedDto;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.exception.RecordIndexDoesNotExistException;
import org.cesecore.repository.util.SynchronizationUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public final class Cache<T extends Dto<Id>, Id> implements Repository<T, Id> {

    private static final Logger log = Logger.getLogger(Cache.class);
    static final long NEVER_EXPIRE = Long.MAX_VALUE;

    private final Map<Id, TimedDto<T>> idToTimedDtoMap;
    private final Map<String, Id> indexToIdMap;
    private final Map<Id, String> idToIndexMap;
    private final long expirationTimeMs;
    private final Lock lock;

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

    private void verifyIdNotUsed(final T dto) {
        if (findById(dto.id()) != null) {
            final var message = "There is already an record with id: " + dto.id();
            log.debug(message);
            throw new RecordIdAlreadyExistsException(message);
        }
    }

    private void verifyIndexNotUsed(final T dto) {
        if (findByIndex(dto.index()) != null) {
            final var message = "There is already an record with index: " + dto.index();
            log.debug(message);
            throw new RecordIndexDoesNotExistException(message);
        }
    }

    T addNonSynchronized(T dto) {
        verifyIdNotUsed(dto);
        verifyIndexNotUsed(dto);
        var prevIndex = idToIndexMap.get(dto.id());
        indexToIdMap.remove(prevIndex);
        final var timedDto = new TimedDto<>(dto);
        idToTimedDtoMap.put(dto.id(), timedDto);
        final var index = dto.index();
        if (index != null) {
            indexToIdMap.put(index, dto.id());
            idToIndexMap.put(dto.id(), index);
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

    T findByIndexNonSynchronized(final String index) {
        final var id = indexToIdMap.get(index);
        final var timedDto = idToTimedDtoMap.get(id);
        return getNonExpiredDto(timedDto);
    }

    @Override
    public T findByIndex(final String index) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->findByIndexNonSynchronized(index));
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
        return SynchronizationUtil.synchronizedSupplier(lock, ()->findAllNonSynchronized());
    }

    T removeByIdNonSynchronized(final Id id) {
        final var timedDto = idToTimedDtoMap.remove(id);
        var index = idToIndexMap.remove(id);
        indexToIdMap.remove(index);
        return timedDto == null ?
                null :
                timedDto.dto();
    }

    T addOrUpdateNonSynchronized(final T dto) {
        removeByIdNonSynchronized(dto.id());
        removeByIndexNonSynchronized(dto.index());
        return addNonSynchronized(dto);
    }

    @Override
    public T addOrUpdate(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->addOrUpdateNonSynchronized(dto));
    }

    @Override
    public void update(final T dto) {
        removeByIdNonSynchronized(dto.id());
        addNonSynchronized(dto);
    }

    @Override
    public T removeById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(this.lock,
                ()->removeByIdNonSynchronized(id));
    }

    T removeByIndexNonSynchronized(final String index) {
        var id = indexToIdMap.remove(index);
        final var timedDto = idToTimedDtoMap.remove(id);
        idToIndexMap.remove(id);
        return timedDto == null ?
                null :
                timedDto.dto();
    }

    @Override
    public T removeByIndex(final String index) {
        return SynchronizationUtil.synchronizedSupplier(this.lock,
                ()->removeByIndexNonSynchronized(index));
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
