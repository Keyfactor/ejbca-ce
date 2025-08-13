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
import org.apache.log4j.Logger;
import org.cesecore.repository.dto.Dto;
import org.cesecore.repository.util.SynchronizationUtil;
import org.ejbca.dto.EntityManagerBean;

import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

public final class CachedDatabase<T extends Dto<Id>, Id, Bean extends EntityManagerBean> implements Repository<T, Id> {

    private static final Logger log = Logger.getLogger(CachedDatabase.class);

    private final Database<T, Id, Bean> database;
    private final Cache<T, Id> cache;
    private final Lock lock;

    public CachedDatabase(final Database<T, Id, Bean> database,
                          final Cache<T, Id> cache) {
        this.database = database;
        this.cache = cache;
        this.lock = new ReentrantLock();
    }

    T addNonSynchronized(final T dto) {
        final var addedDto = database.addNonSynchronized(dto);
        cache.addNonSynchronized(addedDto);
        return addedDto;
    }

    public T add(T dto) {
        return SynchronizationUtil.synchronizedSupplier(this.lock, () -> addNonSynchronized(dto));
    }

    T findByIdNonSynchronized(final Id id) {
        var dto = cache.findByIdNonSynchronized(id);
        if (dto == null) {
            dto = database.findByIdNonSynchronized(id);
            if (dto != null) {
                cache.addNonSynchronized(dto);
            }
        }
        return dto;
    }

    @Override
    public T findById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(this.lock, () -> findByIdNonSynchronized(id));
    }

    T findByIndexNonSynchronized(String index) {
        final var cacheDto = cache.findByIndexNonSynchronized(index);
        if (cacheDto == null) {
            final var dbDto = database.findByIndexNonSynchronized(index);
            if (dbDto != null) {
                cache.addNonSynchronized(dbDto);
            }
            return dbDto;
        }
        else {
            return cacheDto;
        }
    }

    public T findByIndex(String index) {
        return SynchronizationUtil.synchronizedSupplier(this.lock, () -> findByIndexNonSynchronized(index));
    }

    List<T> findAllNonSynchronized() {
        cache.clearNonSynchronized();
        return database.findAllNonSynchronized();
    }

    public List<T> findAll() {
        return SynchronizationUtil.synchronizedSupplier(this.lock, this::findAllNonSynchronized);
    }

    T addOrUpdateNonSynchronized(final T dto) {
        final var addedDto = database.addOrUpdateNonSynchronized(dto);
        cache.addOrUpdateNonSynchronized(addedDto);
        return addedDto;
    }

    public T addOrUpdate(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(this.lock, () -> addOrUpdateNonSynchronized(dto));
    }

    void updateNonSynchronized(final T dto) {
        cache.removeByIdNonSynchronized(dto.id());
        cache.removeByIndexNonSynchronized(dto.index());
        database.updateNonSynchronized(dto);
    }

    public void update(final T dto) {
        SynchronizationUtil.synchronizedRunnable(lock, () -> updateNonSynchronized(dto));
    }

    T removeByIdNonSynchronized(final Id id) {
        cache.removeByIdNonSynchronized(id);
        return database.removeByIdNonSynchronized(id);
    }

    @Override
    public T removeById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIdNonSynchronized(id));
    }

    T removeByIndexNonSynchronized(final String index) {
        cache.removeByIndexNonSynchronized(index);
        return database.removeByIndexNonSynchronized(index);
    }

    @Override
    public T removeByIndex(final String index) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIndexNonSynchronized(index));
    }

    public void clearCache() {
        SynchronizationUtil.synchronizedRunnable(this.lock, cache::clearNonSynchronized);
    }

    public void clearExpired() {
        SynchronizationUtil.synchronizedRunnable(this.lock, cache::clearExpiredNonSynchronized);
    }

    public <R> R execute(Function<EntityManager, R> function) {
        return database.execute((em) -> {
            cache.clearNonSynchronized();
            return function.apply(em);
        });
    }

}
