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
import org.cesecore.repository.dto.Converter;
import org.cesecore.repository.dto.Dto;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.exception.RecordIdDoesNotExistException;
import org.cesecore.repository.exception.RecordIndexAlreadyExistsException;
import org.cesecore.repository.exception.RecordIndexDoesNotExistException;
import org.cesecore.repository.util.SynchronizationUtil;
import org.ejbca.dto.EntityManagerBean;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Supplier;

public final class Database<T extends Dto<Id>, Id, Bean extends EntityManagerBean> implements Repository<T, Id> {

    private static final Logger log = Logger.getLogger(Database.class);

    private final EntityManager entityManager;
    private final Class<Bean> beanClass;
    private final Converter<T, Bean> converter;
    private final String indexColumnName;
    private final Supplier<Id> idSupplier;
    private final Lock lock;

    public Database(final EntityManager entityManager,
                    final Class<Bean> beanClass,
                    final Converter<T, Bean> converter,
                    final String indexColumnName,
                    final Supplier<Id> idSupplier) {
        this.entityManager = entityManager;
        this.beanClass = beanClass;
        this.converter = converter;
        this.indexColumnName = indexColumnName;
        this.idSupplier = idSupplier;
        this.lock = new ReentrantLock();
    }

    public Database(final EntityManager entityManager,
                    final Class<Bean> beanClass,
                    final Converter<T, Bean> converter,
                    final String indexColumnName) {
        this(entityManager, beanClass, converter, indexColumnName, null);
    }

    private void verifyIdNotUsed(final T dto) {
        if (findByIdNonSynchronized(dto.id()) != null) {
            final var message = "There is already an record with id: " + dto.id();
            log.debug(message);
            throw new RecordIdAlreadyExistsException(message);
        }
    }

    private void verifyIndexNotUsed(final T dto) {
        if (findByIndexNonSynchronized(dto.index()) != null) {
            final var message = "There is already an record with index: " + dto.index();
            log.debug(message);
            throw new RecordIndexAlreadyExistsException(message);
        }
    }

    @SuppressWarnings("unchecked")
    T addNonSynchronized(final T dto) {
        T dtoWithId;
        if (dto.id() == null) {
            if (idSupplier == null) {
                final var message = "Cannot add an object without id to the database.";
                log.debug(message);
                throw new IllegalStateException(message);
            }
            else {
                dtoWithId = (T)dto.withId(idSupplier.get());
            }
        }
        else {
            dtoWithId = dto;
        }
        verifyIdNotUsed(dtoWithId);
        verifyIndexNotUsed(dtoWithId);
        Bean bean = converter.toBean(dtoWithId);
        entityManager.persist(bean);
        return dtoWithId;
    }

    @Override
    public T add(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock,
                () -> addNonSynchronized(dto));
    }

    T findByIdNonSynchronized(final Id id) {
        final var bean = entityManager.find(beanClass, id);
        return converter.toDto(bean);
    }

    public T findById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> findByIdNonSynchronized(id));
    }

    Bean findBeanByIndexNonSynchronized(final String index) {
        final var sql = "SELECT bean FROM " + beanClass.getSimpleName() + " bean WHERE " + indexColumnName + "=:index";
        final var query = entityManager.createQuery(sql, beanClass).setParameter("index", index);
        final var list = query.getResultList();
        return list.isEmpty() ?
                null :
                list.get(0);
    }

    T findByIndexNonSynchronized(final String index) {
        final var bean = findBeanByIndexNonSynchronized(index);
        return converter.toDto(bean);
    }

    @Override
    public T findByIndex(final String index) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> findByIndexNonSynchronized(index));
    }

    public List<T> findAllNonSynchronized() {
        return entityManager.createQuery("SELECT bean FROM " + beanClass.getSimpleName() + " bean", beanClass)
                .getResultList()
                .stream()
                .map(converter::toDto)
                .toList();
    }

    public List<T> findAll() {
        return SynchronizationUtil.synchronizedSupplier(this.lock, this::findAllNonSynchronized);
    }

    T addOrUpdateNonSynchronized(final T dto) {
        final var dtoWithId = dto.id() == null ? (T)dto.withId(idSupplier.get()) : dto;
        final var previousBeanById = entityManager.find(beanClass, dtoWithId.id());
        final var previousBeanByIndex = findBeanByIndexNonSynchronized(dtoWithId.index());
        if (previousBeanById == null) {
            if (previousBeanByIndex == null) {
                final var bean = converter.toBean(dtoWithId);
                entityManager.persist(bean);
                return converter.toDto(bean);
            }
            else {
                throw new RecordIndexDoesNotExistException("There is already a record with index: " + dtoWithId.index());
            }
        }
        else {
            if (Objects.equals(previousBeanById, previousBeanByIndex) || previousBeanByIndex == null) {
                entityManager.remove(previousBeanById);
                final var persistedDto = converter.toDto(previousBeanById);
                entityManager.persist(previousBeanById);
                return persistedDto;
            }
            else {
                throw new RecordIndexAlreadyExistsException("There is already a record with index: " + dtoWithId.index());
            }
        }
    }

    @Override
    public T addOrUpdate(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->addOrUpdateNonSynchronized(dto));
    }

    void updateNonSynchronized(final T dto) {
        try {
            entityManager.getTransaction().begin();
            var bean = entityManager.find(beanClass, dto.id());
            if (bean == null) {
                final String message = "There is no record with id: " + dto.id();
                log.debug(message);
                throw new RecordIdDoesNotExistException(message);
            }
            entityManager.refresh(bean);
            var updatedBean = converter.toBean(dto);
            entityManager.persist(updatedBean);
            entityManager.getTransaction().commit();
        }
        catch (Exception e) {
            entityManager.getTransaction().rollback();
            throw e;
        }
    }

    @Override
    public void update(final T dto) {
        SynchronizationUtil.synchronizedRunnable(lock, () -> updateNonSynchronized(dto));
    }

    T removeByIdNonSynchronized(final Id id) {
        final var bean = entityManager.find(beanClass, id);
        if (bean == null) {
            return null;
        }
        else {
            entityManager.remove(bean);
            return converter.toDto(bean);
        }
    }

    @Override
    public T removeById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIdNonSynchronized(id));
    }

    T removeByIndexNonSynchronized(final String index) {
        final var bean = findBeanByIndexNonSynchronized(index);
        if (bean == null) {
            return null;
        }
        else {
            entityManager.remove(bean);
            return converter.toDto(bean);
        }
    }

    @Override
    public T removeByIndex(final String index) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIndexNonSynchronized(index));
    }

    <T> T execute(final Lock lock, final Function<EntityManager, T> function) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> function.apply(entityManager));
    }

    public <T> T execute(final Function<EntityManager, T> function) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> function.apply(entityManager));
    }

}
