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
import org.cesecore.dto.Dto;
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

public final class Database<T extends Dto<Id>, Id, Bean extends EntityManagerBean<T>> implements Repository<T, Id> {

    private static final Logger log = Logger.getLogger(Database.class);

    private final EntityManager entityManager;
    private final Class<Bean> beanClass;
    private final Function<Bean, T> beanToDtoFunction;
    private final Function<T, Bean> dtoToBeanFunction;
    private final String[] indexColumnNames;
    private final Supplier<Id> idSupplier;
    private final Lock lock;

    public Database(final EntityManager entityManager,
                    final Class<Bean> beanClass,
                    final Function<Bean, T> beanToDtoFunction,
                    final Function<T, Bean> dtoToBeanFunction,
                    final Supplier<Id> idSupplier,
                    final String... indexColumnNames) {
        this.entityManager = entityManager;
        this.beanClass = beanClass;
        this.beanToDtoFunction = beanToDtoFunction;
        this.dtoToBeanFunction = dtoToBeanFunction;
        this.idSupplier = idSupplier;
        this.lock = new ReentrantLock();
        if (indexColumnNames.length == 0) {
            try {
                this.indexColumnNames = beanClass
                        .getConstructor()
                        .newInstance()
                        .toDto()
                        .indexNames();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        else {
            this.indexColumnNames = indexColumnNames;
        }
    }

    public Database(final EntityManager entityManager,
                    final Class<Bean> beanClass,
                    final Function<Bean, T> beanToDtoFunction,
                    final Function<T, Bean> dtoToBeanFunction,
                    final String... indexColumnNames) {
        this(entityManager, beanClass, beanToDtoFunction, dtoToBeanFunction, null, indexColumnNames);
    }

    private void verifyIdNotUsed(final T dto) {
        if (findByIdNonSynchronized(dto.id()) != null) {
            final var message = "There is already a record with id: " + dto.id();
            log.debug(message);
            throw new RecordIdAlreadyExistsException(message);
        }
    }

    private void verifyIndexNotUsed(final T dto) {
        var names = dto.indexNames();
        var values = dto.indexValues();
        if (findByIndexNonSynchronized(values) != null) {
            final StringBuilder messageBuilder = new StringBuilder("There is already a record with: ");
            String delim = "";
            for (int i=0; i<names.length; i++) {
                messageBuilder.append(String.format("%s%s=%s", delim, names[i], values[i]));
                delim = ", ";
            }
            final var message = messageBuilder.toString();
            log.debug(message);
            throw new RecordIndexAlreadyExistsException(message);
        }
    }

    @SuppressWarnings("unchecked")
    T addNonSynchronized(final T dto) {
        final T dtoWithId;
        if (dto.isIdUnassigned()) {
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
        final Bean bean = dtoToBeanFunction.apply(dtoWithId);
        entityManager.persist(bean);
        return dtoWithId;
    }

    @Override
    public T add(final T dto) {
        final var addedDto = SynchronizationUtil.synchronizedSupplier(lock,
                () -> addNonSynchronized(dto));
        if (log.isDebugEnabled()) {
            log.debug("Added: " + dto);
        }
        return addedDto;
    }

    T findByIdNonSynchronized(final Id id) {
        final var bean = entityManager.find(beanClass, id);
        return bean == null ?
                null :
                beanToDtoFunction.apply(bean);
    }

    public T findById(final Id id) {
        final var dto = SynchronizationUtil.synchronizedSupplier(lock, () -> findByIdNonSynchronized(id));
        if (log.isDebugEnabled()) {
            log.debug("Found: " + dto);
        }
        return dto;
    }

    private boolean isEmpty(final Object value) {
        return value == null || value.toString().isEmpty();
    }

    String getFindByIndexSql(final Object... indexValues) {
        final StringBuilder sqlBuilder = new StringBuilder();
        sqlBuilder.append("SELECT bean FROM ").append(beanClass.getSimpleName()).append(" bean WHERE ");
        String delimiter = "";
        for (int i = 0; i < indexColumnNames.length; i++) {
            sqlBuilder.append(delimiter);
            if (isEmpty(indexValues[i])) {
                sqlBuilder.append("bean.");
                sqlBuilder.append(indexColumnNames[i]);
                sqlBuilder.append(" IS NULL");
            }
            else {
                sqlBuilder.append("bean.");
                sqlBuilder.append(indexColumnNames[i]);
                sqlBuilder.append("=:");
                sqlBuilder.append(indexColumnNames[i]);
            }
            delimiter = " AND ";
        }
        return sqlBuilder.toString();
    }

    Bean findBeanByIndexNonSynchronized(final Object... indexValues) {
        if (indexValues == null || indexValues.length == 0) {
            return null;
        }
        final var sql = getFindByIndexSql(indexValues);
        var query = entityManager.createQuery(sql, beanClass);
        for (int i=0; i<indexValues.length; i++) {
            if (sql.contains(":" + indexColumnNames[i])) {
                query = query.setParameter(indexColumnNames[i], indexValues[i]);
            }
        }
        final var list = query.getResultList();
        return list.isEmpty() ?
                null :
                list.get(0);
    }

    T findByIndexNonSynchronized(final Object... indexValues) {
        final var bean = findBeanByIndexNonSynchronized(indexValues);
        return bean == null ?
                null :
                beanToDtoFunction.apply(bean);
    }

    @Override
    public T findByIndex(final Object... indexValues) {
        T dto = SynchronizationUtil.synchronizedSupplier(lock, () -> findByIndexNonSynchronized(indexValues));
        if (log.isDebugEnabled()) {
            log.debug("Found by index: " + dto);
        }
        return dto;
    }

    public List<T> findAllNonSynchronized() {
        final var list = entityManager.createQuery("SELECT bean FROM " + beanClass.getSimpleName() + " bean", beanClass)
                .getResultList()
                .stream()
                .map(beanToDtoFunction)
                .toList();
        if (log.isDebugEnabled()) {
            log.debug("Found all: ");
            for (final var dto : list) {
                log.debug(dto);
            }
        }
        return list;
    }

    public List<T> findAll() {
        return SynchronizationUtil.synchronizedSupplier(this.lock, this::findAllNonSynchronized);
    }

    T addOrUpdateNonSynchronized(final T dto) {
        final var dtoWithId = dto.isIdUnassigned() ?
                (T)dto.withId(idSupplier.get()) :
                dto;
        final var previousBeanById = entityManager.find(beanClass, dtoWithId.id());
        final var previousBeanByIndex = findBeanByIndexNonSynchronized(dtoWithId.indexValues());
        if (previousBeanById == null) {
            if (previousBeanByIndex == null) {
                final var beanWithId = dtoToBeanFunction.apply(dtoWithId);
                entityManager.persist(beanWithId);
                return dtoWithId;
            }
            else {
                throw new RecordIndexAlreadyExistsException("There is already a record with: " + Cache.toString(dtoWithId.indexNames(), dtoWithId.indexValues()));
            }
        }
        else {
            if (Objects.equals(previousBeanById, previousBeanByIndex) || previousBeanByIndex == null) {
                previousBeanById.init(dtoWithId);
                entityManager.merge(previousBeanById);
                return dtoWithId;
            }
            else {
                throw new RecordIndexAlreadyExistsException("There is already a record with: " + Cache.toString(dtoWithId.indexNames(), dtoWithId.indexValues()));
            }
        }
    }

    @Override
    public T addOrUpdate(final T dto) {
        return SynchronizationUtil.synchronizedSupplier(lock, ()->addOrUpdateNonSynchronized(dto));
    }

    void updateNonSynchronized(final T dto) {
        final var bean = entityManager.find(beanClass, dto.id());
        if (bean == null) {
            final String message = "There is no record with id: " + dto.id();
            log.debug(message);
            throw new RecordIdDoesNotExistException(message);
        }
        entityManager.remove(bean);
        if (findByIndexNonSynchronized(dto.indexValues()) != null) {
            throw new RecordIndexDoesNotExistException("There is already a record with: " + Cache.toString(dto.indexNames(), dto.indexValues()));
        }
        var updatedBean = dtoToBeanFunction.apply(dto);
        entityManager.persist(updatedBean);
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
            return beanToDtoFunction.apply(bean);
        }
    }

    @Override
    public T removeById(final Id id) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIdNonSynchronized(id));
    }

    T removeByIndexNonSynchronized(final Object... indexValues) {
        final T dto = findByIndexNonSynchronized(indexValues);
        if (dto != null) {
            removeByIdNonSynchronized(dto.id());
        }
        return dto;
    }

    @Override
    public T removeByIndex(final Object... indexValues) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> removeByIndexNonSynchronized(indexValues));
    }

    <U> U execute(final Lock lock, final Function<EntityManager, U> function) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> function.apply(entityManager));
    }

    public <U> U execute(final Function<EntityManager, U> function) {
        return SynchronizationUtil.synchronizedSupplier(lock, () -> function.apply(entityManager));
    }

}
