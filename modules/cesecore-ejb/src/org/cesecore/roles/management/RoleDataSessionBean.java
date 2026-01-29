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
package org.cesecore.roles.management;

import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.repository.Cache;
import org.cesecore.repository.CachedDatabase;
import org.cesecore.repository.Database;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.ProfileID;
import org.ejbca.dto.RoleData;

/**
 * Implementation of the RoleDataSession local interface.
 * 
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleDataSessionBean implements RoleDataSessionLocal, RoleDataSessionRemote {

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    private static final Lock INIT_LOCK = new ReentrantLock();
    private static Cache<RoleDataDto, Integer> roleDataCache;
    private static Database<RoleDataDto, Integer, RoleData> roleDataDatabase;
    private static CachedDatabase<RoleDataDto, Integer, RoleData> roleDataRepository;

    private int findFreeDatabaseId() {
        final ProfileID.DB db = (id) -> {
            if (id == RoleDataDto.ROLE_ID_UNASSIGNED) {
                return false;
            }
            Query query = entityManager.createQuery("SELECT r from RoleData r where r.id = :id");
            query.setParameter("id", id);
            return query.getResultList().isEmpty();
        };
        return ProfileID.getNotUsedID(db);
    }

    private RoleData dtoToBean(RoleDataDto dto) {
        RoleData bean = new RoleData();
        bean.init(dto);
        return bean;
    }

    @PostConstruct
    public void initialize() {
        if (roleDataRepository == null) {
            try {
                INIT_LOCK.lock();
                if (roleDataRepository == null) {
                    roleDataDatabase = new Database<>(
                            entityManager,
                            RoleData.class,
                            RoleData::toDto,
                            this::dtoToBean,
                            this::findFreeDatabaseId,
                            "nameSpace", "roleName");
                    roleDataCache = new Cache<>(CesecoreConfiguration.getCacheAuthorizationTime());
                    roleDataRepository = new CachedDatabase<>(roleDataDatabase, roleDataCache);
                }
            } finally {
                INIT_LOCK.unlock();
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<RoleDataDto> getAllRoles() {
        return roleDataRepository.findAll();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleDataDto getRole(final String nameSpace, final String roleName) {
        return roleDataRepository.findByIndex(nameSpace, roleName);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public RoleDataDto getRole(final int roleId) {
        if (roleId == RoleDataDto.ROLE_ID_UNASSIGNED) {
            // The reserved ID will never have a database entry, so return quickly with what we know will be the result
            return null;
        }
        return roleDataRepository.findById(roleId);
    }

    @Override
    public RoleDataDto persistRole(final RoleDataDto roleData) {
        if (roleData == null) {
            // Successfully did nothing
            return null;
        }
        final var persisted = roleDataRepository.addOrUpdate(roleData);
        if (isRoleMembersPresent(persisted.id())) {
            accessTreeUpdateSession.signalForAccessTreeUpdate();
        }
        return persisted;
    }

    @Override
    public boolean deleteRoleNoAuthorizationCheck(final int roleId) {
        final var removedDto = roleDataRepository.removeById(roleId);
        if (removedDto != null && isRoleMembersPresent(removedDto.id())) {
            accessTreeUpdateSession.signalForAccessTreeUpdate();
        }
        return removedDto != null;
    }
    
    private boolean isRoleMembersPresent(final int roleId) {
        return !roleMemberDataSession.findByRoleId(roleId).isEmpty();
    }

    @Override
    public void forceCacheExpire() {
        roleDataRepository.clearCache();
    }

}
