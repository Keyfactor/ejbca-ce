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
package org.cesecore.roles.member;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;

/**
 * @see RoleMemberSessionLocal
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberSessionBean implements RoleMemberSessionLocal, RoleMemberSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public int createOrEdit(RoleMemberData roleMember) {
        if (roleMember.getPrimaryKey() == 0) {
            roleMember.setPrimaryKey(findFreePrimaryKey());
            entityManager.persist(roleMember);
        } else {
            entityManager.merge(roleMember);
        }
        return roleMember.getPrimaryKey();

    }
    
    private int findFreePrimaryKey() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                //0 is a protected ID for RoleMemberData. Use only positive values, since negatives are seen as "erronous" by some customers.
                return find(i) == null && i > 0;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMemberData find(final int primaryKey) {
        return entityManager.find(RoleMemberData.class, primaryKey);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMember findRoleMember(int primaryKey) {
        RoleMemberData roleMemberData = find(primaryKey);
        if (roleMemberData != null) {
            return roleMemberData.asValueObject();
        } else {
            return null;
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMemberData> findByRoleId(int roleId) {
        final TypedQuery<RoleMemberData> query = entityManager.createQuery("SELECT a FROM RoleMemberData a WHERE a.roleId=:roleId", RoleMemberData.class);
        query.setParameter("roleId", roleId);
        return query.getResultList();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMember> findRoleMemberByRoleId(int roleId) {
        List<RoleMemberData> entityBeans = findByRoleId(roleId);
        List<RoleMember> result = new ArrayList<>();
        for (RoleMemberData roleMemberData : entityBeans) {
            if (roleMemberData != null) {
                result.add(roleMemberData.asValueObject());
            }
        }
        return result;
    }

    @Override
    public boolean remove(final int primaryKey) {
        RoleMemberData roleMember = find(primaryKey);
        if (roleMember != null) {
            entityManager.remove(roleMember);
            return true;
        } else {
            return false;
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<Integer> getRoleIdsMatchingAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final Set<Integer> ret = new HashSet<>();
        final AccessMatchValue defaultAccessMatchValue = authenticationToken.getDefaultMatchValue();
        final String tokenType = defaultAccessMatchValue.getTokenType();
        // TODO: This a naive implementation iterating over all RoleMemberDatas of this type. See ECA-5607 for suggested improvement.
        final TypedQuery<RoleMemberData> query = entityManager.createQuery("SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType", RoleMemberData.class);
        query.setParameter("tokenType", tokenType);
        final List<RoleMemberData> roleMemberDatas = query.getResultList();
        for (final RoleMemberData roleMemberData : roleMemberDatas) {
            if (roleMemberData.getRoleId()!=RoleMember.NO_ROLE) {
                if (authenticationToken.matches(convertToAccessUserAspect(roleMemberData))) {
                    ret.add(roleMemberData.getRoleId());
                }
            }
        }
        return ret;
    }
    
    // TODO: Remove this once there is a better way to match tokens
    private AccessUserAspect convertToAccessUserAspect(final RoleMemberData roleMemberData) {
        return new AccessUserAspect() {
            private static final long serialVersionUID = 1L;

            @Override
            public int getMatchWith() {
                return roleMemberData.getTokenSubType();
            }

            @Override
            public void setMatchWith(Integer matchWith) { }

            @Override
            public int getMatchType() {
                return AccessMatchType.TYPE_NONE.getNumericValue();
            }

            @Override
            public void setMatchType(Integer matchType) { }

            @Override
            public AccessMatchType getMatchTypeAsType() {
                return AccessMatchType.TYPE_NONE;
            }

            @Override
            public void setMatchTypeAsValue(AccessMatchType matchType) { }

            @Override
            public String getMatchValue() {
                return roleMemberData.getTokenMatchValue();
            }

            @Override
            public void setMatchValue(String matchValue) { }

            @Override
            public Integer getCaId() {
                return roleMemberData.getTokenIssuerId();
            }

            @Override
            public void setCaId(Integer caId) { }

            @Override
            public String getTokenType() {
                return roleMemberData.getTokenType();
            }

            @Override
            public void setTokenType(String tokenType) { }
        };
    }
}
