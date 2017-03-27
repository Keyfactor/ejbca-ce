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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;

/**
 * @see RoleMemberSessionDataLocal
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberDataSessionBean implements RoleMemberDataSessionLocal, RoleMemberDataSessionRemote {

    private static final Logger log = Logger.getLogger(RoleMemberDataSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public RoleMember persistRoleMember(final RoleMember roleMember) {
        if (roleMember==null) {
            // Successfully did nothing
            return null;
        }
        if (roleMember.getId() == RoleMember.ROLE_MEMBER_ID_UNASSIGNED) {
            roleMember.setId(findFreePrimaryKey());
            entityManager.persist(new RoleMemberData(roleMember));
        } else {
            final RoleMemberData roleMemberData = find(roleMember.getId());
            if (roleMemberData==null) {
                // Must have been removed by another process, but caller wants to persist it, so we proceed
                roleMember.setId(findFreePrimaryKey());
                entityManager.persist(new RoleMemberData(roleMember));
            } else {
                // Since the entity is managed, we just update its values
                roleMemberData.updateValuesFromValueObject(roleMember);
            }
        }
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        return roleMember;
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
            accessTreeUpdateSession.signalForAccessTreeUpdate();
            return true;
        } else {
            return false;
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<Integer> getRoleIdsMatchingAuthenticationToken(final AuthenticationToken authenticationToken) {
        try {
            return getRoleIdsMatchingAuthenticationTokenOrFail(authenticationToken);
        } catch (AuthenticationFailedException e) {
            log.debug(e.getMessage(), e);
            return new HashSet<>();
        }
    }
    
    private TypedQuery<RoleMemberData> getQueryForAuthenticationToken(final AuthenticationToken authenticationToken) {
        final String tokenType = authenticationToken.getMetaData().getTokenType();
        final TypedQuery<RoleMemberData> query;
        final int preferredMatchKey = authenticationToken.getPreferredMatchKey();
        if (preferredMatchKey != AuthenticationToken.NO_PREFERRED_MATCH_KEY) {
            final List<AccessMatchType> accessMatchType = authenticationToken.getMetaData().getAccessMatchValueIdMap().get(preferredMatchKey).getAvailableAccessMatchTypes();
            final int preferredOperator = accessMatchType.isEmpty() ? AccessMatchType.TYPE_UNUSED.getNumericValue() : accessMatchType.get(0).getNumericValue();
            // Optimized search for preferred match values (e.g. serial number match key) amongst members with that match key.
            // For members with other match keys, we include everything in the search
            query = entityManager.createQuery("SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType AND a.roleId<>0 AND "+
                    "((a.tokenMatchKey=:preferredTokenMatchKey AND a.tokenMatchOperator=:operator AND a.tokenMatchValueColumn=:preferredTokenMatchValue) OR " +
                    "NOT (a.tokenMatchKey=:preferredTokenMatchKey AND a.tokenMatchOperator=:operator))", RoleMemberData.class)
                    .setParameter("tokenType", tokenType)
                    .setParameter("preferredTokenMatchKey", preferredMatchKey)
                    .setParameter("operator", preferredOperator)
                    .setParameter("preferredTokenMatchValue", authenticationToken.getPreferredMatchValue());
        } else {
            // Search for all members with the same token type
            query = entityManager.createQuery("SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType AND a.roleId<>0", RoleMemberData.class)
                    .setParameter("tokenType", tokenType);
        }
        return query;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<Integer> getRoleIdsMatchingAuthenticationTokenOrFail(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final Set<Integer> ret = new HashSet<>();
        if (authenticationToken!=null) {
            final TypedQuery<RoleMemberData> query = getQueryForAuthenticationToken(authenticationToken);
            for (final RoleMemberData roleMemberData : query.getResultList()) {
                if (authenticationToken.matches(convertToAccessUserAspect(roleMemberData.asValueObject()))) {
                    ret.add(roleMemberData.getRoleId());
                }
            }
        }
        return ret;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    @Deprecated
    public Map<Integer,Integer> getRoleIdsAndTokenMatchKeysMatchingAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final TypedQuery<RoleMemberData> query = getQueryForAuthenticationToken(authenticationToken);
        final Map<Integer,Integer> ret = new HashMap<>();
        for (final RoleMemberData roleMemberData : query.getResultList()) {
            if (authenticationToken.matches(convertToAccessUserAspect(roleMemberData.asValueObject()))) {
                ret.put(roleMemberData.getRoleId(), roleMemberData.getTokenMatchKey());
            }
        }
        return ret;
    }
    
    // TODO: Remove this once there is a better way to match tokens
    private AccessUserAspect convertToAccessUserAspect(final RoleMember roleMember) {
        return new AccessUserAspect() {
            private static final long serialVersionUID = 1L;

            @Override
            public int getMatchWith() {
                return roleMember.getTokenMatchKey();
            }

            @Override
            public void setMatchWith(Integer matchWith) { }

            @Override
            public int getMatchType() {
                return roleMember.getTokenMatchOperator();
            }

            @Override
            public void setMatchType(Integer matchType) { }

            @Override
            public AccessMatchType getMatchTypeAsType() {
                return AccessMatchType.matchFromDatabase(roleMember.getTokenMatchOperator());
            }

            @Override
            public void setMatchTypeAsValue(AccessMatchType matchType) { }

            @Override
            public String getMatchValue() {
                return roleMember.getTokenMatchValue();
            }

            @Override
            public void setMatchValue(String matchValue) { }

            @Override
            public Integer getCaId() {
                return roleMember.getTokenIssuerId();
            }

            @Override
            public void setCaId(Integer caId) { }

            @Override
            public String getTokenType() {
                return roleMember.getTokenType();
            }

            @Override
            public void setTokenType(String tokenType) { }
        };
    }
}
