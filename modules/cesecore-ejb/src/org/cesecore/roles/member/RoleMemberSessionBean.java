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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.management.RoleSessionLocal;
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

    private static final Logger log = Logger.getLogger(RoleMemberSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private RoleSessionLocal roleSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    
    private void checkRoleAuth(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        // TODO should do an authorization check on the role itself, see RoleSessionBean.persistRole()
        //assertAuthorizedToEditRoles(authenticationToken);
        //assertAuthorizedToAllAccessRules(authenticationToken, role);
        //assertNotMemberAndAuthorizedToNameSpace(authenticationToken, role);
        
        // Check existence and authorization of referenced objects 
        if (roleMember.getRoleId() != RoleMember.NO_ROLE && roleSession.getRole(authenticationToken, roleMember.getRoleId()) == null) {
            throw new IllegalStateException("Role with ID " + roleMember.getRoleId() + " was not found, or administrator is not authorized to it");
        }
        if (roleMember.getTokenIssuerId() != RoleMember.NO_ISSUER) {
            try {
                caSession.getCAInfo(authenticationToken, roleMember.getTokenIssuerId());
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("CA with ID " + roleMember.getTokenIssuerId() + " was not found, or administrator is not authorized to it");
            }
        }
    }
    
    @Override
    public int createOrEdit(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        checkRoleAuth(authenticationToken, roleMember);
        
        final RoleMemberData roleMemberData;
        if (roleMember.getId() != RoleMember.ROLE_MEMBER_ID_UNASSIGNED) {
            roleMemberData = find(roleMember.getId());
            checkRoleAuth(authenticationToken, roleMemberData.asValueObject());
        } else {
            roleMemberData = new RoleMemberData();
        }
        
        roleMemberData.updateValuesFromValueObject(roleMember);
        
        if (log.isDebugEnabled()) {
            log.debug("Persisting a role member with ID " + roleMember.getRoleId() + " and match value '" + roleMember.getTokenMatchValue() + "'");
        }
        return createOrEdit(roleMemberData);
    }
    
    @Override
    public int createOrEdit(RoleMemberData roleMember) {
        if (roleMember.getPrimaryKey() == 0) {
            roleMember.setPrimaryKey(findFreePrimaryKey());
            entityManager.persist(roleMember);
        } else {
            entityManager.merge(roleMember);
        }
        accessTreeUpdateSession.signalForAccessTreeUpdate();
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
    public RoleMember getRoleMember(final AuthenticationToken authenticationToken, final int roleMemberId) throws AuthorizationDeniedException {
        final RoleMember roleMember = findRoleMember(roleMemberId);
        // Authorization checks
        if (roleMember.getRoleId() != null && roleMember.getRoleId() != RoleMember.NO_ROLE) {
            roleSession.getRole(authenticationToken, roleMember.getRoleId());
        }
        if (roleMember.getTokenIssuerId() != RoleMember.NO_ISSUER) {
            try {
                caSession.getCA(authenticationToken, roleMember.getTokenIssuerId());
            } catch (CADoesntExistsException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Role references CA with ID " + roleMember.getTokenIssuerId() + ", which is missing.");
                }
            }
        }
        return roleMember;
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
        // TODO: This a naive implementation iterating over all RoleMemberDatas of this type. See ECA-5607 for suggested improvement.
        // For example keep a list of distinct tokenSubTypes present in the table and asking the authToken for all permutations might be another approach
        // With the naive approach below we would be better off to background reload all rows into memory and search there
        final TypedQuery<RoleMemberData> query = entityManager
                .createQuery("SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType", RoleMemberData.class)
                .setParameter("tokenType", authenticationToken.getMetaData().getTokenType());
        try {
            final Set<Integer> ret = new HashSet<>();
            for (final RoleMemberData roleMemberData : query.getResultList()) {
                if (roleMemberData.getRoleId()!=RoleMember.NO_ROLE) {
                    if (authenticationToken.matches(convertToAccessUserAspect(roleMemberData.asValueObject()))) {
                        ret.add(roleMemberData.getRoleId());
                    }
                }
            }
            return ret;
        } catch (AuthenticationFailedException e) {
            log.debug(e.getMessage(), e);
            return new HashSet<>();
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    @Deprecated
    public Map<Integer,Integer> getRoleIdsAndTokenMatchKeysMatchingAuthenticationToken(final AuthenticationToken authenticationToken) {
        final TypedQuery<RoleMemberData> query = entityManager
                .createQuery("SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType", RoleMemberData.class)
                .setParameter("tokenType", authenticationToken.getMetaData().getTokenType());
        try {
            final Map<Integer,Integer> ret = new HashMap<>();
            for (final RoleMemberData roleMemberData : query.getResultList()) {
                if (roleMemberData.getRoleId()!=RoleMember.NO_ROLE) {
                    if (authenticationToken.matches(convertToAccessUserAspect(roleMemberData.asValueObject()))) {
                        ret.put(roleMemberData.getRoleId(), roleMemberData.getTokenMatchKey());
                    }
                }
            }
            return ret;
        } catch (AuthenticationFailedException e) {
            log.debug(e.getMessage(), e);
            return new HashMap<>();
        }
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
