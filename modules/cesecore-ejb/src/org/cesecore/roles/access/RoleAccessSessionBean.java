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
package org.cesecore.roles.access;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.LocalJvmOnlyAuthenticationToken;
import org.cesecore.authentication.tokens.NestableAuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.util.QueryResultWrapper;

/**
 * @version $Id$
 *
 */
@Deprecated
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class RoleAccessSessionBean implements RoleAccessSessionLocal, RoleAccessSessionRemote {

    @EJB
    private CaSessionLocal caSession;
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @SuppressWarnings("unchecked")
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AdminGroupData> getAllRoles() {
        final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a");
        return (query.getResultList() != null ? query.getResultList() : new ArrayList<AdminGroupData>());
    }


    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData findRole(final String roleName) {
        final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.roleName=:roleName");
        query.setParameter("roleName", roleName);
        return (AdminGroupData) QueryResultWrapper.getSingleResult(query);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData findRole(final Integer primaryKey) {
        final Query query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.primaryKey=:primaryKey");
        query.setParameter("primaryKey", primaryKey);

        return (AdminGroupData) QueryResultWrapper.getSingleResult(query);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<String> getRolesMatchingAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final List<AdminGroupData> roleDatas = getAllRoles();
        final List<String> roleNames = new ArrayList<String>();
        for (final AdminGroupData roleData : roleDatas) {
            for (final AccessUserAspectData a : roleData.getAccessUsers().values()) {
                if (authenticationToken.matches(a)) {
                    roleNames.add(roleData.getRoleName());
                }
            }
        }
        return roleNames;
    }

    /*
     * NOTE: This separate method for remote EJB calls exists for a good reason: If this is invoked as a part of a
     * local transaction, the LocalJvmOnlyAuthenticationToken will be valid for subsequent authentication calls.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<String> getRolesMatchingAuthenticationTokenRemote(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        if (authenticationToken instanceof NestableAuthenticationToken) {
            ((NestableAuthenticationToken) authenticationToken).initRandomToken();
        } else if (authenticationToken instanceof LocalJvmOnlyAuthenticationToken) {
            // Ensure that the matching procedure below also works for remote EJB calls
            ((LocalJvmOnlyAuthenticationToken) authenticationToken).initRandomToken();
        }
        return getRolesMatchingAuthenticationToken(authenticationToken);
    }


    @Override
    public List<AdminGroupData> getAllAuthorizedRoles(AuthenticationToken authenticationToken) {
        List<AdminGroupData> roles = new ArrayList<>();
        roleLoop: for(AdminGroupData role : getAllRoles()) {
            // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
            for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
                if (!caSession.authorizedToCANoLogging(authenticationToken, accessUserAspect.getCaId())) {
                    continue roleLoop;
                }
            }
            // Secondly, walk through all CAs and make sure that there are no differences. 
            for (Integer caId : caSession.getAllCaIds()) {
                if(!caSession.authorizedToCANoLogging(authenticationToken, caId) && role.hasAccessToRule(StandardRules.CAACCESS.resource() + caId)) {
                    continue roleLoop;
                }
            }
            roles.add(role);
        }
        Collections.sort(roles);
        return roles;
    }
}
