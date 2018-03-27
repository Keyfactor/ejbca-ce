/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ra;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EndEntityAccessSessionBean implements EndEntityAccessSessionLocal, EndEntityAccessSessionRemote {

    /** Columns in the database used in select. */
    private static final String USERDATA_CREATED_COL = "timeCreated";

    private static final Logger log = Logger.getLogger(EndEntityAccessSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm> getPasswordAndHashAlgorithmForUser(String username)
            throws NotFoundException {
        UserData user = findByUsername(username);
        if (user == null) {
            throw new NotFoundException("End Entity of name " + username + " not found in database");
        } else {
            return new AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm>(user.getPasswordHash(), user.findHashAlgorithm());
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findUserBySubjectDN(final AuthenticationToken admin, final String subjectdn)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserBySubjectDN(" + subjectdn + ")");
        }
        // String used in SQL so strip it
        final String dn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with subjectdn: " + dn);
        }
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN", UserData.class);
        query.setParameter("subjectDN", dn);
        final List<UserData> dataList =  query.getResultList();
        
        if (dataList.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with subjectdn: " + dn);
            }
        }
        final List<EndEntityInformation> result = new ArrayList<EndEntityInformation>();
        for (UserData data : dataList) {
            result.add(convertUserDataToEndEntityInformation(admin, data, null));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectDN(" + subjectdn + ")");
        }
        return result;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<UserData> findNewOrKeyrecByHardTokenIssuerId(int hardTokenIssuerId, int maxResults) {
        final TypedQuery<UserData> query = entityManager
                .createQuery("SELECT a FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId AND a.tokenType>=:tokenType AND (a.status=:status1 OR a.status=:status2)", UserData.class);
        query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
        query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
        query.setParameter("status1", EndEntityConstants.STATUS_NEW);
        query.setParameter("status2", EndEntityConstants.STATUS_KEYRECOVERY);
        if (maxResults > 0) {
            query.setMaxResults(maxResults);
        }
        return query.getResultList();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> findSubjectDNsByCaIdAndNotUsername(final int caId, final String username,
            final String serialnumber) {
        final TypedQuery<String> query = entityManager
                .createQuery("SELECT a.subjectDN FROM UserData a WHERE a.caId=:caId AND a.username!=:username AND a.subjectDN LIKE :serial", String.class);
        query.setParameter("caId", caId);
        query.setParameter("username", username);
        query.setParameter("serial", "%SN="+ serialnumber + "%");
        return query.getResultList();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findUserBySubjectAndIssuerDN(final AuthenticationToken admin, final String subjectdn, final String issuerdn)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserBySubjectAndIssuerDN(" + subjectdn + ", " + issuerdn + ")");
        }
        // String used in SQL so strip it
        final String dn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
        final String issuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerdn));
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with subjectdn: " + dn + ", issuerdn : " + issuerDN);
        }
        
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN AND a.caId=:caId", UserData.class);
        query.setParameter("subjectDN", dn);
        query.setParameter("caId", issuerDN.hashCode());
        final List<UserData> dataList = query.getResultList();
        if (dataList.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with subjectdn: " + dn + ", issuerdn : " + issuerDN);
            }
        }
        final List<EndEntityInformation> result = new ArrayList<EndEntityInformation>();
        for (UserData data : dataList) {
            result.add(convertUserDataToEndEntityInformation(admin, data, null));
        }
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectAndIssuerDN(" + subjectdn + ", " + issuerDN + ")");
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityInformation findUser(final String username) {
        try {
            return findUser(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal search for End Entity")), username);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always allow token was denied authorization.", e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityInformation findUser(final AuthenticationToken admin, final String username) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUser(" + username + ")");
        }        
        final UserData data = findByUsername(username);
        if (data == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with username='" + username + "'");
            }
        }
        final EndEntityInformation ret = convertUserDataToEndEntityInformation(admin, data, username);
        if (log.isTraceEnabled()) {
            log.trace("<findUser(" + username + "): " + (ret == null ? "null" : ret.getDN()));
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public UserData findByUsername(String username) {
        if (username == null) {
            return null;
        }
        return entityManager.find(UserData.class, username);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findUserByEmail(AuthenticationToken admin, String email) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserByEmail(" + email + ")");
        }
        if (log.isDebugEnabled()) {
            log.debug("Looking for user with email: " + email);
        }
        
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectEmail=:subjectEmail", UserData.class);
        query.setParameter("subjectEmail", email);
        final List<UserData> result =  query.getResultList();
        if (result.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with Email='" + email + "'");
            }
        }
        final List<EndEntityInformation> returnval = new ArrayList<EndEntityInformation>();
        for (final UserData data : result) {
            if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                    .getEnableEndEntityProfileLimitations()) {
                // Check if administrator is authorized to view user.
                if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_END_ENTITY)) {
                    continue;
                }
            }
            if (!authorizedToCA(admin, data.getCaId())) {
                continue;
            }
            returnval.add(convertUserDataToEndEntityInformation(admin, data, null));

        }
        if (log.isTraceEnabled()) {
            log.trace("<findUserByEmail(" + email + ")");
        }
        return returnval;
    }

    /** 
     * @return the userdata value object if admin is authorized. Does not leak username if auth fails. 
     * 
     * @throws AuthorizationDeniedException if the admin was not authorized to the end entity profile or issuing CA
     */
    private EndEntityInformation convertUserDataToEndEntityInformation(final AuthenticationToken admin, final UserData data,
            final String requestedUsername) throws AuthorizationDeniedException {
        if (data != null) {
            if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                    .getEnableEndEntityProfileLimitations()) {
                // Check if administrator is authorized to view user.
                if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_END_ENTITY)) {
                    if (requestedUsername == null) {
                        final String msg = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(data.getEndEntityProfileId()),
                                admin.toString());
                        throw new AuthorizationDeniedException(msg);
                    } else {
                        final String msg = intres.getLocalizedMessage("ra.errorauthprofileexist", Integer.valueOf(data.getEndEntityProfileId()),
                                requestedUsername, admin.toString());
                        throw new AuthorizationDeniedException(msg);
                    }
                }
            }
            if (!authorizedToCA(admin, data.getCaId())) {
                if (requestedUsername == null) {
                    final String msg = intres.getLocalizedMessage("ra.errorauthca", Integer.valueOf(data.getCaId()), admin.toString());
                    throw new AuthorizationDeniedException(msg);
                } else {
                    final String msg = intres.getLocalizedMessage("ra.errorauthcaexist", Integer.valueOf(data.getCaId()), requestedUsername,
                            admin.toString());
                    throw new AuthorizationDeniedException(msg);
                }
            }
            return data.toEndEntityInformation();
        }
        return null;
    }

    private boolean authorizedToEndEntityProfile(AuthenticationToken admin, int profileid, String rights) {
        boolean returnval = false;
        if (profileid == EndEntityConstants.EMPTY_END_ENTITY_PROFILE
                && (rights.equals(AccessRulesConstants.CREATE_END_ENTITY) || rights.equals(AccessRulesConstants.EDIT_END_ENTITY))) {
            if (authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                returnval = true;
            } else {
                log.info("Admin " + admin.toString() + " was not authorized to resource " + StandardRules.ROLE_ROOT);
            }
        } else {
            returnval = authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights,
                    AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
        return returnval;
    }

    private boolean authorizedToCA(AuthenticationToken admin, int caid) {
        boolean returnval = false;
        returnval = authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
        if (!returnval) {
            log.info("Admin " + admin.toString() + " not authorized to resource " + StandardRules.CAACCESS.resource() + caid);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<EndEntityInformation> findAllUsersByStatus(AuthenticationToken admin, int status) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByStatus(" + status + ")");
        }
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with status: " + status);
        }
        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(status));
        Collection<EndEntityInformation> returnval = null;
        try {
            returnval = query(admin, query, null, null, 0, AccessRulesConstants.VIEW_END_ENTITY);
        } catch (IllegalQueryException e) {
        }
        if (log.isDebugEnabled()) {
            log.debug("found " + returnval.size() + " user(s) with status=" + status);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByStatus(" + status + ")");
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<EndEntityInformation> findAllUsersByCaId(AuthenticationToken admin, int caid) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByCaId(" + caid + ")");
        }
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with caid: " + caid);
        }
        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_CA, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(caid));
        Collection<EndEntityInformation> returnval = null;
        try {
            returnval = query(admin, query, null, null, 0, AccessRulesConstants.VIEW_END_ENTITY);
        } catch (IllegalQueryException e) {
            // Ignore ??
            log.debug("Illegal query", e);
            returnval = new ArrayList<EndEntityInformation>();
        }
        if (log.isDebugEnabled()) {
            log.debug("found " + returnval.size() + " user(s) with caid=" + caid);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByCaId(" + caid + ")");
        }
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countByCaId(int caId) {
        final javax.persistence.Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.caId=:caId");
        query.setParameter("caId", caId);
        return ((Long) query.getSingleResult()).longValue(); // Always returns a result
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countByCertificateProfileId(int certificateProfileId) {
        final javax.persistence.Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.certificateProfileId=:certificateProfileId");
        query.setParameter("certificateProfileId", certificateProfileId);
        return ((Long) query.getSingleResult()).longValue(); // Always returns a result
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countByHardTokenIssuerId(int hardTokenIssuerId) {
        final javax.persistence.Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId");
        query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
        return ((Long) query.getSingleResult()).longValue(); // Always returns a result
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countByHardTokenProfileId(int hardTokenProfileId) {
        final javax.persistence.Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.tokenType=:tokenType");
        query.setParameter("tokenType", hardTokenProfileId);
        return ((Long) query.getSingleResult()).longValue(); // Always returns a result
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countNewOrKeyrecByHardTokenIssuerId(int hardTokenIssuerId) {
        final javax.persistence.Query query = entityManager
                .createQuery("SELECT COUNT(a) FROM UserData a WHERE a.hardTokenIssuerId=:hardTokenIssuerId AND a.tokenType>=:tokenType AND (a.status=:status1 OR a.status=:status2)");
        query.setParameter("hardTokenIssuerId", hardTokenIssuerId);
        query.setParameter("tokenType", SecConst.TOKEN_HARD_DEFAULT);
        query.setParameter("status1", EndEntityConstants.STATUS_NEW);
        query.setParameter("status2", EndEntityConstants.STATUS_KEYRECOVERY);
        return ((Long) query.getSingleResult()).longValue(); // Always returns a result
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findAllBatchUsersByStatusWithLimit(int status) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByStatusWithLimit()");
        }
        final javax.persistence.Query query = entityManager
                .createQuery("SELECT a FROM UserData a WHERE a.status=:status AND (clearPassword IS NOT NULL)");
        query.setParameter("status", status);
        query.setMaxResults(getGlobalCesecoreConfiguration().getMaximumQueryCount());
        @SuppressWarnings("unchecked")
        final List<UserData> userDataList = query.getResultList();
        final List<EndEntityInformation> returnval = new ArrayList<EndEntityInformation>(userDataList.size());
        for (UserData ud : userDataList) {
            EndEntityInformation endEntityInformation = ud.toEndEntityInformation();
            if (endEntityInformation.getPassword() != null && endEntityInformation.getPassword().length() > 0) {
                returnval.add(endEntityInformation);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByStatusWithLimit()");
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<EndEntityInformation> query(final AuthenticationToken admin, final Query query, final String caauthorizationstr,
            final String endentityprofilestr, final int numberofrows, final String endentityAccessRule) throws IllegalQueryException {
        boolean authorizedtoanyprofile = true;
        final String caauthorizationstring = StringTools.strip(caauthorizationstr);
        final String endentityprofilestring = StringTools.strip(endentityprofilestr);
        final ArrayList<EndEntityInformation> returnval = new ArrayList<EndEntityInformation>();
        int fetchsize = getGlobalCesecoreConfiguration().getMaximumQueryCount();

        if (numberofrows != 0) {
            fetchsize = numberofrows;
        }

        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        String sqlquery = "";
        if (query != null) {
            sqlquery += query.getQueryString();
        }

        final GlobalConfiguration globalconfiguration = getGlobalConfiguration();
        String caauthstring = caauthorizationstring;
        String endentityauth = endentityprofilestring;
        RAAuthorization raauthorization = null;
        if (caauthorizationstring == null || endentityprofilestring == null) {
            raauthorization = new RAAuthorization(admin, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
            caauthstring = raauthorization.getCAAuthorizationString();
            if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                endentityauth = raauthorization.getEndEntityProfileAuthorizationString(true, endentityAccessRule);
            } else {
                endentityauth = "";
            }
        }
        if (!StringUtils.isBlank(caauthstring)) {
            if (StringUtils.isBlank(sqlquery)) {
                sqlquery += caauthstring;
            } else {
                sqlquery = "(" + sqlquery + ") AND " + caauthstring;
            }
        } 
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (endentityauth == null || StringUtils.isBlank(endentityauth)) {
                authorizedtoanyprofile = false;
            } else {
                if (StringUtils.isEmpty(sqlquery)) {
                    sqlquery += endentityauth;
                } else {
                    sqlquery = "(" + sqlquery + ") AND " + endentityauth;
                }
            }
        }
        // Finally order the return values
        sqlquery += " ORDER BY " + USERDATA_CREATED_COL + " DESC";
        if (log.isDebugEnabled()) {
            log.debug("generated query: " + sqlquery);
        }
        if (authorizedtoanyprofile) {
            final javax.persistence.Query dbQuery = entityManager.createQuery("SELECT a FROM UserData a WHERE " + sqlquery);
            if (fetchsize > 0) {
                dbQuery.setMaxResults(fetchsize);
            }
            @SuppressWarnings("unchecked")
            final List<UserData> userDataList = dbQuery.getResultList();
            for (UserData userData : userDataList) {
                returnval.add(userData.toEndEntityInformation());
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("authorizedtoanyprofile=false");
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<query(): " + returnval.size());
        }
        return returnval;
    }

    private GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
        return (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    }

    /** Gets the Global Configuration from ra admin session bean */
    private GlobalConfiguration getGlobalConfiguration() {
        return (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }    
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<EndEntityInformation> findAllUsersWithLimit(AuthenticationToken admin) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersWithLimit()");
        }
        Collection<EndEntityInformation> returnval = null;
        try {
            returnval = query(admin, null, null, null, 0, AccessRulesConstants.VIEW_END_ENTITY);
        } catch (IllegalQueryException e) {
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersWithLimit()");
        }
        return returnval;
    }
 
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findAllUsersByCaIdNoAuth(int caid) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByCaIdNoAuth()");
        }
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.caId=:caId", UserData.class);
        query.setParameter("caId", caid);
        final List<UserData> userDataList = query.getResultList();
        final List<EndEntityInformation> returnval = new ArrayList<EndEntityInformation>(userDataList.size());
        for (UserData ud : userDataList) {
            returnval.add(ud.toEndEntityInformation());
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByCaIdNoAuth()");
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<UserData> findByEndEntityProfileId(int endentityprofileid) {
        if (log.isTraceEnabled()) {
            log.trace(">findByEndEntityProfileId(" + endentityprofileid + ")");
        }
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.endEntityProfileId=:endEntityProfileId", UserData.class);
        query.setParameter("endEntityProfileId", endentityprofileid);
        List<UserData> found = query.getResultList();        
        if (log.isTraceEnabled()) {
            log.trace("<findByEndEntityProfileId(" + endentityprofileid + "), found: " + found.size());
        }
        return found;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> findByCertificateProfileId(int certificateprofileid) {
        if (log.isTraceEnabled()) {
            log.trace(">checkForCertificateProfileId("+certificateprofileid+")");
        }
        final javax.persistence.Query query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.certificateProfileId=:certificateProfileId");
        query.setParameter("certificateProfileId", certificateprofileid);

        List<String> result = new ArrayList<String>();
        for(Object userDataObject : query.getResultList()) {
                result.add(((UserData) userDataObject).getUsername());
        }
        if (log.isTraceEnabled()) {
            log.trace("<checkForCertificateProfileId("+certificateprofileid+"): "+result.size());
        }
        return result;
        
    }

}
