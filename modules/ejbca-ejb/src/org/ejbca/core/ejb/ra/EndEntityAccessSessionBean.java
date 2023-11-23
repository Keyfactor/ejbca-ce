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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.transaction.TransactionSynchronizationRegistry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.DnComponents;

/**
 * An {@link EndEntityInformation} Data Access Object (DAO).
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityAccessSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EndEntityAccessSessionBean implements EndEntityAccessSessionLocal, EndEntityAccessSessionRemote {

    private static final String USER_DATA_NATIVE_QUERY = "SELECT username, subjectDN, caId, subjectAltName, cardNumber, subjectEmail, "
            + "status, type, clearPassword, passwordHash, timeCreated, timeModified, endEntityProfileId, certificateProfileId, "
            + "tokenType, extendedInformationData, hardTokenIssuerId, keyStorePassword, rowVersion, rowProtection "
            + "FROM UserData";

    /** Columns in the database used in select. */
    private static final String USERDATA_CREATED_COL = "timeCreated";

    private static final Logger log = Logger.getLogger(EndEntityAccessSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    @Resource
    private TransactionSynchronizationRegistry registry;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    private PerTransactionData perTransactionData;

    @PostConstruct
    public void postConstruct() {
        perTransactionData = new PerTransactionData(registry);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm> getPasswordAndHashAlgorithmForUser(String username)
            throws NotFoundException {
        UserData user = findByUsername(username);
        if (user == null) {
            throw new NotFoundException("End Entity of name " + username + " not found in database");
        } else {
            return new AbstractMap.SimpleEntry<>(user.getPasswordHash(), user.findHashAlgorithm());
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findUserBySubjectDN(final AuthenticationToken admin, final String subjectdn)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserBySubjectDN(" + LogRedactionUtils.getSubjectDnLogSafe(subjectdn)+ ")");
        }
        // String used in SQL so strip it
        final String dn = DnComponents.stringToBCDNString(StringTools.strip(subjectdn));
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with subjectdn: " + LogRedactionUtils.getSubjectDnLogSafe(dn));
        }
        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN", UserData.class);
        query.setParameter("subjectDN", dn);
        final List<UserData> dataList =  query.getResultList();

        if (dataList.isEmpty() && log.isDebugEnabled()) {
            log.debug("Cannot find user with subjectdn: " + LogRedactionUtils.getSubjectDnLogSafe(dn));
        }
        final List<EndEntityInformation> result = getEndEntityInformation(admin, dataList);
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectDN(" + LogRedactionUtils.getSubjectDnLogSafe(subjectdn) + ")");
        }
        return result;
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
            log.trace(">findUserBySubjectAndIssuerDN(" + LogRedactionUtils.getSubjectDnLogSafe(subjectdn) + ", " + issuerdn + ")");
        }
        // String used in SQL so strip it
        final String dn = DnComponents.stringToBCDNString(StringTools.strip(subjectdn));
        final String issuerDN = DnComponents.stringToBCDNString(StringTools.strip(issuerdn));
        if (log.isDebugEnabled()) {
            log.debug("Looking for users with subjectdn: " + LogRedactionUtils.getSubjectDnLogSafe(dn) + ", issuerdn : " + issuerDN);
        }

        final TypedQuery<UserData> query = entityManager.createQuery("SELECT a FROM UserData a WHERE a.subjectDN=:subjectDN AND a.caId=:caId", UserData.class);
        query.setParameter("subjectDN", dn);
        query.setParameter("caId", issuerDN.hashCode());
        final List<UserData> dataList = query.getResultList();
        if (dataList.isEmpty() && log.isDebugEnabled()) {
            log.debug("Cannot find user with subjectdn: " + LogRedactionUtils.getSubjectDnLogSafe(dn) + ", issuerdn : " + issuerDN);
        }
        final List<EndEntityInformation> result = getEndEntityInformation(admin, dataList);
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectAndIssuerDN(" + LogRedactionUtils.getSubjectDnLogSafe(subjectdn) + ", " + issuerDN + ")");
        }
        return result;
    }

    private List<EndEntityInformation> getEndEntityInformation(AuthenticationToken admin, List<UserData> dataList)
            throws AuthorizationDeniedException {
        final List<EndEntityInformation> result = new ArrayList<>();
        for (UserData data : dataList) {
            result.add(convertUserDataToEndEntityInformation(admin, data, null,
                    authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_END_ENTITY)));
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
        final String trimmedUsername = StringTools.trim(username);
        if (log.isTraceEnabled()) {
            log.trace(">findUser(" + trimmedUsername + ")");
        }
        final UserData data = findByUsername(trimmedUsername);
        if (data == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with username='" + trimmedUsername + "'");
            }
            return null;
        }
        final EndEntityInformation ret = convertUserDataToEndEntityInformation(admin, data, trimmedUsername,
                authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_END_ENTITY));
        if (log.isTraceEnabled()) {
            log.trace("<findUser(" + trimmedUsername + "): " + (ret == null ? "null" : ret.getLogSafeSubjectDn()));
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityInformation findUserWithoutViewEndEntityAccessRule(final AuthenticationToken admin, final String username) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserWithoutViewEndEntityAccessRule(" + username + ")");
        }
        final UserData data = findByUsername(username);
        if (data == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot find user with username='" + username + "'");
            }
            return null;
        }
        final EndEntityInformation ret = convertUserDataToEndEntityInformation(admin, data, username,
                authorizedToEndEntityProfileForRaWebCertificateCreation(admin, data.getEndEntityProfileId()));
        if (log.isTraceEnabled()) {
            log.trace("<findUserWithoutViewEndEntityAccessRule(" + username + "): " + (ret == null ? "null" : ret.getLogSafeSubjectDn()));
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public UserData findByUsername(final String username) {
        if (username == null) {
            return null;
        }
        if (perTransactionData.isInTransaction()) {
            final UserData pendingUser = perTransactionData.getPendingUserData(username); // Pending addition in the current transaction
            if (pendingUser != null) {
                if (log.isDebugEnabled()) {
                    log.debug("User '" + username + "' is a pending addition / has a pending modification.");
                }
                return pendingUser;
            }
        }
        return entityManager.find(UserData.class, StringTools.trim(username));
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
        if (result.isEmpty() && log.isDebugEnabled()) {
            log.debug("Cannot find user with Email='" + email + "'");
        }
        final List<EndEntityInformation> returnval = new ArrayList<>();
        for (final UserData data : result) {
            boolean isAuthorizedToEndEntityProfile = authorizedToEndEntityProfile(admin,
                    data.getEndEntityProfileId(), AccessRulesConstants.VIEW_END_ENTITY);

            if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                    .getEnableEndEntityProfileLimitations()) {
                // Check if administrator is authorized to view user.
                if (!isAuthorizedToEndEntityProfile) {
                    continue;
                }
            }
            if (!authorizedToCA(admin, data.getCaId())) {
                continue;
            }
            returnval.add(convertUserDataToEndEntityInformation(admin, data, null, isAuthorizedToEndEntityProfile));

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
        final String requestedUsername, boolean authorizationPrecondition) throws AuthorizationDeniedException {
        if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID))
                .getEnableEndEntityProfileLimitations() && (!authorizationPrecondition)) {
            final String msg;
            if (requestedUsername == null) {
                msg = intres.getLocalizedMessage("ra.errorauthprofile", data.getEndEntityProfileId(), admin.toString());
            } else {
                msg = intres.getLocalizedMessage("ra.errorauthprofileexist", data.getEndEntityProfileId(),
                        requestedUsername, admin.toString());
            }
            throw new AuthorizationDeniedException(msg);

        }
        if (!authorizedToCA(admin, data.getCaId())) {
            final String msg;
            if (requestedUsername == null) {
                msg = intres.getLocalizedMessage("ra.errorauthca", data.getCaId(), admin.toString());
            } else {
                msg = intres.getLocalizedMessage("ra.errorauthcaexist", data.getCaId(), requestedUsername,
                        admin.toString());
            }
            throw new AuthorizationDeniedException(msg);
        }
        return data.toEndEntityInformation();
    }

    private boolean authorizedToEndEntityProfile(AuthenticationToken admin, int profileId, String rights) {
        boolean returnval = false;
        if (profileId == EndEntityConstants.EMPTY_END_ENTITY_PROFILE
                && (rights.equals(AccessRulesConstants.CREATE_END_ENTITY) || rights.equals(AccessRulesConstants.EDIT_END_ENTITY))) {
            if (authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                returnval = true;
            } else {
                log.info("Admin " + admin.toString() + " was not authorized to resource " + StandardRules.ROLE_ROOT);
            }
        } else {
            returnval = authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileId + rights,
                    AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
        return returnval;
    }

    private boolean authorizedToEndEntityProfileForRaWebCertificateCreation(AuthenticationToken admin, int profileid) {
            // We need to have access to the profile, but not any specific access.
            // With only "AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid", it would require full access.
            // So we accept any of /endentityprofilerules/.../(create|view|edit)_end_entity/
            // (The access rules /ra_functions/(create|view|edit)_end_entity/ are NOT required)
        return authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.CREATE_END_ENTITY) ||
                    authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.VIEW_END_ENTITY) ||
                    authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.EDIT_END_ENTITY);
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
            log.debug("Query is illegal: " + e);
        }
        if (log.isDebugEnabled() && Objects.nonNull(returnval)) {
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
        Collection<EndEntityInformation> returnval;
        try {
            returnval = query(admin, query, null, null, 0, AccessRulesConstants.VIEW_END_ENTITY);
        } catch (IllegalQueryException e) {
            // Ignore ??
            log.debug("Illegal query", LogRedactionUtils.getRedactedException(e));
            returnval = new ArrayList<>();
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
        return (Long) query.getSingleResult(); // Always returns a result
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public long countByCertificateProfileId(int certificateProfileId) {
        final javax.persistence.Query query = entityManager.createQuery("SELECT COUNT(a) FROM UserData a WHERE a.certificateProfileId=:certificateProfileId");
        query.setParameter("certificateProfileId", certificateProfileId);
        return (Long) query.getSingleResult(); // Always returns a result
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findAllBatchUsersByStatusWithLimit(int status) {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByStatusWithLimit(): " + status);
        }
        final javax.persistence.Query query = entityManager
                .createQuery("SELECT a FROM UserData a WHERE a.status=:status AND (clearPassword IS NOT NULL)");
        query.setParameter("status", status);
        query.setMaxResults(getGlobalCesecoreConfiguration().getMaximumQueryCount());
        @SuppressWarnings("unchecked")
        final List<UserData> userDataList = query.getResultList();
        final List<EndEntityInformation> returnval = new ArrayList<>(userDataList.size());
        for (UserData ud : userDataList) {
            EndEntityInformation endEntityInformation = ud.toEndEntityInformation();
            if (endEntityInformation.getPassword() != null && endEntityInformation.getPassword().length() > 0) {
                returnval.add(endEntityInformation);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByStatusWithLimit(): " + returnval.size());
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<EndEntityInformation> queryOptimized(AuthenticationToken admin, Query query, int numberofrows,
            String endentityAccessRule) throws IllegalQueryException {
        final ArrayList<EndEntityInformation> returnval = new ArrayList<>();
        int fetchsize = getGlobalCesecoreConfiguration().getMaximumQueryCount();

        if (numberofrows != 0) {
            fetchsize = numberofrows;
        }

        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        String sqlquery = constructInitial(StringUtils.EMPTY, query);

        // Finally order the return values
        sqlquery += " ORDER BY " + USERDATA_CREATED_COL + " DESC";
        if (log.isDebugEnabled()) {
            log.debug("generated query: " + LogRedactionUtils.getRedactedMessage(sqlquery));
        }
            final javax.persistence.Query dbQuery = entityManager.createQuery("SELECT a FROM UserData a WHERE " + sqlquery);
            if (fetchsize > 0) {
                dbQuery.setMaxResults(fetchsize);
            }
            @SuppressWarnings("unchecked")
            final List<UserData> userDataList = dbQuery.getResultList();
            for (UserData userData : userDataList) {
                returnval.add(userData.toEndEntityInformation());
            }
        if (log.isTraceEnabled()) {
            log.trace("<query(): " + returnval.size());
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @SuppressWarnings({ "unchecked" })
    @Override
    public Collection<EndEntityInformation> query(AuthenticationToken admin, Query query, String caAuthorization,
            String endEntityProfile, int numberOfRows, String endEntityAccessRule) throws IllegalQueryException {
        boolean authorizedToAnyProfile = true;

        int fetchSize = getGlobalCesecoreConfiguration().getMaximumQueryCount();

        if (numberOfRows != 0) {
            fetchSize = numberOfRows;
        }

        UserDataQueryResult userDataQuery = constructUserDataQuery(query, caAuthorization, endEntityProfile,
                admin, endEntityAccessRule, authorizedToAnyProfile);
		if (!userDataQuery.authorizedToAnyProfile) {
			if (log.isDebugEnabled()) {
				log.debug("authorizedToAnyProfile = false");
			}
			return List.of();
		}

		javax.persistence.Query dbQuery = entityManager.createNativeQuery(USER_DATA_NATIVE_QUERY +
                " WHERE " + userDataQuery.getWhereValue(), UserData.class);
		if (fetchSize > 0) {
			dbQuery.setMaxResults(fetchSize);
		}

		return (List<EndEntityInformation>) dbQuery.getResultList()
                    .stream()
                    .map(userData -> ((UserData) userData).toEndEntityInformation())
                    .map(EndEntityInformation.class::cast)
                    .collect(Collectors.toList());
    }

	protected UserDataQueryResult constructUserDataQuery(Query query, String caAuthorization, String endEntityProfile,
			AuthenticationToken admin, String endEntityAccessRule, boolean authorizedToAnyProfile)
			throws IllegalQueryException {
		String caAuthorizationStripped = StringTools.strip(caAuthorization);
		String endEntityProfileStripped = StringTools.strip(endEntityProfile);

		if (query != null && !query.isLegalQuery()) {
			log.error("The following query: " + LogRedactionUtils.getRedactedMessage(query.getQueryString()) + " appeared to be an illegal one");
			throw new IllegalQueryException();
		}

        String whereClause = constructInitial(StringUtils.EMPTY, query);

        GlobalConfiguration globalconfiguration = getGlobalConfiguration();

		String caAuth = getCaAuth(caAuthorizationStripped, endEntityProfileStripped, admin);

		String endEntityAuth = getEndEntityAuth(caAuthorizationStripped, endEntityProfileStripped, admin,
				globalconfiguration, endEntityAccessRule);

		if (!StringUtils.isBlank(caAuth)) {
			whereClause = appendIfNotBlank(whereClause, caAuth);
		}

		return appendResultingQuery(authorizedToAnyProfile, whereClause, endEntityAuth, globalconfiguration);
	}

    private String constructInitial(String empty, Query query) {
        String whereClause = empty;
        if (query != null) {
            whereClause += query.getQueryString();
        }
        return whereClause;
    }

    private UserDataQueryResult appendResultingQuery(boolean authorizedToAnyProfile, String whereClause,
            String endEntityAuth, GlobalConfiguration globalConfiguration) {

        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            if (endEntityAuth == null || StringUtils.isBlank(endEntityAuth)) {
                authorizedToAnyProfile = false;
            } else {
                whereClause = appendIfNotBlank(whereClause, endEntityAuth);
            }
        }
        whereClause += (" ORDER BY " + USERDATA_CREATED_COL + " DESC");

        return new UserDataQueryResult(whereClause, authorizedToAnyProfile);
    }

    private String getEndEntityAuth(String caAuthorizationStripped, String endEntityProfileStripped,
			AuthenticationToken admin, GlobalConfiguration globalconfiguration, String endEntityAccessRule) {
        if (caAuthorizationStripped == null || endEntityProfileStripped == null) {
            RAAuthorization raAuthorization = getRaAuthorization(admin);
            return getEndEntityAuth(endEntityAccessRule, globalconfiguration, raAuthorization);
        }
        return endEntityProfileStripped;
    }

    private String getCaAuth(String caAuthorizationStripped, String endEntityProfileStripped, AuthenticationToken admin) {
        if (caAuthorizationStripped == null || endEntityProfileStripped == null) {
            RAAuthorization raAuthorization = getRaAuthorization(admin);
            return raAuthorization.getCAAuthorizationString();
        }
        return caAuthorizationStripped;
    }

    private RAAuthorization getRaAuthorization(AuthenticationToken admin) {
        return new RAAuthorization(admin, globalConfigurationSession, authorizationSession, caSession,
                endEntityProfileSession);
    }

    private String getEndEntityAuth(String endEntityAccessRule,
            GlobalConfiguration globalconfiguration, RAAuthorization raAuthorization) {
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            return raAuthorization.getEndEntityProfileAuthorizationString(true, endEntityAccessRule);
        }
        return StringUtils.EMPTY;
    }

    private String appendIfNotBlank(String clause, String toAppend) {

        if (StringUtils.isBlank(clause)) {
            clause += toAppend;
        } else {
            clause = "(" + clause + ") AND " + toAppend;
        }
        return clause;
    }

    protected static final class UserDataQueryResult {

        private final String whereClause;
        private final boolean authorizedToAnyProfile;

        public UserDataQueryResult(String whereClause, boolean authorizedToAnyProfile) {
            this.whereClause = whereClause;
            this.authorizedToAnyProfile = authorizedToAnyProfile;
        }

        public String getWhereValue() {
            return whereClause;
        }

        public boolean isAuthorizedToAnyProfile() {
            return authorizedToAnyProfile;
        }
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
            log.debug("Query is illegal: " + LogRedactionUtils.getRedactedException(e));
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
        final List<EndEntityInformation> returnval = new ArrayList<>(userDataList.size());
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

        List<String> result = new ArrayList<>();
        for(Object userDataObject : query.getResultList()) {
                result.add(((UserData) userDataObject).getUsername());
        }
        if (log.isTraceEnabled()) {
            log.trace("<checkForCertificateProfileId("+certificateprofileid+"): "+result.size());
        }
        return result;

    }

    @Override
    public CertificateWrapper getCertificate(AuthenticationToken authenticationToken, String certSNinHex, String issuerDN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        final String bcString = DnComponents.stringToBCDNString(issuerDN);
        final int caId = bcString.hashCode();
        caSession.verifyExistenceOfCA(caId);
        final String[] rules = {StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate", StandardRules.CAACCESS.resource() + caId};
        if(!authorizationSession.isAuthorizedNoLogging(authenticationToken, rules)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", Arrays.toString(rules), null);
            throw new AuthorizationDeniedException(msg);
        }
        final Certificate result = certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, new BigInteger(certSNinHex,16));
        if (log.isDebugEnabled()) {
            log.debug("Found certificate for issuer '" + issuerDN + "' and SN " + certSNinHex + " for admin " + authenticationToken.getUniqueId());
        }
        return EJBTools.wrap(result);
    }

    @Override
    public Collection<CertificateWrapper> findCertificatesByUsername(final AuthenticationToken authenticationToken, final String username, final boolean onlyValid, final long now)
            throws AuthorizationDeniedException, CertificateEncodingException {
        if (log.isDebugEnabled()) {
            log.debug( "Find certificates by username requested by " + authenticationToken.getUniqueId());
        }
        // Check authorization on current CA and profiles and view_end_entity by looking up the end entity.
        if (findUser(authenticationToken, username) == null && log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("ra.errorentitynotexist", username));
        }
        // Even if there is no end entity, it might be the case that we don't store UserData, so we still need to check CertificateData.
        Collection<CertificateWrapper> searchResults;
        if (onlyValid) {
            // We will filter out not yet valid certificates later on, but we use the database to not return any expired certificates
            searchResults = EJBTools.wrapCertCollection(certificateStoreSession.findCertificatesByUsernameAndStatusAfterExpireDate(username, CertificateConstants.CERT_ACTIVE, now));
            // "active" certificates include two statuses, CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION, this is a bit of tricky corner case unfortunately
            searchResults.addAll(EJBTools.wrapCertCollection(certificateStoreSession.findCertificatesByUsernameAndStatusAfterExpireDate(username, CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION, now)));
        } else {
            searchResults = certificateStoreSession.findCertificatesByUsername(username);
        }
        // Assume the user may have certificates from more than one CA.
        Certificate certificate = null;
        int caId = -1;
        Boolean authorized = null;
        final Map<Integer, Boolean> authorizationCache = new HashMap<>();
        final List<CertificateWrapper> result = new ArrayList<>();
        for (final CertificateWrapper searchResult: searchResults) {
            certificate = searchResult.getCertificate();
            caId = CertTools.getIssuerDN(certificate).hashCode();
            authorized = authorizationCache.get(caId);
            if (authorized == null) {
                authorized = authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId);
                authorizationCache.put(caId, authorized);
            }
            if (Boolean.TRUE.equals(authorized)) {
                result.add(searchResult);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug( "Found " + result.size() + " certificate(s) by username requested by " + authenticationToken.getUniqueId());
        }
        return result;
    }


}
