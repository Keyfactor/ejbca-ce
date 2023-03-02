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

package org.ejbca.core.ejb.ca.auth;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.audit.log.dto.SecurityEventProperties;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.CertTools;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Authenticates users towards a user database.
 * @see EndEntityAuthenticationSession
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityAuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityAuthenticationSessionBean implements EndEntityAuthenticationSessionLocal, EndEntityAuthenticationSessionRemote {
    private static final Logger log = Logger.getLogger(EndEntityAuthenticationSessionBean.class);
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    private GlobalConfiguration getGlobalConfiguration() {
        return (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @Override
    public EndEntityInformation authenticateUser(final AuthenticationToken admin, final String username, final String password)
        throws AuthStatusException, AuthLoginException, NoSuchEndEntityException {
    	if (log.isTraceEnabled()) {
            log.trace(">authenticateUser(" + username + ", hiddenpwd)");
    	}
    	boolean eichange = false;
        try {
            // Find the user with username username, or throw ObjectNotFoundException
            final UserData data = endEntityAccessSession.findByUsername(username);
            if (data == null) {
            	throw new NoSuchEndEntityException("Could not find username " + username);
            }
            // Decrease the remaining login attempts. When zero, the status is set to STATUS_GENERATED
            ExtendedInformation ei = data.getExtendedInformation();
           	eichange = decRemainingLoginAttempts(data, ei);
           	boolean authenticated = false;
           	final int status = data.getStatus();
            if (isAllowedToEnroll(admin, username)) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to authenticate user: username="+username+", dn="+data.getSubjectDnNeverNull()+", email="+data.getSubjectEmail()+", status="+status+", type="+data.getType());
            	}
                if (!data.comparePassword(password)) {
                	final String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                    final Map<String, Object> details = new LinkedHashMap<>();
                    details.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.CA_USERAUTH, EventStatus.FAILURE, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(data.getCaId()), null, username, details);
                    if (eichange) {
                        data.setTimeModified(new Date().getTime());
                        data.setExtendedInformation(ei);
                    }
                	throw new AuthLoginException(ErrorCode.LOGIN_ERROR, msg);
                }
                // Resets the remaining login attempts as this was a successful login
                if (UserData.resetRemainingLoginAttemptsInternal(ei, data.getUsername())) {
                    // This call can never set eichange to false, only to true (because it is already false if it should be)
                    eichange = true;
                }
            	// Log formal message that authentication was successful
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", intres.getLocalizedMessage("authentication.authok", username));
                auditSession.log(EjbcaEventTypes.CA_USERAUTH, EventStatus.SUCCESS, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(data.getCaId()), null, username, details);
            	if (log.isTraceEnabled()) {
                    log.trace("<authenticateUser("+username+", hiddenpwd)");
            	}
            	authenticated = true;
            }
            if (eichange) {
                data.setTimeModified(new Date().getTime());
                data.setExtendedInformation(ei);
            }
            if (authenticated) {
                return data.toEndEntityInformation();
            } else {
                final String msg = intres.getLocalizedMessage("authentication.wrongstatus", EndEntityConstants.getStatusText(status), status, username);
                log.info(msg);
                throw new AuthStatusException(msg);
            }
        } catch (NoSuchEndEntityException oe) {
        	final String msg = intres.getLocalizedMessage("authentication.usernotfound", username);
        	log.info(msg);
            throw oe;
        } catch (AuthStatusException | AuthLoginException se) {
            throw se;
        }  catch (Exception e) {
            log.error(intres.getLocalizedMessage("error.unknown"), e);
            throw new EJBException(e);
        }
    }

    /**
     * Decrements the remaining failed login attempts counter. If the counter
     * already was zero the status for the user is set to
     * {@link EndEntityConstants#STATUS_GENERATED} if it wasn't that already.
     * This method does nothing if the counter value is set to UNLIMITED (-1).
     *
     * @param user the unique username of the user
     * @param ei extended information of the user
     * @return true if the value was decremented or the status was changed, false if not
     */
    public boolean decRemainingLoginAttempts(UserData user, ExtendedInformation ei) {
        if (log.isTraceEnabled()) {
            log.trace(">decRemainingLoginAttempts(" + user.getUsername()+ ")");
        }
        boolean ret = false;
        int counter = Integer.MAX_VALUE;
        if (ei != null) {
            counter = ei.getRemainingLoginAttempts();
            // If we get to 0 we must set status to generated
            if (counter == 0) {
                // if it isn't already
                if (user.getStatus() != EndEntityConstants.STATUS_GENERATED) {
                    user.setStatus(EndEntityConstants.STATUS_GENERATED);
                    user.setTimeModified(new Date().getTime());
                    if (UserData.resetRemainingLoginAttemptsInternal(ei, user.getUsername())) {
                        final String msg = intres.getLocalizedMessage("ra.decreasedloginattemptscounter", user.getUsername(), counter);
                        log.info(msg);
                        // We return that ei was changed so it can be persisted later
                        ret = true;
                    }
                }
            } else if (counter != -1) {
                if (log.isDebugEnabled()) {
                    log.debug("Found a remaining login counter with value " + counter);
                }
                ei.setRemainingLoginAttempts(--counter);
                // We return ei to set later
                // We return that ei was changed so it can be persisted later
                ret = true;
                String msg = intres.getLocalizedMessage("ra.decreasedloginattemptscounter", user.getUsername(), counter);
                log.info(msg);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found a remaining login counter with value UNLIMITED, not decreased in db.");
                }
                counter = Integer.MAX_VALUE;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<decRemainingLoginAttempts(" + user.getUsername() + "): " + counter);
        }
        return ret;
    }

    @Override
    public boolean verifyPassword(AuthenticationToken authenticationToken, String username, String password, boolean decRemainingLoginAttemptsOnFailure) throws NoSuchEndEntityException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">verifyPassword(" + username + ", hiddenpwd)");
        }
        boolean ret;
        // Find user
        final UserData data = endEntityAccessSession.findByUsername(username);
        if (data == null) {
            throw new NoSuchEndEntityException("Could not find user " + username);
        }
        if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to edit user.
            assertAuthorizedToEndEntityProfile(authenticationToken, data.getEndEntityProfileId(), AccessRulesConstants.EDIT_END_ENTITY, data.getCaId());
        }
        assertAuthorizedToCA(authenticationToken, data.getCaId());
        try {
            ret = data.comparePassword(password);
            if (!ret && decRemainingLoginAttemptsOnFailure) {
                // If verification fails, and the caller want to, try to decrease remaining login attempts
                final ExtendedInformation ei = data.getExtendedInformation();
                if (decRemainingLoginAttempts(data, ei)) {
                    data.setTimeModified(new Date().getTime());
                    data.setExtendedInformation(ei);
                }
            }
        } catch (NoSuchAlgorithmException nsae) {
            log.debug("NoSuchAlgorithmException while verifying password for user " + username);
            throw new EJBException(nsae);
        }
        if (log.isTraceEnabled()) {
            log.trace("<verifyPassword(" + username + ", hiddenpwd)");
        }
        return ret;
    }

    @Override
    public boolean isAllowedToEnroll(final AuthenticationToken admin, final String username) {
        final UserData userdata = endEntityAccessSession.findByUsername(username);
        if (userdata == null) {
            return false;
        }
        // Quick access check, to ensure that user has some kind of access to the EE.
        // But we can't require view_end_entity here, because this call happens during enrollment.
        if (!authorizedToCA(admin, userdata.getCaId())) {
            return false;
        }
        final int status = userdata.getStatus();
        if (status == EndEntityConstants.STATUS_NEW || status == EndEntityConstants.STATUS_FAILED ||
                status == EndEntityConstants.STATUS_INPROCESS || status == EndEntityConstants.STATUS_KEYRECOVERY) {
            return true;
        } else if (status == EndEntityConstants.STATUS_GENERATED) {
            // Renewal might be allowed
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(userdata.getEndEntityProfileId());
            if (eep == null) {
                log.warn("End Entity Profile with ID " + userdata.getEndEntityProfileId() + " doesn't exist. Username: " + username);
            } else if (eep.isRenewDaysBeforeExpirationUsed()) {
                final long maximumExpirationDate = System.currentTimeMillis() + eep.getRenewDaysBeforeExpiration()*24*60*60*1000;
                Date maxDate = new Date(maximumExpirationDate);
                final Date now = new Date();
                final Collection<Certificate> certs = certificateStoreSession.findCertificatesByUsernameAndStatusAfterExpireDate(
                        username, CertificateConstants.CERT_ACTIVE, now.getTime());
                for (final Certificate cert : certs) {
                    if (maxDate.after(CertTools.getNotAfter(cert))) {
                        return true;
                    }
                }
                if (log.isDebugEnabled()) {
                    if (certs.isEmpty()) {
                        log.debug("End entity is in status GENERATED but has no certificates. Not allowing renewal. Username: " + username);
                    } else {
                        log.debug("Certificates of end entity will expire after allowed period. Not allowing renewal. Username: " + username);
                    }
                }
            } else if (log.isDebugEnabled()) {
                log.debug("Enrollment is not allowed for end entity with status GENERATED. Username: " + username);
            }
        } else if (log.isDebugEnabled()) {
            log.debug("Enrollment is not allowed with end entity status " + status + ". Username: " + username);
        }
        return false;
    }

    @Override
    public boolean isAuthorizedToEndEntityProfile(AuthenticationToken admin, int profileId, String rights) {
        return authorizationSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileId + rights, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    }

    @Override
    public void assertAuthorizedToEndEntityProfile(final AuthenticationToken authenticationToken, final int endEntityProfileId, final String accessRule, final int caId) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + accessRule, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + accessRule)) {
            final String msg = intres.getLocalizedMessage("ra.errorauthprofile", endEntityProfileId, authenticationToken.toString());
            auditSession.log(
                    EventTypes.ACCESS_CONTROL, EventStatus.FAILURE,
                    EjbcaModuleTypes.RA, ServiceTypes.CORE,
                    authenticationToken.toString(),
                    String.valueOf(caId), null, null,
                    SecurityEventProperties.builder().withMsg(msg).build().toMap()
            );
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public void assertAuthorizedToCA(final AuthenticationToken authenticationToken, final int caId) throws AuthorizationDeniedException {
        if (!authorizedToCA(authenticationToken, caId)) {
            final String msg = intres.getLocalizedMessage("ra.errorauthca", caId, authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public boolean authorizedToCA(final AuthenticationToken authenticationToken, final int caId) {
        boolean returnval = authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId);
        if (!returnval) {
            log.info("Admin " + authenticationToken.toString() + " not authorized to resource " + StandardRules.CAACCESS.resource() + caId);
        }
        return returnval;
    }
}
