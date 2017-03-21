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

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionLocal;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleInitializationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleInitializationSessionBean implements RoleInitializationSessionRemote {

    private static final Logger log = Logger.getLogger(RoleInitializationSessionBean.class);
    
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
	@EJB
	private SimpleAuthenticationProviderSessionLocal simpleAuthenticationProviderSession;
	
	@Override
    public void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate) throws RoleExistsException, RoleNotFoundException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
        final HashMap<String,Boolean> accessRules = new HashMap<>();
        accessRules.put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
        final Role role = roleSession.persistRole(authenticationToken, new Role(null, roleName, accessRules));
        roleMemberSession.persist(authenticationToken, new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED,
                X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                CertTools.getIssuerDN(certificate).hashCode(),
                X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASEINS.getNumericValue(),
                CertTools.getSerialNumber(certificate).toString(16),
                role.getRoleId(),
                null, null));
        if (log.isTraceEnabled()) {
            log.trace("<initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
    }

    @Override
    public void createRoleAndAddCertificateAsRoleMember(final X509Certificate x509Certificate, final String roleNameSpace, final String roleName,
            final List<String> resourcesAllowed, final List<String> resourcesDenied) throws RoleExistsException {
        final AuthenticationToken alwaysAllowAuthenticationToken = new AlwaysAllowLocalAuthenticationToken("createAuthenticationTokenAndAssignToNewRole - " + roleName);
        // Define initial access rules
        final HashMap<String,Boolean> initialAccessRules = new HashMap<>();
        if (resourcesAllowed!=null) {
            for (final String resource : resourcesAllowed) {
                initialAccessRules.put(resource, Role.STATE_ALLOW);
            }
        }
        if (resourcesDenied!=null) {
            for (final String resource : resourcesDenied) {
                initialAccessRules.put(resource, Role.STATE_DENY);
            }
        }
        if (resourcesAllowed==null && resourcesDenied==null) {
            initialAccessRules.put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
        }
        // Setup Role and RoleMember matching by certificate serial number
        try {
            // Clean up old left overs from a failed previous run
            final Role oldRole = roleSession.getRole(alwaysAllowAuthenticationToken, null, roleName);
            if (oldRole!=null) {
                roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, oldRole.getRoleId());
            }
            final Role role = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(roleNameSpace, roleName, initialAccessRules));
            roleMemberSession.persist(alwaysAllowAuthenticationToken, new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED,
                    X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    CertTools.getIssuerDN(x509Certificate).hashCode(),
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASEINS.getNumericValue(),
                    CertTools.getSerialNumber(x509Certificate).toString(16),
                    role.getRoleId(),
                    null, null));
            if (log.isDebugEnabled()) {
                log.debug("Added role '"+role.getRoleNameFull()+"' ("+role.getRoleId()+") matching certificate " + CertTools.getSubjectDN(x509Certificate));
            }
        } catch (AuthorizationDeniedException e) {
            // AlwaysAllowLocalAuthenticationToken should never be denied access
            throw new IllegalStateException(e);
        }
    }

    @Override
	public TestX509CertificateAuthenticationToken createAuthenticationTokenAndAssignToNewRole(final String subjectDn, final String roleNameSpace, final String roleName,
	        final List<String> resourcesAllowed, final List<String> resourcesDenied) throws RoleExistsException {
	    // Create X509Certificate based test authentication token
        final AuthenticationSubject authenticationSubject = new AuthenticationSubject(new HashSet<Principal>(Arrays.asList(new X500Principal(subjectDn))), null);
        final TestX509CertificateAuthenticationToken authenticationToken = (TestX509CertificateAuthenticationToken) simpleAuthenticationProviderSession.authenticate(authenticationSubject);
        if (authenticationToken==null) {
            log.debug("TestX509CertificateAuthenticationToken was null. No clean up will take place.");
            throw new IllegalStateException("Creation of role management token failed.");
        }
        final X509Certificate x509Certificate = (X509Certificate) authenticationToken.getCredentials().iterator().next();
        createRoleAndAddCertificateAsRoleMember(x509Certificate, roleNameSpace, roleName, resourcesAllowed, resourcesDenied);
        return authenticationToken;
	}

    @Override
    public void removeAllAuthenticationTokensRoles(final TestX509CertificateAuthenticationToken authenticationToken) {
        if (authenticationToken==null) {
            log.debug("TestX509CertificateAuthenticationToken was null. No clean up will take place.");
        } else {
            final List<Role> roles = roleSession.getRolesAuthenticationTokenIsMemberOf(authenticationToken);
            if (log.isDebugEnabled()) {
                log.debug("Removing " + roles.size() + " roles matching " + authenticationToken);
            }
            final AuthenticationToken alwaysAllowAuthenticationToken = new AlwaysAllowLocalAuthenticationToken("removeAllAuthenticationTokensRoles");
            for (final Role role : roles) {
                try {
                    if (roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, role.getRoleId())) {
                        if (log.isDebugEnabled()) {
                            log.debug("Removed role '"+role.getRoleNameFull()+"' ("+role.getRoleId()+") matching " + authenticationToken);
                        }
                    }
                } catch (AuthorizationDeniedException e) {
                    // AlwaysAllowLocalAuthenticationToken should never be denied access
                    throw new IllegalStateException(e);
                }
            }
        }
    }
}
