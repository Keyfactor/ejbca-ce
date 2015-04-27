/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for {@link CAAdminSession}
 * 
 * @version $Id$
 *
 */
public class CaAdminSessionBeanTest {

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken("CaAdminSessionBeanTest");

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testGetAuthorizedPublisherIds() throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException,
            IOException, RoleExistsException, AuthorizationDeniedException, PublisherExistsException, CAExistsException, CertificateProfileExistsException, CADoesntExistsException {
        //Create a publisher to be attached to a CA that the admin has access to
        LdapPublisher caPublisher = new LdapPublisher();
        final String caPublisherName = "CA_PUBLISHER";
        int caPublisherId = publisherProxySession.addPublisher(alwaysAllowToken, caPublisherName, caPublisher);
        //Create a publisher to be attached to a CA that the admin doesn't have access to
        LdapPublisher unauthorizedCaPublisher = new LdapPublisher();
        final String unauthorizedCaPublisherName = "UNAUTHORIZED_CA_PUBLISHER";
        int unauthorizedCaPublisherId = publisherProxySession.addPublisher(alwaysAllowToken, unauthorizedCaPublisherName, unauthorizedCaPublisher);
        //Create a publisher to be unattached to any CA or certificate profile
        LdapPublisher unattachedPublisher = new LdapPublisher();
        final String unattachedCaPublisherName = "UNATTACHED_PUBLISHER";
        int unattachedCaPublisherId = publisherProxySession.addPublisher(alwaysAllowToken, unattachedCaPublisherName, unattachedPublisher);
        //Create a publisher to be attached to a certificate profile
        LdapPublisher certificateProfilePublisher = new LdapPublisher();
        final String certificateProfilePublisherName = "CERTIFICATE_PROFILE_PUBLISHER";
        int certificateProfilePublisherId = publisherProxySession.addPublisher(alwaysAllowToken, certificateProfilePublisherName, certificateProfilePublisher);
        UnAuthorizedCustomPublisherMock unAuthorizedCustomPublisher = new UnAuthorizedCustomPublisherMock();
        final String unAuthorizedCustomPublisherName = "UNAUTHORIZED_CUSTOM_PUBLISHER";
        int unAuthorizedCustomPublisherId = publisherProxySession.addPublisher(alwaysAllowToken, unAuthorizedCustomPublisherName, unAuthorizedCustomPublisher);
        AuthorizedCustomPublisherMock authorizedCustomPublisher = new AuthorizedCustomPublisherMock();
        final String authorizedCustomPublisherName = "AUTHORIZED_CUSTOM_PUBLISHER";
        int authorizedCustomPublisherId = publisherProxySession.addPublisher(alwaysAllowToken, authorizedCustomPublisherName, authorizedCustomPublisher);
        
        
        
        //Create a CA that admin has access to. Publishers attached to this CA should be included
        X509CA authorizedCa = CaTestUtils.createTestX509CA("CN=PUB_ID_authorizedCa", null, false);
        authorizedCa.setCRLPublishers(new ArrayList<Integer>(Arrays.asList(caPublisherId)));
        caSession.addCA(alwaysAllowToken, authorizedCa);
        //Create a CA that admin doesn't have access to. Publishers attached to this CA should not be included
        X509CA unauthorizedCa = CaTestUtils.createTestX509CA("CN=PUB_ID_unauthorizedCa", null, false);
        unauthorizedCa.setCRLPublishers(new ArrayList<Integer>(Arrays.asList(unauthorizedCaPublisherId)));
        caSession.addCA(alwaysAllowToken, unauthorizedCa);
        //Create a CA that admin has access to, to be attached to a certificate profile. Publishers attached to that Certificate Profile should be included
        X509CA certProfileCa = CaTestUtils.createTestX509CA("CN=PUB_ID_certprofileCa", null, false);
        caSession.addCA(alwaysAllowToken, certProfileCa);
        
        //Set up a certificate profile
        final String certificateProfileName = "testGetAuthorizedPublisherIds";
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAvailableCAs(Arrays.asList(certProfileCa.getCAId()));
        certificateProfile.setPublisherList(Arrays.asList(certificateProfilePublisherId));
        certificateProfileSession.addCertificateProfile(alwaysAllowToken, certificateProfileName, certificateProfile);
        
        //Set up a role for this test
        final String roleName = "testGetAuthorizedPublisherIds";
        RoleData role = roleManagementSession.create(alwaysAllowToken, roleName);
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        //Give our admin access to the authorized CA. 
        accessRules.add(new AccessRuleData(roleName, StandardRules.CAACCESS.resource() +  authorizedCa.getCAId(), AccessRuleState.RULE_ACCEPT, false));
        accessRules.add(new AccessRuleData(roleName, StandardRules.CAACCESS.resource() + certProfileCa.getCAId(), AccessRuleState.RULE_ACCEPT, false));
        try {
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowToken, role, accessRules);
        } catch (RoleNotFoundException e2) {
            // NOPMD: Ignore
        }
        List<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        //SimpleAuthenticationProviderSession used below will presume that our ad hoc user issued themselves. 
        subjects.add(new AccessUserAspectData(roleName, ("CN=" + roleName).hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, roleName));
        try {
            role = roleManagementSession.addSubjectsToRole(alwaysAllowToken, role, subjects);
        } catch (RoleNotFoundException e) {
            // NOPMD: Ignore
        }
        
        //Create the authentication token we'll be using for this test.
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal("CN=" + roleName);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        principals.add(p);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
                SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        AuthenticationToken authenticationToken = authenticationProvider.authenticate(subject);

        try {
            Set<Integer> publisherIds = caAdminSession.getAuthorizedPublisherIds(authenticationToken);
            assertTrue("Publisher attached to an authorized CA was not in list.", publisherIds.contains(Integer.valueOf(caPublisherId)));
            assertFalse("Publisher attached to an unauthorized CA was in list.", publisherIds.contains(Integer.valueOf(unauthorizedCaPublisherId)));
            assertTrue("Unattached publisher was not in list.", publisherIds.contains(Integer.valueOf(unattachedCaPublisherId)));
            assertTrue("Publisher attached to Certificate Profile was not in list.", publisherIds.contains(Integer.valueOf(certificateProfilePublisherId)));
            assertTrue("Authorized custom publisher was not in list.", publisherIds.contains(Integer.valueOf(authorizedCustomPublisherId)));
            assertFalse("Unauthorized custom publisher was in list.", publisherIds.contains(Integer.valueOf(unAuthorizedCustomPublisherId)));         
        } finally {
            //Remove the test role
            try {
                roleManagementSession.remove(alwaysAllowToken, role);
            } catch (RoleNotFoundException e1) {
                // NOPMD: Ignore
            } catch (AuthorizationDeniedException e1) {
                // NOPMD: Ignore
            }

            //Remove the test CAs
            try {
                CaTestUtils.removeCa(alwaysAllowToken, authorizedCa.getCAInfo());
            } catch (AuthorizationDeniedException e) {
                // NOPMD: Ignore
            }
            try {
                CaTestUtils.removeCa(alwaysAllowToken, unauthorizedCa.getCAInfo());
            } catch (AuthorizationDeniedException e) {
                // NOPMD: Ignore
            }
            try {
                CaTestUtils.removeCa(alwaysAllowToken, certProfileCa.getCAInfo());
            } catch (AuthorizationDeniedException e) {
                // NOPMD: Ignore
            }

            //Remove the certificate profile
            certificateProfileSession.removeCertificateProfile(alwaysAllowToken, certificateProfileName);
            
            //Remove the publishers
            publisherProxySession.removePublisher(alwaysAllowToken, caPublisherName);
            publisherProxySession.removePublisher(alwaysAllowToken, unauthorizedCaPublisherName);
            publisherProxySession.removePublisher(alwaysAllowToken, unattachedCaPublisherName);
            publisherProxySession.removePublisher(alwaysAllowToken, certificateProfilePublisherName);
            publisherProxySession.removePublisher(alwaysAllowToken, unAuthorizedCustomPublisherName);
            publisherProxySession.removePublisher(alwaysAllowToken, authorizedCustomPublisherName);
        }
    }
}
