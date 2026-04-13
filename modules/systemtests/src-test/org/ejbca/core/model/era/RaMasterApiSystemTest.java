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
package org.ejbca.core.model.era;

import static java.util.function.Function.identity;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.test.ApiVersion;
import com.keyfactor.util.test.MethodApiDescriptor;

/**
 * Test to verify implementation constraints of RaMasterApi.
 * <p>
 * Verifies that:
 * <ul>
 * <li>all defined classes are Serializable
 * <li>method names are unique
 * </ul>
 */
public class RaMasterApiSystemTest {

    private static final Logger log = Logger.getLogger(RaMasterApiSystemTest.class);

    private enum EjbcaVersion implements ApiVersion {
        EJBCA_8_3_0("classes_in_8_3_0.txt"),
        EJBCA_9_3_0("classes_in_9_3_0.txt"),
        EJBCA_9_4_1("classes_in_9_4_1.txt"),
        EJBCA_9_6_0("classes_in_9_6_0.txt");

        private final String classListFilename;

        EjbcaVersion(final String classListFilename) {
            this.classListFilename = classListFilename;
        }

        public String getClassListFilename() {
            return classListFilename;
        }

        @Override
        public int versionOrdinal() {
            return ordinal();
        }
    }

    /**
     * List of all methods in the RA Master API.
     * <p>
     * When adding a NEW method in the RA Master API, please run this test and copy-paste the method definition from the error log.
     * <p>
     * DO NOT CHANGE already released methods in this list. They are duplicated here for a reason
     * (because changes will break the API, and this must not happen).
     */
    private static final List<MethodApiDescriptor> expectedRaMasterApiMethods = Arrays.asList(
    // @formatter:off
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("scepDispatchIntune", "org.ejbca.core.model.era.ScepResponseInfo", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String"), "bab777625c06"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("finishUserAfterLocalKeyRecovery", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "24ed77b365eb"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("generateOrKeyRecoverToken", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"), "d7a33d2f2a3b"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateProfileInfo", "org.ejbca.core.model.era.RaCertificateProfileResponseV2", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "9fa1dad795f2"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedCertificateProfiles", "org.ejbca.core.model.era.IdNameHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "5226fc8bfc9d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorization", "org.ejbca.core.model.era.RaAuthorizationResult", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "f239e3ee58a9"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("verifyScepPkcs10RequestMessage", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "[B"), "682191280995"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("deleteRoleMember", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int", "int"), "1d008e55ceed"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("generateKeyStore", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation"), "2ee25e1d9064"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeChallengeById", "org.ejbca.core.protocol.acme.AcmeChallenge", Arrays.asList("java.lang.String"), "53ad2f307134"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateProfile", "org.cesecore.certificates.certificateprofile.CertificateProfile", Arrays.asList("int"), "3a432a08c364"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("customLog", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "org.cesecore.audit.enums.EventType"), "ee44e0e3a093"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeChallengesByAuthorizationId", "java.util.List", Arrays.asList("java.lang.String"), "df883414f385"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getRemainingNumberOfApprovals", "java.lang.Integer", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "8a9a80ce2aad"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeChallengeList", "void", Arrays.asList("java.util.List"), "bf2f236409e0"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getLatestCrlByRequest", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaCrlSearchRequest"), "4a3b4235b55f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("processCertificateRequest", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String", "int", "java.lang.String", "java.lang.String"), "d83f3713e3ad"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeAuthorizationsByAccountId", "java.util.List", Arrays.asList("java.lang.String"), "da2b169e82fc"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getRolesAuthenticationTokenIsMemberOf", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "a920a6faf3dc"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getRolesAuthenticationTokenIsMemberOfV2", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "8bb6918c396d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCaaIdentities", "java.util.HashSet", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "76b1338933ca"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificateChainWithPreferredRoot", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "42d96fb91bf0"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("estDispatch", "[B", Arrays.asList("java.lang.String", "java.lang.String", "java.security.cert.X509Certificate", "java.lang.String", "java.lang.String", "[B"), "e1c932ec9b88"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeAccount", "java.lang.String", Arrays.asList("org.ejbca.core.protocol.acme.AcmeAccount"), "ac949107faa8"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCountOfCertificatesByExpirationTime", "int", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "long"), "edc7c20026cd"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchUser", "org.cesecore.certificates.endentity.EndEntityInformation", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "db470cb6bddb"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("isAuthorizedNoLoggingWithoutNeedingActiveLocalCA", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "[Ljava.lang.String;"), "fcadd44bbf9c"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("addRequestResponse", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaApprovalResponseRequest"), "4dcbb7dacd69"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("deleteUser", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "6b60a53bbe56"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("parseAcmeEabMessage", "java.lang.String", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"), "e5c2e5967a19"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getRoleMember", "org.cesecore.roles.member.RoleMember", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "0bebd3925cce"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeAccountByPublicKeyStorageId", "org.ejbca.core.protocol.acme.AcmeAccount", Arrays.asList("java.lang.String"), "429313b0326a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("editUserWs", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserDataVOWS"), "4f4a08e50dd1"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificatesV2", "org.ejbca.core.model.era.RaCertificateSearchResponseV2", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaCertificateSearchRequestV2"), "9303c4a4fe7d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getLastCertChain", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "4b862c27ad99"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificatesByExpirationTime", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "long", "int", "int"), "2887073cea92"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForApprovalRequests", "org.ejbca.core.model.era.RaRequestsSearchResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaRequestsSearchRequest"), "c7ad9caf5200"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getApprovalRequestByRequestHash", "org.ejbca.core.model.era.RaApprovalRequestInfo", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "7cd92dd2e592"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getLatestCrlByIssuerDn", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "boolean"), "6781967a2875"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getEndEntityProfile", "org.ejbca.core.model.era.RaEndEntityProfileResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "255173def0c2"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeAuthorizationById", "org.ejbca.core.protocol.acme.AcmeAuthorization", Arrays.asList("java.lang.String"), "13b07cdcc4d8"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAllCustomRaStyles", "java.util.LinkedHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "efd06d2ba529"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("markForRecovery", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "com.keyfactor.util.certificate.CertificateWrapper", "boolean"), "c373222c854e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("createCertificateWS", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserDataVOWS", "java.lang.String", "int", "java.lang.String", "java.lang.String"), "8b328ca17ab3"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("revokeCert", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.math.BigInteger", "java.util.Date", "java.lang.String", "int", "boolean"), "5819295d0569"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getPublisherQueueLength", "int", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "097c73ce5c59"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificate", "com.keyfactor.util.certificate.CertificateWrapper", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "6713823db688"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeOrderById", "org.ejbca.core.protocol.acme.AcmeOrder", Arrays.asList("java.lang.String"), "3e41d4303808"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeChallenge", "java.lang.String", Arrays.asList("org.ejbca.core.protocol.acme.AcmeChallenge"), "452aa2440f88"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("checkUserStatus", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "6c55df9d82b2"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("isApproved", "java.lang.Integer", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "964944f1837e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getEndEntityProfileAsXml", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "a0d2274518d1"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getRole", "org.cesecore.roles.Role", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "7575166f6c90"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_4_1, "getRoleV2", "org.cesecore.dto.RoleDataDto", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "c14180e1f69b"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForRoles", "org.ejbca.core.model.era.RaRoleSearchResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaRoleSearchRequest"), "a1be22cb54a9"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_4_1, "searchForRolesV2", "org.ejbca.core.model.era.RaRoleSearchResponseV2", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaRoleSearchRequest"), "563525762d08"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("scepDispatch", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String"), "e3a0173b494e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificate", "org.cesecore.certificates.certificate.CertificateDataWrapper", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "05b89f2f3579"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedRoles", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "3c69ec7af15a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedRolesV2", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "c09c4cdd8b35"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateDataForRenew", "org.ejbca.core.model.era.RaCertificateDataOnRenew", Arrays.asList("java.math.BigInteger", "java.lang.String"), "b9766620c18a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("createCertificateWithEntity", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "java.lang.String","int", "int"), "500f51d12feb"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("createCertificateRest", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest"), "dc7a418e6186"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAvailableCustomRaStyles", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "e47a77fe1f6e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("softTokenRequest", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserDataVOWS", "java.lang.String", "java.lang.String", "boolean"), "a49c92128e0e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("enrollAndIssueSshCertificate", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "org.ejbca.core.protocol.ssh.SshRequestMessage"), "34dc8f8a7c53"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("revokeAndDeleteUser", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "int"), "b942acbd65ac"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("revokeCertWithMetadata", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.ejb.dto.CertRevocationDto"), "fedba3240bb3"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedCas", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "7fde80aae84f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificates", "org.ejbca.core.model.era.RaCertificateSearchResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaCertificateSearchRequest"), "18c746b063f6"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("createCertificate", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation"), "66379cbbe70d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getApprovalProfileForAction", "org.ejbca.core.model.approval.profile.ApprovalProfile", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.ca.ApprovalRequestType", "int", "int"), "cffb0172522d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeOrder", "java.lang.String", Arrays.asList("org.ejbca.core.protocol.acme.AcmeOrder"), "f5f2f689dfe0"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("addUser", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "boolean"), "84b5ab85c400"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateChain", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "60488a031426"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForRoleMembers", "org.ejbca.core.model.era.RaRoleMemberSearchResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaRoleMemberSearchRequest"), "f99f39ce58f5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("editUser", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "boolean", "java.lang.String"), "bd2b47d27cb9"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForEndEntities", "org.ejbca.core.model.era.RaEndEntitySearchResponse", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaEndEntitySearchRequest"), "3477940a21ea"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificateByIssuerAndSerial", "org.cesecore.certificates.certificate.CertificateDataWrapper", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "51f1bb4fe897"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("addUserAndGenerateKeyStore", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "boolean"), "db98e3b26e0d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("processCardVerifiableCertificateRequest", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String"), "cc3eade3634e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getGlobalConfiguration", "org.cesecore.configuration.ConfigurationBase", Arrays.asList("java.lang.Class"), "a0d688352226"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("isAuthorized", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "[Ljava.lang.String;"), "fb5f2db58fa6"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("changeCertificateStatus", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "int", "int"), "c16d130b2ebe"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("isAuthorizedNoLogging", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "[Ljava.lang.String;"), "4354535cb853"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("removeAcmeOrders", "void", Arrays.asList("java.util.List"), "f6fff389bc58"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("findUserWS", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserMatch", "int"), "bd341b7e3454"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("republishCertificate", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String"), "02755897373c"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("keyRecoverEnrollWS", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String", "java.lang.String"), "4554d61accb5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmePreAuthorizationsByAccountIdAndIdentifiers", "java.util.List", Arrays.asList("java.lang.String", "java.util.List"), "2852fe5ae38e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("cmpDispatch", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "[B", "java.lang.String"), "f059f74c1869"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getFinalizedAcmeOrdersByFingerprint", "java.util.Set", Arrays.asList("java.lang.String"), "6840aef1663e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("canEndEntityEnroll", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "9131cda0413f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("saveRoleMember", "org.cesecore.roles.member.RoleMember", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.roles.member.RoleMember"), "e60d184cee17"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedEndEntityProfiles", "org.ejbca.core.model.era.IdNameHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "b998e6832218"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("addUserAndCreateCertificate", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation", "boolean"), "1b0b88d402c5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("keyRecoveryPossible", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.security.cert.Certificate", "java.lang.String"), "1fe8ab7e8eb5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificatesByExpirationTimeAndType", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "long", "int", "int"), "b72229013c61"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("enrollAndIssueSshCertificateWs", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserDataVOWS", "org.ejbca.core.protocol.ssh.SshRequestMessage"), "2ab2bdbd82f9"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForEndEntitiesV2", "org.ejbca.core.model.era.RaEndEntitySearchResponseV2", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaEndEntitySearchRequestV2"), "b2b3b205640d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("keyRecoverWS", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.lang.String"), "67d3e1badb2a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAvailableRoleMemberTokenTypes", "java.util.Map", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "908e6c0b3175"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchUserWithoutViewEndEntityAccessRule", "org.cesecore.certificates.endentity.EndEntityInformation", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "f74a773d6ecb"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeAuthorizationsByOrderId", "java.util.List", Arrays.asList("java.lang.String"), "0a1fa95eef5e"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("checkSubjectDn", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation"), "8eec78ad4bd2"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateProfileAsXml", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "3fefb0435fe5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedRoleNamespaces", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "6dc827c9cf1f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedCAInfos", "org.ejbca.core.model.era.IdNameHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "a69926fdfd1c"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_8_3_0, "getRequestedAuthorizedCAInfos", "org.ejbca.core.model.era.IdNameHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaCaListRequest"), "f96a74c94169"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificatesByUsername", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "boolean", "long"), "1ee8cad768f1"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getLastCaChain", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "5f79decd107d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeOrders", "java.util.List", Arrays.asList("java.util.List"), "7de72950f11a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("extendApprovalRequest", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int", "long"), "83cd1b290787"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificatesByExpirationTimeAndIssuer", "java.util.Collection", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "long", "java.lang.String", "int"), "ed6e0dc85480"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("doEtsiOperation", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "[B", "int"), "4db1d2f86565"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("revokeUser", "void", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "int", "boolean"), "46b963a003ef"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("createApprovalRequest", "java.lang.Integer", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int", "int", "int", "java.lang.String"), "18ce742df3b6"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedCertificateProfileIdsToNameMap", "java.util.Map", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "e962c985bc4f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeAuthorizationList", "void", Arrays.asList("java.util.List"), "d61bde225f5d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("searchForCertificateChain", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String"), "313fdcb4008d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAvailableCertificateProfiles", "java.util.Map", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "85d65d605a68"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getSshCaPublicKey", "[B", Arrays.asList("java.lang.String"), "8510e2329eea"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeOrdersByAccountId", "java.util.Set", Arrays.asList("java.lang.String"), "273fe3257be9"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getApiVersion", "int", Collections.emptyList(), "78ffc504ae78"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAvailableCasInProfile", "java.util.Map", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "01ddc7716c98"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("removeAcmeOrder", "void", Arrays.asList("java.lang.String"), "f719959751cb"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("generateKeyStoreWithoutViewEndEntityAccessRule", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.certificates.endentity.EndEntityInformation"), "78505d347972"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAcmeAccountById", "org.ejbca.core.protocol.acme.AcmeAccount", Arrays.asList("java.lang.String"), "368381a79ddf"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("persistAcmeAuthorization", "java.lang.String", Arrays.asList("org.ejbca.core.protocol.acme.AcmeAuthorization"), "14c872164d27"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getApprovalRequest", "org.ejbca.core.model.era.RaApprovalRequestInfo", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "880536e09d44"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("saveRole", "org.cesecore.roles.Role", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.roles.Role"), "b4f64fb545e3"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_4_1, "saveRoleV2", "org.cesecore.dto.RoleDataDto", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.dto.RoleDataDto"), "1c63be4cd6d5"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("deleteRole", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int"), "94bdda58c6f7"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateStatus", "org.cesecore.certificates.certificate.CertificateStatus", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.math.BigInteger"), "58df46cf0d1c"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getLatestCrl", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "boolean"), "cbbaa53f5912"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("isBackendAvailable", "boolean", Collections.emptyList(), "d70964d2c317"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAuthorizedEndEntityProfileIdsToNameMap", "java.util.Map", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "65303d7b46c2"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("addUserFromWS", "boolean", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.protocol.ws.objects.UserDataVOWS", "boolean"), "364f8ad9ebbe"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("estDispatchAuthenticated", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.String", "java.lang.String", "java.security.cert.X509Certificate", "java.lang.String", "java.lang.String", "[B"), "8a01c8e1634f"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("editApprovalRequest", "org.ejbca.core.model.era.RaApprovalRequestInfo", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.RaApprovalEditRequest"), "288dfc8aafee"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("selfRenewCertificate", "[B", Arrays.asList("org.ejbca.core.model.era.RaSelfRenewCertificateData"), "5488eee381e8"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getAllAuthorizedCertificateProfiles", "org.ejbca.core.model.era.IdNameHashMap", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken"), "0e0b93165b7d"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getKeyExchangeCertificate", "java.security.cert.Certificate", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "int", "int"), "a6aef899bc21"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getGlobalConfigurationLocalFirst", "org.cesecore.configuration.ConfigurationBase", Arrays.asList("java.lang.Class"), "d48ed5d749db"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("findUsernameByIssuerDnAndSerialNumber", "java.lang.String", Arrays.asList("java.lang.String", "java.lang.String"), "980858d82ee7"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_8_3_0, "generateOrKeyRecoverTokenV2", "[B", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.ejbca.core.model.era.GenerateOrKeyRecoverTokenRequest"), "c3c6329c0edc"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_3_0,"keyImportV2", "java.util.List", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "org.cesecore.keys.keyimport.KeyImportRequestData"), "a3c0246f2655"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getCertificateCount", "java.lang.Long", Arrays.asList("org.cesecore.authentication.tokens.AuthenticationToken", "java.lang.Boolean"), "940551e8dbe3"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor("getIfReadyAcmeOrder", "org.ejbca.core.protocol.acme.AcmeOrder", Arrays.asList("java.lang.String"), "287251acd17a"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_6_0, "sendOAuthRefreshTokenRequest", "org.cesecore.authentication.oauth.OAuthGrantResponseInfo", Arrays.asList("java.lang.String", "org.cesecore.authentication.oauth.OAuthKeyInfo", "java.lang.String"), "aae777f84d0b"),
            // Do NOT change! - A test failure means that the API has been broken!
            new MethodApiDescriptor(EjbcaVersion.EJBCA_9_6_0, "requestOAuthToken", "org.cesecore.authentication.oauth.OAuthGrantResponseInfo", Arrays.asList("org.cesecore.authentication.oauth.OAuthKeyInfo", "java.lang.String", "java.lang.String"), "7dc40342dfc6")

            // New methods should have a new MethodApiDescriptor and a "Do NOT change!" comment.
            // New methods should preferably have an EjbcaVersion.EJBCA_x_y_z and MUST have an EjbcaVersion.EJBCA_x_y_z if they use newly added types.
            // Existing methods should NOT be changed!
    // @formatter:on
    );

    private boolean logApiErrors;

    @Before
    public void before() {
        logApiErrors = false;
    }

    @Test
    public void testUniqueMethodNames() {
        final Set<String> methodNames = new HashSet<>();
        for (final Method method : RaMasterApi.class.getDeclaredMethods()) {
            assertTrue("Design violation. Non-unique method name " + method.getName() + " detected.", methodNames.add(method.getName()));
        }
    }

    @Test
    public void testSerializable() {
        final Set<Class<?>> referencedClasses = getReferencedClassesInInterface(RaMasterApi.class, ApiVersion.ALL_VERSIONS, true);
        final Set<Class<?>> allReferencedClasses = new HashSet<>(referencedClasses);
        int size = 0;
        while (size<allReferencedClasses.size()) {
            size = allReferencedClasses.size();
            for (final Class<?> clazz : new HashSet<>(allReferencedClasses)) {
                allReferencedClasses.addAll(getReferencedClasses(clazz));
            }
        }
        List<String> violators = new ArrayList<>();
        List<String> violatorsInInterface = new ArrayList<>();
        for (final Class<?> clazz : allReferencedClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers()) && !Serializable.class.isAssignableFrom(clazz)) {
                violators.add(clazz.getName());
                if (referencedClasses.contains(clazz)) {
                    violatorsInInterface.add(clazz.getName());
                }
            }
        }
        Collections.sort(violators);
        Collections.sort(violatorsInInterface);
        final StringBuilder sb = new StringBuilder();
        if (violatorsInInterface.isEmpty()) {
            for (final String className : violators) {
                log.debug(" " + className + " matched violation rule.");
                if (!sb.isEmpty()) {
                    sb.append(", ");
                }
                sb.append(className);
            }
        } else {
            // No need to show every referenced violation if there is a clear source of this
            for (final String className : violatorsInInterface) {
                log.debug(" " + className + " matched violationInterface rule.");
                if (!sb.isEmpty()) {
                    sb.append(", ");
                }
                sb.append(className);
            }
        }
        assertEquals("Design violation. The following referenced classes of RaMasterApi are not Serializable: " + sb, 0, sb.length());
    }

    /**
     * Checks that no peers method declarations have changed. Changes to the interface are
     * NOT allowed, since it would break the API compatibility.
     * <p>
     * DO NOT CHANGE the MethodApiDescriptors above. A test failure here is a real issue that we need to deal with.
     * <p>
     * DO NOT disable the test, test failures here are real problems.
     */
    @Test
    public void apiCheckMethods() {
        logApiErrors = true;
        doApiCheckMethods(expectedRaMasterApiMethods);
    }

    /**
     * Simulates an addition of a new API method (by a removal from the expected list of methods), which should give an error.
     * This is done to check that the test code itself is working.
     */
    @Test
    public void selfTestNewMethod() {
        final List<MethodApiDescriptor> expected = new ArrayList<>(expectedRaMasterApiMethods);
        expected.remove(12); // simulate an addition
        try {
            doApiCheckMethods(expected);
            fail("Should throw when a new method has been added");
        } catch (AssertionError e) { // should throw
            if (!e.getMessage().startsWith("Untested methods.")) {
                throw e;
            }
        }
    }

    @Test
    public void selfTestRemovedMethod() {
        // Given
        final List<MethodApiDescriptor> expected = new ArrayList<>(expectedRaMasterApiMethods);
        final String methodName = "youThinkYouCanRemoveThis";
        final String expectedMessage = "Method "+methodName+" has been removed, and this is an incompatible API change.";
        expected.add(MethodApiDescriptor.makeDummyMethod(methodName)); // simulate an removal

        // When
        try {
            doApiCheckMethods(expected);
            fail("Should throw when a new method has been removed");
        } catch (AssertionError e) { // should throw
            final String actualMessage = e.getMessage();
            final String assertMessage = "Expected error message: \"" + expectedMessage + "\"\nActual   error message: \"" + actualMessage + "\"\n";
            assertEquals(assertMessage, expectedMessage, actualMessage);
       }
    }

    @Test
    public void selfTestRenamedMethod() {
        final List<MethodApiDescriptor> expected = new ArrayList<>(expectedRaMasterApiMethods);
        expected.set(12, MethodApiDescriptor.makeDummyMethod("youThinkYouCanRenameThis")); // simulate a rename
        try {
            doApiCheckMethods(expected);
            fail("Should throw when a new method has been renamed");
        } catch (AssertionError e) { // should throw
            if (!"Method youThinkYouCanRenameThis has been removed, and this is an incompatible API change.".equals(e.getMessage())) {
                throw e;
            }
        }
    }

    @Test
    public void selfTestModifiedMethod() {
        final List<MethodApiDescriptor> expected = new ArrayList<>(expectedRaMasterApiMethods);
        expected.set(12, MethodApiDescriptor.makeDummyMethod(expected.get(12).getName())); // simulate a modified method
        try {
            doApiCheckMethods(expected);
            fail("Should throw when a new method has been modified");
        } catch (AssertionError e) { // should throw
            if (!e.getMessage().contains(" incompatible ")) {
                throw e;
            }
        }
    }

    /**
     * Checks that all classes that are available in the 7.12.x API do not reference
     * any classes that were added in later versions.
     * <p>
     * It is probably not necessary to have a test for ALL versions, but if we add significant
     * functionality in a new version, then we might want to add a new version, to prevent breakage
     * of that versions in later versions.
     * <p>
     * DO NOT CHANGE the MethodApiDescriptors above. A test failure here is a real issue that we need to deal with.
     * <p>
     * DO NOT disable the test, test failures here are real problems.
     */
    @Test
    public void checkExistenceOfClassesByVersion() throws IOException {
        /*
         * The resource was generated by running this command in 7.12.0:
         * find modules/caa/src modules/cesecore-common/src modules/cesecore-cvcca/src modules/cesecore-ejb/src modules/cesecore-ejb-interface/src modules/cesecore-entity/src modules/cesecore-x509ca/src modules/ct/src modules/ejbca-common/src modules/ejbca-ejb/src modules/ejbca-ejb-interface/src modules/ejbca-ws/src modules/peerconnector/src-{common,ejb,interface,ra} -name '*.java' | LC_ALL=C.UTF-8 sort > ~/workspace/ejbca/modules/systemtests/resources/classes_in_7_12_0.txt
         * (Note: This is the find command for GNU/Linux. MacOS uses an incompatible find command).
         * 
         * Note: This does not include nested classes, but it works without them, at least currently.
         *
         * DO NOT just remove these lines on test failure, test failures here are real problems.
         */
        // Test failures on this line can happen for two reasons:
        // 1. a type was removed (this will cause deserialization failures on older EJBCA versions than the current version)
        // 2. a new MethodApiDescriptor was added and doesn't have a EjbcaVersion.EJBCA_x_y_z specified, but it uses a type from a newer version than 7.12.0.
        doCheckExistenceOfClasses("classes_in_7_12_0.txt", ApiVersion.INITIAL_VERSION); // 7.12.0 is no longer supported, but the test was created in 7.12.0
        for (final EjbcaVersion ejbcaVersion : EjbcaVersion.values()) {
            doCheckExistenceOfClasses(ejbcaVersion.getClassListFilename(), ejbcaVersion);
        }
    }

    private void doCheckExistenceOfClasses(final String resourceName, final ApiVersion ejbcaVersion) throws IOException {
        final Set<String> classesInVersion;
        final InputStream resource = getClass().getClassLoader().getResourceAsStream(resourceName);
        Objects.requireNonNull(resource, "Resource file '" + resourceName + "' is missing.");
        try (final BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource, StandardCharsets.UTF_8))) {
            classesInVersion = reader.lines()
                    .map(line -> line.replaceFirst(".*/src(-[^/]+)?/", ""))
                    .map(line -> line.replaceFirst("#.*", "").trim())
                    .filter(line -> !line.isEmpty())
                    .map(line -> line.replace(".java", "").replace('/', '.'))
                    .collect(Collectors.toSet());
        }
        doCheckExistenceOfClasses(classesInVersion, ejbcaVersion);
    }

    /**  Checks that all classes in RaMasterApi existed in a specific version. */
    private void doCheckExistenceOfClasses(final Set<String> classesInVersion, final ApiVersion ejbcaVersion) {
        final Set<Class<?>> classesInApi = getReferencedClassesInInterface(RaMasterApi.class, ejbcaVersion, false);
        final Set<Class<?>> classesToCheck = classesInApi.stream()
                .filter(cl -> !cl.isPrimitive())
                .map(cl -> cl.isArray() ? cl.getComponentType() : cl)
                .collect(Collectors.toSet());
        final Set<Class<?>> alreadyCheckedClasses = new HashSet<>();
        for (final Class<?> cl : classesToCheck) {
            checkClassExistence(cl, classesInVersion, alreadyCheckedClasses, ejbcaVersion);
        }
    }

    /**
     * Checks that a specific class exists in the set of classes of a given version.
     * Classes of fields are checked recursively.
     */
    private void checkClassExistence(final Class<?> cl, final Set<String> classesInVersion, final Set<Class<?>> alreadyCheckedClasses, final ApiVersion apiVersion) {
        final String className = cl.getName();
        if (!alreadyCheckedClasses.add(cl) || className.startsWith("java.")) {
            return;
        }
        assertTrue("Class " + className + " is unavailable in version "+apiVersion,
                cl.isInterface() || cl.isPrimitive() ||
                classesInVersion.contains(className) ||
                // Classes that were accidentally renamed in 8.0. For these we have special handling.
                className.equals("com.keyfactor.util.CertificateSerializableWrapper") ||
                className.equals("com.keyfactor.CesecoreException") ||
                className.equals("com.keyfactor.ErrorCode"));
        for (final Class<?> nestedClass : getReferencedClasses(cl)) {
            checkClassExistence(nestedClass, classesInVersion, alreadyCheckedClasses, apiVersion);
        }
    }

    /**
     * Checks that no method in the RaMasterApi has been changed. Changes are not allowed, since
     * it would break backwards compatibility.
     */
    private void doApiCheckMethods(final List<MethodApiDescriptor> expectedMethods) {
        final Map<String, Method> availableMethods = new HashMap<>(
                Arrays.stream(RaMasterApi.class.getDeclaredMethods()).collect(Collectors.toMap(Method::getName, identity())));
        int i = 0;
        for (final MethodApiDescriptor methodDesc : expectedMethods) {
            System.out.println("i="+i);
            final Method actualMethod = availableMethods.remove(methodDesc.getName());
            assertNotNull("Method " + methodDesc.getName() + " has been removed, and this is an incompatible API change.", actualMethod);
            // Check that the method has NOT been changed. Changes are NOT allowed.
            methodDesc.checkUnchanged(actualMethod);
            ++i;
        }
        if (!availableMethods.isEmpty()) {
            final StringBuilder code = new StringBuilder();
            for (final Method untestedMethod : availableMethods.values()) {
                code.append(',');
                code.append(System.lineSeparator());
                code.append(MethodApiDescriptor.formatAsJavaCode(untestedMethod));
            }
            if (logApiErrors) {
                log.error("Untested methods:" + code);
            }
            fail("Untested methods. The following methods are not tested for API compatibility (please check the error log): "
                    + String.join(", ", availableMethods.keySet()));
        }
    }

    /** @return a Set of all classes declared as method parameters, method return types, method Exceptions in the specified interface */
    private Set<Class<?>> getReferencedClassesInInterface(final Class<?> clazz, final ApiVersion ejbcaVersion, final boolean includeExceptions) throws NoClassDefFoundError {
        final Set<Class<?>> acceptedClasses = new HashSet<>();
        for (final Method method : clazz.getDeclaredMethods()) {
            if (isPresentInVersion(method, ejbcaVersion)) {
                addReferencedClassesFromMethod(acceptedClasses, method, includeExceptions);
            }
        }
        return acceptedClasses;
    }

    private boolean isPresentInVersion(final Method method, final ApiVersion versionToCheck) {
        final String methodName = method.getName();
        final MethodApiDescriptor apiInfo = expectedRaMasterApiMethods.stream().filter(m -> m.getName().equals(methodName)).findFirst().get();
        return apiInfo.getApiVersion().versionOrdinal() <= versionToCheck.versionOrdinal();
    }

    private void addReferencedClassesFromMethod(final Set<Class<?>> acceptedClasses, final Method method, final boolean includeExceptions) {
        final Class<?>[] methodParamClasses = method.getParameterTypes();
        acceptedClasses.addAll(Arrays.asList(methodParamClasses));
        if (includeExceptions) {
            final Class<?>[] methodExceptionClasses = method.getExceptionTypes();
            acceptedClasses.addAll(Arrays.asList(methodExceptionClasses));
        }
        acceptedClasses.add(method.getReturnType());
    }

    /** @return a Set of all classes declared as non-transient, non-static field in the class */
    private Set<Class<?>> getReferencedClasses(final Class<?> clazz) throws NoClassDefFoundError {
        final Set<Class<?>> acceptedClasses = new HashSet<>();
        for (final Field field : clazz.getDeclaredFields()) {
            if (!Modifier.isStatic(field.getModifiers()) && !Modifier.isTransient(field.getModifiers())) {
                acceptedClasses.add(field.getDeclaringClass());
            }
        }
        final Class<?> superClass = clazz.getSuperclass();
        if (superClass!=null) {
            acceptedClasses.addAll(getReferencedClasses(superClass));
        }
        return acceptedClasses;
    }
}
