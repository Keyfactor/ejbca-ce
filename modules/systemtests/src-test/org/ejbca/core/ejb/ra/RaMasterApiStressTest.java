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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.lang.time.StopWatch;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataProxySessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.era.TestRaMasterApiProxySessionRemote;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Will create heaps of end entities and certificates by calling the RaMasterApi
 *
 * @version $Id$
 */
public class RaMasterApiStressTest extends CaTestCase {

	private static final Logger log = Logger.getLogger(RaMasterApiStressTest.class);

	private static final String USERNAME_PREFIX = "RaMasterApiStressTest";
	private static final int NUMBER_OF_THREADS = 10;
	private static final int USERS_PER_THREAD = 100;
	private static final int NUMBER_OF_ROLE_MEMBERS = 10000;
	
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RaMasterApiStressTest"));

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberDataProxySessionRemote roleMemberDataProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(RoleMemberDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private TestRaMasterApiProxySessionRemote testRaMasterApiProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(TestRaMasterApiProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        //We want to make database transactions expensive. This means that we need to stuff a few thousand entries into the RoleMemberData table
        int roleId = roleSession.getRole(alwaysAllowToken, null, getRoleName()).getRoleId();
        for(int i = 0; i < NUMBER_OF_ROLE_MEMBERS; i++) {
            roleMemberDataProxySession.createOrEdit(new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, getTestCAId(),
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                    USERNAME_PREFIX + i, roleId, null));
        }
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        //Role members will be deleted with the role, which happens in the superclass
    }

    public String getRoleName() {
        return "RaMasterApiStressTest"; 
    }

    
    private String generatePkcs10() throws Exception {
         KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        // Make a PKCS10 request with extensions
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        // Add a custom extension (dummy)
        ASN1EncodableVector attr = new ASN1EncodableVector();
        attr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        extgen.addExtension(new ASN1ObjectIdentifier("1.2.3.4"), false, new DEROctetString("foo123".getBytes()));
        Extensions exts = extgen.generate();
        attr.add(new DERSet(exts));
        attributes.add(new DERSequence(attr));
        PKCS10CertificationRequest pkcs10 = CertTools.genPKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX500Name("CN=NOUSED"),
                keys.getPublic(), new DERSet(attributes), keys.getPrivate(), null);
        return new String(Base64.encode(pkcs10.getEncoded()));
    }

    @Test
    public void testAddUser() throws Exception { 
        final StopWatch stopWatch = new StopWatch();
        List<Callable<String[]>> tasks = new ArrayList<>();
        List<String> createdUsers = new ArrayList<>();
        for(int i = 0; i < NUMBER_OF_THREADS; i++) {
            //Pregenerate PKCS10 requests
            String[] requests = new String[USERS_PER_THREAD];
            for(int j = 0; j < USERS_PER_THREAD; j++) {
                requests[j] = generatePkcs10();
            }
            tasks.add(new AddUserThread(i, requests));
        }
        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_THREADS);
        stopWatch.start();
        try {
            List<Future<String[]>> futures = executor.invokeAll(tasks);
            for(Future<String[]> future : futures) {
                createdUsers.addAll(Arrays.asList(future.get()));
            }
            stopWatch.stop();
            long diff = stopWatch.getTime();
            log.info(createdUsers.size() + " end entities have been generated using AddUser. Total time: " + diff + " ms."); 
            log.info("Average creation time: " + diff / (NUMBER_OF_THREADS * USERS_PER_THREAD) + " ms per end entity");
        } finally {
            for (String endEntityName : createdUsers) {
                try {
                    endEntityManagementSession.deleteUser(alwaysAllowToken, endEntityName);
                } catch (NoSuchEndEntityException e) {
                    //NOPMD Ignore
                }
                internalCertificateStoreSession.removeCertificatesByUsername(endEntityName);
            }
        }
    }
    

    @Test
    public void testCertificateWs() throws Exception { 
        final StopWatch stopWatch = new StopWatch();
        List<Callable<String[]>> tasks = new ArrayList<>();
        List<String> createdUsers = new ArrayList<>();
        for(int i = 0; i < NUMBER_OF_THREADS; i++) {
            //Pregenerate PKCS10 requests
            String[] requests = new String[USERS_PER_THREAD];
            for(int j = 0; j < USERS_PER_THREAD; j++) {
                requests[j] = generatePkcs10();
            }
            tasks.add(new CertificateWsThread(i, requests));
        }
        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_THREADS);
        stopWatch.start();
        try {
            List<Future<String[]>> futures = executor.invokeAll(tasks);
            for(Future<String[]> future : futures) {
                createdUsers.addAll(Arrays.asList(future.get()));
            }
            stopWatch.stop();
            long diff = stopWatch.getTime();
            log.info(createdUsers.size() + " end entities with certificates have been generated using CertificateWsThread. Total time: " + diff + " ms."); 
            log.info("Average creation time: " + diff / (NUMBER_OF_THREADS * USERS_PER_THREAD) + " ms per end entity");
        } finally {
            for (String endEntityName : createdUsers) {
                try {
                    endEntityManagementSession.deleteUser(alwaysAllowToken, endEntityName);
                } catch (NoSuchEndEntityException e) {
                    //NOPMD Ignore
                }
                internalCertificateStoreSession.removeCertificatesByUsername(endEntityName);
            }
        }
    }
    
    
    private class CertificateWsThread implements Callable<String[]> {

        private final String[] requests;
        private final String[] usernames;
        private final int threadNumber;
        
        public CertificateWsThread(int threadNumber, String[] requests) {
            this.threadNumber = threadNumber;
            this.requests = requests;
            this.usernames = new String[requests.length];
        }

        @Override
        public String[] call() throws Exception {
            String theadUsername = USERNAME_PREFIX + "_" + threadNumber;
            for (int i = 0; i < requests.length; i++) {
                String username = theadUsername + "_" + i;
                usernames[i] = username;
                UserDataVOWS userdata = new UserDataVOWS(username, "foo123", false, "CN=" + username, getTestCAName(), null, null,
                        EndEntityConstants.STATUS_NEW, UserDataVOWS.TOKEN_TYPE_USERGENERATED, "EMPTY", "ENDUSER", null);
                // Replace the below authentication token with an always allow token to create a baseline (since auto allow doesn't require referencing the database)
                testRaMasterApiProxySession.createCertificateWS(roleMgmgToken, userdata, requests[i], CertificateHelper.CERT_REQ_TYPE_PKCS10, null,
                        CertificateHelper.RESPONSETYPE_CERTIFICATE);

            }
            return usernames;
        }
    }
    
    private class AddUserThread implements Callable<String[]> {

        private final String[] requests;
        private final String[] usernames;
        private final int threadNumber;
        
        public AddUserThread(int threadNumber, String[] requests) {
            this.threadNumber = threadNumber;
            this.requests = requests;
            this.usernames = new String[requests.length];
        }

        @Override
        public String[] call() throws Exception {
            String theadUsername = USERNAME_PREFIX + "_" + threadNumber;
            for (int i = 0; i < requests.length; i++) {
                String username = theadUsername + "_" + i;
                usernames[i] = username;
                EndEntityInformation endEntity = new EndEntityInformation(username, "CN=" + username, getTestCAId(), null, null, EndEntityTypes.ENDUSER.toEndEntityType(), 
                        SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
                
                testRaMasterApiProxySession.addUser(roleMgmgToken, endEntity, false);

            }
            return usernames;
        }
    }
    
}
