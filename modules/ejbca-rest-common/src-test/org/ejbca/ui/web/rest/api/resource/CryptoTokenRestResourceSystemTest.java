/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.ui.web.rest.api.io.request.CryptoTokenActivationRestRequest;
import org.ejbca.ui.web.rest.api.io.request.CryptoTokenKeyGenerationRestRequest;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertJsonContentType;
import static org.ejbca.ui.web.rest.api.Assert.EjbcaAssert.assertProperJsonStatusResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A unit test class for CryptoTokenRestResource to test its content.
 *
 * @version $Id: CryptoTokenRestResourceSystemTest.java 32447 2019-05-28 12:38:14Z aminkh $
 */
public class CryptoTokenRestResourceSystemTest extends RestResourceSystemTestBase {

    private static final String SOFT_CRYPTO_TOKEN_NAME = "RestSystemTestToken";
    private static final String TEST_KEY_PAIR_ALIAS = "TestKeyPair";
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();

    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        
    }

    @Test
    public void shouldReturnStatusInformation() throws Exception {
        // given
        final String expectedStatus = "OK";
        final String expectedVersion = "1.0";
        final String expectedRevision = GlobalConfiguration.EJBCA_VERSION;
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/cryptotoken/status").get();
        final String actualJsonString = actualResponse.getEntity(String.class);
        actualResponse.close();
        // then
        assertEquals(Response.Status.OK.getStatusCode(), actualResponse.getStatus());
        assertJsonContentType(actualResponse);
        assertProperJsonStatusResponse(expectedStatus, expectedVersion, expectedRevision, actualJsonString);
    }

    /**
     * Disables REST and then runs a simple REST access test which will expect status 403 when
     * service is disabled by configuration.
     * @throws Exception
     */
    
    @Test
    public void shouldRestrictAccessToRestResourceIfProtocolDisabled() throws Exception {
        // given
        disableRestProtocolConfiguration();
        // when
        final ClientResponse<?> actualResponse = newRequest("/v1/cryptotoken/status").get();
        final int status = actualResponse.getStatus();
        actualResponse.close();
        // then
        assertEquals("Unexpected response after disabling protocol", 403, status);
        // restore state
        enableRestProtocolConfiguration();
    }
    
    @Test
    public void shouldReturnStatusOkOnSuccessfulActivationIdempotent() throws Exception {
        // Create and deactivate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, false, false);
        try {
            // Perform crypto token activation REST call
            final CryptoTokenActivationRestRequest requestObject = new CryptoTokenActivationRestRequest("foo123");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/activate");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.put();
            actualResponse.close();
    
            // Verify Response
            assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
            assertTrue(cryptoTokenSession.isCryptoTokenStatusActive(INTERNAL_ADMIN_TOKEN, cryptoTokenId));
            
            // Perform another activation call
            final ClientResponse<?> idempotentResponse = request.put();
            idempotentResponse.close();
            // Expecting idempotence (return OK and remain status)
            assertEquals(Status.OK.getStatusCode(), idempotentResponse.getStatus());
            assertTrue(cryptoTokenSession.isCryptoTokenStatusActive(INTERNAL_ADMIN_TOKEN, cryptoTokenId));
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnUnprocessableEntityActivatingUnknownCryptoToken() throws Exception {
        // Build request object
        final CryptoTokenActivationRestRequest requestObject = new CryptoTokenActivationRestRequest("foo123");
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(requestObject);
        final ClientRequest request = newRequest("/v1/cryptotoken/" + "SomeUnknownCryptoToken" + "/activate");
        request.body(MediaType.APPLICATION_JSON, requestBody);
        // Perform crypto token activation REST call
        final ClientResponse<?> actualResponse = request.put();
        actualResponse.close();
        // Verify result
        assertJsonContentType(actualResponse);
        assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
    }
    
    @Test
    public void shouldReturnUnprocessableEntityCryptoTokenWithInvalidCode() throws Exception {
        // Create and deactivate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, false, false);
        try {
            // Perform crypto token activation REST call
            final CryptoTokenActivationRestRequest requestObject = new CryptoTokenActivationRestRequest("fooWrongActivationCode");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/activate");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.put();
            actualResponse.close();
    
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
            assertFalse(cryptoTokenSession.isCryptoTokenStatusActive(INTERNAL_ADMIN_TOKEN, cryptoTokenId));
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnStatusOkOnSuccessfulDeactivationIdempotent() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token deactivation REST call
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/deactivate");
            final ClientResponse<?> actualResponse = request.put();
            actualResponse.close();
    
            // Verify Response
            assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
            assertFalse(cryptoTokenSession.isCryptoTokenStatusActive(INTERNAL_ADMIN_TOKEN, cryptoTokenId));
            
            // Perform another deactivation call
            final ClientResponse<?> idempotentResponse = request.put();
            idempotentResponse.close();
            // Expecting idempotence (return OK and remain status)
            assertEquals(Status.OK.getStatusCode(), idempotentResponse.getStatus());
            assertFalse(cryptoTokenSession.isCryptoTokenStatusActive(INTERNAL_ADMIN_TOKEN, cryptoTokenId));
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnUnprocessableEntityDeactivatingUnknownCryptoToken() throws Exception {
        final ClientRequest request = newRequest("/v1/cryptotoken/" + "SomeUnknownCryptoToken" + "/deactivate");
        // Perform crypto token deactivation REST call
        final ClientResponse<?> actualResponse = request.put();
        actualResponse.close();
        // Verify result
        assertJsonContentType(actualResponse);
        assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
    }
    
    @Test
    public void shouldReturnStatusOkOnGeneratingKeys() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key generation REST call
            final CryptoTokenKeyGenerationRestRequest requestObject = new CryptoTokenKeyGenerationRestRequest("SomeTestAlias", "RSA", "1024");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/generatekeys");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
    
            // Verify Response
            assertEquals(Status.CREATED.getStatusCode(), actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnUnprocessableEntityWrongCryptoTokenName() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key generation REST call
            final CryptoTokenKeyGenerationRestRequest requestObject = new CryptoTokenKeyGenerationRestRequest("SomeTestAlias", "RSA", "1024");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + "WrongCryptoTokenName" + "/generatekeys");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
    
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }

    @Test
    public void shouldReturnUnprocessableEntityDuplicateAlias() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key generation REST call
            final CryptoTokenKeyGenerationRestRequest requestObject = new CryptoTokenKeyGenerationRestRequest("SomeTestAlias", "RSA", "1024");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/generatekeys");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> firstResponse = request.post();
            firstResponse.close();
            // Verify Response
            assertEquals(Status.CREATED.getStatusCode(), firstResponse.getStatus());
            
            // Perform the call again
            final ClientResponse<?> secondResponse = request.post();
            secondResponse.close();
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, secondResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }

    @Test
    public void shouldReturnUnprocessableEntityInvalidKeyAlg() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key generation REST call
            final CryptoTokenKeyGenerationRestRequest requestObject = new CryptoTokenKeyGenerationRestRequest("SomeTestAlias", "InvalidAlgorithm", "1024");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/generatekeys");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
    
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnUnprocessableEntityInvalidKeySpec() throws Exception {
        // Create and activate crypto token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key generation REST call
            final CryptoTokenKeyGenerationRestRequest requestObject = new CryptoTokenKeyGenerationRestRequest("SomeTestAlias", "RSA", "NotEvenANumber");
            final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
            final String requestBody = objectMapper.writeValueAsString(requestObject);
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/generatekeys");
            request.body(MediaType.APPLICATION_JSON, requestBody);
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
    
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnStatusOkOnKeyPairRemoval() throws Exception {
        // Create and activate crypto token + generate key pair
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, true);
        try {
            // Perform crypto token key removal REST call
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/" + TEST_KEY_PAIR_ALIAS + "/removekeys");
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
            // Verify Response
            assertEquals(Status.OK.getStatusCode(), actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnUnprocessableEntityRemovingUnknownKeyPair() throws Exception {
        // Create and activate crypto token. Don't generate key pair
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, true, false);
        try {
            // Perform crypto token key removal REST call
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/" + TEST_KEY_PAIR_ALIAS + "/removekeys");
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
    
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    @Test
    public void shouldReturnServiceUnavailableRemovingKeyPairFromOfflineToken() throws Exception {
        // Create crypto token, generate key pair and deactivate the token
        final int cryptoTokenId = createTestSoftCryptoToken(SOFT_CRYPTO_TOKEN_NAME, false, true);
        try {
            // Perform crypto token key removal REST call
            final ClientRequest request = newRequest("/v1/cryptotoken/" + SOFT_CRYPTO_TOKEN_NAME + "/" + TEST_KEY_PAIR_ALIAS + "/removekeys");
            final ClientResponse<?> actualResponse = request.post();
            actualResponse.close();
            // Verify Response
            assertEquals(HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY, actualResponse.getStatus());
        } finally {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
    }
    
    private static int createTestSoftCryptoToken(final String cryptoTokenName, final boolean activate, final boolean generateKeyPair) 
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, 
                AuthorizationDeniedException, NoSuchSlotException, InvalidKeyException, InvalidAlgorithmParameterException {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        final int cryptoTokenId = cryptoTokenSession.createCryptoToken(INTERNAL_ADMIN_TOKEN, cryptoTokenName, SoftCryptoToken.class.getName(), cryptoTokenProperties, null, "foo123".toCharArray());
        if (generateKeyPair) {
            cryptoTokenSession.createKeyPair(INTERNAL_ADMIN_TOKEN, cryptoTokenId, TEST_KEY_PAIR_ALIAS, "RSA1024");
        }
        if (!activate) {
            cryptoTokenSession.deactivate(INTERNAL_ADMIN_TOKEN, cryptoTokenId);
        }
        return cryptoTokenId;
    }
    
}
