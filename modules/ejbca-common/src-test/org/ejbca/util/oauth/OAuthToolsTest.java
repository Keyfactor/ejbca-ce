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
package org.ejbca.util.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;

import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.keys.KeyTools;

/**
 * Unit tests for the OAuthTools class
 */

public class OAuthToolsTest {

    private static final String JWK_KEY_IDENTIFIER = "fAhtTrQfRIB0C31iCdPUe9ZJ_8wx4Ov-wn5MdUxCwoQ";
    private static final String JWK_PUBLIC_KEY = "{\"kid\":\"fAhtTrQfRIB0C31iCdPUe9ZJ_8wx4Ov-wn5MdUxCwoQ\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig"
            + "\",\"n\":\"j4g81S3nhh3vW2eGIYiwLsJC7cHGMunzMsAl6N4zyzDh0DgrtWn3Bawi32DZFAydbvlCRuLDjqw7m6AX7UUVVgUqCLg68B7uPQ2v7oC9swpLi4"
            + "lQ0C6zTqPdAsKTs7ZFd-4cluSFlBC6xkgqzP4dDvh6hJVHLI9SbbizTraGa9cnwjCuMIVxFbv1UNqM2fevmyjXUcMjdco5laeYcHh5LwAgFjedkagXRj35qAn"
            + "SDG727mUN0BFDdT-tGpmNkv7BXKd6aLzt5KvgxnNIMrMSlSoa0Pcot6iA7hd8Z_Tm5Jm0DmzAfPqYacGGCocN89x9cpoZEODSXimUfSqVL_3bNw\",\"e\":"
            + "\"AQAB\",\"x5c\":[\"MIICmTCCAYECBgF2ZxeHxzANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQDDAVFSkJDQTAeFw0yMDEyMTUxNTQ3NDRaFw0zMDEyMTUxNT"
            + "Q5MjRaMBAxDjAMBgNVBAMMBUVKQkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj4g81S3nhh3vW2eGIYiwLsJC7cHGMunzMsAl6N4zyzDh0Dgr"
            + "tWn3Bawi32DZFAydbvlCRuLDjqw7m6AX7UUVVgUqCLg68B7uPQ2v7oC9swpLi4lQ0C6zTqPdAsKTs7ZFd+4cluSFlBC6xkgqzP4dDvh6hJVHLI9SbbizTraGa9"
            + "cnwjCuMIVxFbv1UNqM2fevmyjXUcMjdco5laeYcHh5LwAgFjedkagXRj35qAnSDG727mUN0BFDdT+tGpmNkv7BXKd6aLzt5KvgxnNIMrMSlSoa0Pcot6iA7hd8"
            + "Z/Tm5Jm0DmzAfPqYacGGCocN89x9cpoZEODSXimUfSqVL/3bNwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAGVYzPvxozq/cSknbSUjddkG6rIM5/n4QHx4o/F4"
            + "KW0Bg2lXvN0ZSSTht5T+6Y4LhSvlcySQiq5zumCC+xPIkNP7ec1CKL9xjzinHDBckh1OxVhQpH157X2hYXAxA+3tIdNIJwd8KYsRXaR+YeyhjOCTNBzZtm0nuT"
            + "P9eSI3hw3v3uWPtbWeqhjjun8uDYLjW1Ptt+jGLd0VTnqK10n+VAYjLRKQF87+euCVFfPcBzwWwM8JbONKIUGj1MR8R8p4/rzmJ7jbyiEfDwtOKNMIwGUnGHfq"
            + "gPQkkiE4LY8a4MzdJuSPcT6FXDjvARjk22iEg+LrXOesDQGY/0xwVxs810\"],\"x5t\":\"W_cCMb00oHfX1snRC29oWQeH_IM\",\"x5t#S256\":\"gmvc8"
            + "frXsa_8ejoDdHSKfAJCA1C3s1hChQNOA2lw1XY\"}";

    /** self signed cert */
    private static final byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    @Test
    public void testGetBytesFromOauthKeyEmpty() {
        try {
            OAuthTools.getBytesFromOauthKey(new byte[] {});
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Public key file is empty", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromOauthKeyInvalid() {
        try {
            OAuthTools.getBytesFromOauthKey(new byte[] { 'x' });
            fail("Should throw");
        } catch (CertificateParsingException e) {
            assertEquals("Key could neither be parsed as PEM, DER, certificate or JWK", e.getMessage());
        }
    }

    @Test
    public void testGetBytesFromOauthKeyJwk() throws CertificateParsingException {
        final byte[] keyBytes = OAuthTools.getBytesFromOauthKey(JWK_PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII));
        assertNotNull("Should get an encoded key", keyBytes);
        final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(keyBytes);
        assertNotNull("Bytes should represent a public key", pubKey);
    }

    @Test
    public void testGetBytesFromOauthKeyCertificate() throws CertificateParsingException {
        final byte[] keyBytes = OAuthTools.getBytesFromOauthKey(certbytes);
        assertNotNull("Should get an encoded key", keyBytes);
        final PublicKey pubKey = KeyTools.getPublicKeyFromBytes(keyBytes);
        assertNotNull("Bytes should represent a public key", pubKey);
    }

    @Test
    public void testGetKeyIdFromJwkKeyBadKey() {
        assertNull("For malformed keys, the Key ID should be null", OAuthTools.getKeyIdFromJwkKey(new byte[] { 'x' }));
    }

    @Test
    public void testGetKeyIdFromJwkKey() {
        assertEquals("Wrong Key Identifier as returned", JWK_KEY_IDENTIFIER,
                OAuthTools.getKeyIdFromJwkKey(JWK_PUBLIC_KEY.getBytes(StandardCharsets.US_ASCII)));
    }

}
