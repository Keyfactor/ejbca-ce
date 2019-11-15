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
package org.cesecore.keys.token;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;
import java.util.HashMap;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.cesecore.util.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A Java signature provider for creating signatures with Azure Key Vault. Only does "engineInitSign, engineUpdate and engineSign"
 * 
 * @version $Id$
 */
public class AzureSignature extends SignatureSpi {

    private static final Logger log = Logger.getLogger(AzureSignature.class);

    private AzureCryptoToken.KeyVaultPrivateKey privateKey;
    protected String hashAlg;
    protected String azureSignAlg;
    private byte[] tbs;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = (AzureCryptoToken.KeyVaultPrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.tbs = Arrays.copyOfRange(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("engineSign: " + this.getClass().getName());
            }
            // Key Vault REST API: https://docs.microsoft.com/en-us/rest/api/keyvault/
            
            //String lastKeyVersion = AzureCryptoToken.getLastKeyVersion(privateKey.getKeyURI());
            //HttpPost request = new HttpPost(lastKeyVersion + "/sign?api-version=2016-10-01");
            final HttpPost request = new HttpPost(privateKey.getKeyURI() + "/sign?api-version=2016-10-01");
            request.setHeader("Content-Type", "application/json");

            final HashMap<String, String> map = new HashMap<>();
            // RSA SHA-256 Signature algorithm, https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.keyvault.cryptography.algorithms.rs256
            // ES256 is ECDSA with curve P-256 from NIST
            // ES384 is ECDSA with curve P-384 from NIST
            // ES512 is ECDSA with curve P-521 from NIST
            map.put("alg", azureSignAlg);
            MessageDigest hash = null;
            try {
                hash = MessageDigest.getInstance(hashAlg, BouncyCastleProvider.PROVIDER_NAME);
            } catch (NoSuchAlgorithmException e) {
                throw new SignatureException("Hash algorithm " + hashAlg + " can not be found in the BC provider: ", e);
            } catch (NoSuchProviderException e) {
                throw new SignatureException("BC provider not installed, fatal error: ", e);
            }
            final byte[] digest = hash.digest(tbs);
            map.put("value", java.util.Base64.getEncoder().encodeToString(digest));
            final JSONObject jsonObject = new JSONObject(map);
            final StringWriter out = new StringWriter();
            jsonObject.writeJSONString(out);
            request.setEntity(new StringEntity(out.toString()));
            if (log.isDebugEnabled()) {
                log.debug("engineSign Request: " + request.toString()+", "+privateKey.toString());
            }
            try (final CloseableHttpResponse response = privateKey.getCryptoToken().performRequest(request)) {
                final InputStream content = response.getEntity().getContent();
                final String s = IOUtils.toString(content, StandardCharsets.UTF_8);
                final int statusCode = response.getStatusLine().getStatusCode();
                if (log.isDebugEnabled()) {
                    log.debug("Status code engineSign is: " + statusCode);
                    log.debug("Response.toString: " + response.toString());
                    log.debug("Response JSON: " + s);
                }
                if (statusCode != 200) {
                    throw new SignatureException("Signing failed with status code " + statusCode + ", and response JSON: " + s);
                }
                final JSONParser jsonParser = new JSONParser();
                final JSONObject parse = (JSONObject) jsonParser.parse(s);
                final String value = (String) parse.get("value");
                if (log.isDebugEnabled()) {
                    log.debug("Response Signature Base64 value: " + value);
                }
                byte[] bytes = Base64.decodeURLSafe(value);
                final int valueLength = bytes.length;
                if (log.isDebugEnabled()) {
                    log.debug("Response bytes length: " + valueLength);
                }
                if (azureSignAlg.startsWith("ES")) {
                    int nLen = 256; // for ES256, 32 bytes per signature value integer
                    switch (azureSignAlg) {
                    case "ES384":
                        nLen = 384; // 48 bytes per signature value integer
                        break;
                    case "ES512":
                        nLen = 528; // 66 bytes per signature value integer, a special case for secp521r1, 
                        // the curve order is just a shade under 2^521−1, hence it requires 521 bits to express one of those integers, 
                        // or 1042 to express two. 131 bytes would suffice; however the convention is to express those two integers 
                        // separately; each integer takes up 66 bytes, and hence 132 is used for the two
                        break;
                    default:
                        break;
                    }
                    final BigInteger n = BigInteger.ONE.shiftLeft(nLen).subtract(BigInteger.ONE); // "order", just to know how long the signature integers should be
                    if (log.isDebugEnabled()) {
                        log.debug("(EC) n is: "+BigIntegers.getUnsignedByteLength(n));
                    }
                    final BigInteger[] plain = PlainDSAEncoding.INSTANCE.decode(n, bytes);
                    bytes = StandardDSAEncoding.INSTANCE.encode(n, plain[0], plain[1]);
                }
                return bytes;
            }
        } catch (CryptoTokenAuthenticationFailedException | CryptoTokenOfflineException | IOException | ParseException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return false;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
    
    public static final class SHA256WithRSA extends AzureSignature {
        public SHA256WithRSA() {
            hashAlg = "SHA256";
            azureSignAlg = "RS256";
        }
    }

    public static final class SHA384WithRSA extends AzureSignature {
        public SHA384WithRSA() {
            hashAlg = "SHA384";
            azureSignAlg = "RS384";
        }
    }

    public static final class SHA512WithRSA extends AzureSignature {
        public SHA512WithRSA() {
            hashAlg = "SHA512";
            azureSignAlg = "RS512";
        }
    }

    public static final class SHA256WithECDSA extends AzureSignature {
        public SHA256WithECDSA() {
            hashAlg = "SHA256";
            azureSignAlg = "ES256";
        }
    }

    public static final class SHA384WithECDSA extends AzureSignature {
        public SHA384WithECDSA() {
            hashAlg = "SHA384";
            azureSignAlg = "ES384";
        }
    }

    public static final class SHA512WithECDSA extends AzureSignature {
        public SHA512WithECDSA() {
            hashAlg = "SHA512";
            azureSignAlg = "ES512";
        }
    }

}
