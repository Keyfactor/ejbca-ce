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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Provider for signing and decrypting with Azure Key Vault REST API.
 *
 * @version $Id$
 */
public class AzureProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public AzureProvider(String name) {
        super(name, 1.0, "AzureKeyVault");
        // The different signature algorithms we handle in Azure Key Vault
        put("Signature.SHA256WITHRSA" , AzureSignature.SHA256WithRSA.class.getName());
        put("Signature.SHA384WITHRSA" , AzureSignature.SHA384WithRSA.class.getName());
        put("Signature.SHA512WITHRSA" , AzureSignature.SHA512WithRSA.class.getName());
        put("Signature.SHA256WITHECDSA" , AzureSignature.SHA256WithECDSA.class.getName());
        put("Signature.SHA384WITHECDSA" , AzureSignature.SHA384WithECDSA.class.getName());
        put("Signature.SHA512WITHECDSA" , AzureSignature.SHA512WithECDSA.class.getName());
        // Encryption with RSA can be done to support key recovery and SCEP
        put("Cipher.RSA" , AzureCipher.RSA.class.getName());
    }

    /**
     * A Java signature provider for creating signatures with Azure Key Vault. Only does "engineInitSign, engineUpdate and engineSign"
     * 
     * @version $Id: AzureSignature.java 33885 2019-11-19 12:34:08Z anatom $
     */
    public static class AzureSignature extends SignatureSpi {

        private static final Logger log = Logger.getLogger(AzureSignature.class);

        private KeyVaultPrivateKey privateKey;
        /** the hash algorithm to use to hash the toBeSigned data, hashing is done in SW before signing */
        protected String hashAlg;
        /** data to be signed */
        private byte[] toBeSigned;
        /** the signature algorithm as named by the Azure Key Vault REST API, to be used for signing the hashed toBeSigned data */
        protected String azureSignAlg;

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            this.privateKey = (KeyVaultPrivateKey) privateKey;
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            this.toBeSigned = Arrays.copyOfRange(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("engineSign: " + this.getClass().getName());
                }
                // Key Vault REST API for signing: https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign
                final HttpPost request = new HttpPost(privateKey.getKeyURL() + "/sign?api-version=7.0");
                request.setHeader("Content-Type", "application/json");

                // Create hash value of the data to be signed
                final byte[] signInput;
                try {
                    final MessageDigest digest = MessageDigest.getInstance(hashAlg, BouncyCastleProvider.PROVIDER_NAME);
                    signInput = digest.digest(toBeSigned);
                } catch (NoSuchAlgorithmException e) {
                    throw new SignatureException("Hash algorithm " + hashAlg + " can not be found in the BC provider: ", e);
                } catch (NoSuchProviderException e) {
                    throw new SignatureException("BC provider not installed, fatal error: ", e);
                }
                final HashMap<String, String> map = new HashMap<>();
                // Signature algorithms, https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
                // Supported/tested
                // RS256 is SHA256WithRSA (PKCS#1 v1.5)
                // RS384 is SHA384WithRSA (PKCS#1 v1.5)
                // RS512 is SHA512WithRSA (PKCS#1 v1.5)
                // ES256 is SHA256WithECDSA with curve P-256 from NIST
                // ES384 is SHA384WithECDSA with curve P-384 from NIST
                // ES512 is SHA512WithECDSA with curve P-521 from NIST
                // Not supported/tested yet
                // PS256 is SHA256WithRSAAndMGF1 (RSA-PSS)
                // PS384 is SHA384WithRSAAndMGF1 (RSA-PSS)
                // PS512 is SHA512WithRSAAndMGF1 (RSA-PSS)
                // ES256K is SHA256WithECDSA with curve P-256K from NIST
                map.put("alg", azureSignAlg);
                map.put("value", java.util.Base64.getEncoder().encodeToString(signInput));
                final JSONObject jsonObject = new JSONObject(map);
                final StringWriter out = new StringWriter();
                jsonObject.writeJSONString(out);
                request.setEntity(new StringEntity(out.toString()));
                if (log.isDebugEnabled()) {
                    log.debug("engineSign Request: " + request.toString()+", "+privateKey.toString());
                }
                try (final CloseableHttpResponse response = privateKey.getCryptoToken().azureHttpRequest(request)) {
                    final int statusCode = response.getStatusLine().getStatusCode();
                    final InputStream is = response.getEntity().getContent();
                    final String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("Status code engineSign is: " + statusCode);
                        log.debug("Response.toString: " + response.toString());
                        log.debug("Response JSON: " + json);
                    }
                    if (statusCode != 200) {
                        throw new SignatureException("Signing failed with status code " + statusCode + ", and response JSON: " + json);
                    }
                    final JSONParser parser = new JSONParser();
                    final JSONObject parse = (JSONObject) parser.parse(json);
                    final String value = (String) parse.get("value");
                    if (log.isDebugEnabled()) {
                        log.debug("Signature response base64 value: " + value);
                    }
                    byte[] bytes = Base64.decodeBase64(value);
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
                this.hashAlg = "SHA384";
                this.azureSignAlg = "ES384";
            }
        }

        public static final class SHA512WithECDSA extends AzureSignature {
            public SHA512WithECDSA() {
                hashAlg = "SHA512";
                azureSignAlg = "ES512";
            }
        }
    }
        
    /**
     * A Java Cipher provider for decrypting small values (key unwrapping) with Azure Key Vault. Only does two types of "engineDoInit and engineDoFinal"
     * 
     * @version $Id: AzureCipher.java 34697 2020-03-23 14:22:36Z anatom $
     */
    public static class AzureCipher extends CipherSpi {

        private static final Logger log = Logger.getLogger(AzureCipher.class);

        private int opmode;
        private KeyVaultPrivateKey privateKey;
        protected String azureEncAlg;

        public static final class RSA extends AzureCipher {
            public RSA() {
                azureEncAlg = "RSA";
            }
        }

        @Override
        protected byte[] engineUpdate(byte[] b, int off, int len) {
            if (log.isDebugEnabled()) {
                log.debug("engineUpdate1: " + this.getClass().getName());
            }
            return null;
        }
        
        @Override
        protected int engineUpdate(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4) throws ShortBufferException {
            if (log.isDebugEnabled()) {
                log.debug("engineUpdate2: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected byte[] engineDoFinal(byte[] arg0, int arg1, int arg2) throws IllegalBlockSizeException, BadPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineDoFinal1: " + this.getClass().getName() + ", opmode=" + this.opmode);
            }

            try {
                // Key Vault decrypt REST API: https://docs.microsoft.com/en-us/rest/api/keyvault/decrypt/decrypt
                final HttpPost request = new HttpPost(privateKey.getKeyURL() + "/decrypt?api-version=7.0");
                request.setHeader("Content-Type", "application/json");

                final HashMap<String, String> map = new HashMap<>();
                // RsaEncryption algorithm, https://docs.microsoft.com/en-us/rest/api/keyvault/decrypt/decrypt#jsonwebkeyencryptionalgorithm
                map.put("alg", "RSA1_5");
                map.put("value", java.util.Base64.getEncoder().encodeToString(arg0));
                final JSONObject jsonObject = new JSONObject(map);
                final StringWriter out = new StringWriter();
                jsonObject.writeJSONString(out);
                request.setEntity(new StringEntity(out.toString()));
                if (log.isDebugEnabled()) {
                    log.debug("engineDoFinal Request: " + request.toString()+", "+privateKey.toString());
                }
                try (final CloseableHttpResponse response = privateKey.getCryptoToken().azureHttpRequest(request)) {
                    final InputStream is = response.getEntity().getContent();
                    final int statusCode = response.getStatusLine().getStatusCode();
                    final String json = IOUtils.toString(is, StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug("Status code engineDoFinal is: " + statusCode);
                        log.debug("Response.toString: " + response.toString());
                        log.debug("Response JSON: " + json);
                    }
                    if (statusCode != HttpStatus.SC_OK) {
                        throw new BadPaddingException("Decryption failed with status code " + statusCode + ", and response JSON: " + json);
                    }
                    final JSONParser jsonParser = new JSONParser();
                    final JSONObject parse = (JSONObject) jsonParser.parse(json);
                    final String value = (String) parse.get("value");
                    if (log.isDebugEnabled()) {
                        log.debug("Decryption response base64 value: " + value);
                    }
                    byte[] bytes = Base64.decodeBase64(value);
                    final int valueLength = bytes.length;
                    if (log.isDebugEnabled()) {
                        log.debug("Response bytes length: " + valueLength);
                    }
                    return bytes;
                }
            } catch (CryptoTokenAuthenticationFailedException | CryptoTokenOfflineException | IOException | ParseException e) {
                BadPaddingException newe = new BadPaddingException(e.getMessage());
                newe.initCause(e);
                throw newe;
            }
        }

        @Override
        protected int engineDoFinal(byte[] arg0, int arg1, int arg2, byte[] arg3, int arg4)
                throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineDoFinal2: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected int engineGetBlockSize() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetBlockSize: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected byte[] engineGetIV() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetIV: " + this.getClass().getName());
            }
            return null;
        }

        @Override
        protected int engineGetOutputSize(int arg0) {
            if (log.isDebugEnabled()) {
                log.debug("engineGetOutputSize: " + this.getClass().getName());
            }
            return 0;
        }

        @Override
        protected AlgorithmParameters engineGetParameters() {
            if (log.isDebugEnabled()) {
                log.debug("engineGetParameters: " + this.getClass().getName());
            }
            return null;
        }

        @Override
        protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit1: " + this.getClass().getName());
            }
            this.opmode = opmode;
            if (this.opmode != Cipher.DECRYPT_MODE && this.opmode != Cipher.UNWRAP_MODE) {
                throw new IllegalArgumentException("Only DECRYPT_MODE (2) or UNWRAP_MODE (4) can be used: " + opmode);
            }
            this.privateKey = (KeyVaultPrivateKey)key;            
        }

        @Override
        protected void engineInit(int opmode, Key arg1, AlgorithmParameterSpec arg2, SecureRandom arg3)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit2: " + this.getClass().getName());
            }
        }

        @Override
        protected void engineInit(int opmode, Key arg1, AlgorithmParameters arg2, SecureRandom arg3)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (log.isDebugEnabled()) {
                log.debug("engineInit3: " + this.getClass().getName());
            }
        }

        @Override
        protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
            if (log.isDebugEnabled()) {
                log.debug("engineSetMode: " + this.getClass().getName() + ", " + mode);
            }
        }

        @Override
        protected void engineSetPadding(String arg0) throws NoSuchPaddingException {
            if (log.isDebugEnabled()) {
                log.debug("engineSetPadding: " + this.getClass().getName());
            }
        }
    }

    public static class KeyVaultPrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private String keyURL;
        private String keyAlg;
        private AzureCryptoToken cryptoToken;

        public KeyVaultPrivateKey(String keyURL, String keyAlg, AzureCryptoToken cryptoToken) {
            this.keyURL = keyURL;
            this.keyAlg = keyAlg;
            this.cryptoToken = cryptoToken;
        }
        
        @Override
        public String getAlgorithm() {
            return keyAlg;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }

        public AzureCryptoToken getCryptoToken() {
            return cryptoToken;
        }
        
        public String getKeyURL() {
            return keyURL;
        }
        
        @Override
        public String toString() {
            return getKeyURL() + ":" + getAlgorithm() + ":" + getCryptoToken().getTokenName();
        }
    }


}
