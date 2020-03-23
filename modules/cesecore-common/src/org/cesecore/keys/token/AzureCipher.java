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
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.cesecore.util.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * A Java encryption provider for encrypting small values with Azure Key Vault. Only does two types of "engineDoInit and engineDoFinal"
 * 
 * @version $Id$
 */
public class AzureCipher extends CipherSpi {

    private static final Logger log = Logger.getLogger(AzureCipher.class);

    private int opmode;
    private AzureCryptoToken.KeyVaultPrivateKey privateKey;
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
            // Key Vault REST API: https://docs.microsoft.com/en-us/rest/api/keyvault/
            final HttpPost request = new HttpPost(privateKey.getKeyURI() + "/decrypt?api-version=7.0");
            request.setHeader("Content-Type", "application/json");

            final HashMap<String, String> map = new HashMap<>();
            // RsaEncryption algorithm, https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.keyvault.cryptography.algorithms.rsaencryption
            map.put("alg", "RSA1_5");
            map.put("value", java.util.Base64.getEncoder().encodeToString(arg0));
            final JSONObject jsonObject = new JSONObject(map);
            final StringWriter out = new StringWriter();
            jsonObject.writeJSONString(out);
            request.setEntity(new StringEntity(out.toString()));
            if (log.isDebugEnabled()) {
                log.debug("engineDoFinal Request: " + request.toString()+", "+privateKey.toString());
            }
            try (final CloseableHttpResponse response = privateKey.getCryptoToken().performRequest(request)) {
                final InputStream content = response.getEntity().getContent();
                final String s = IOUtils.toString(content, StandardCharsets.UTF_8);
                final int statusCode = response.getStatusLine().getStatusCode();
                if (log.isDebugEnabled()) {
                    log.debug("Status code engineDoFinal is: " + statusCode);
                    log.debug("Response.toString: " + response.toString());
                    log.debug("Response JSON: " + s);
                }
                if (statusCode != HttpStatus.SC_OK) {
                    throw new BadPaddingException("Decryption failed with status code " + statusCode + ", and response JSON: " + s);
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
        this.privateKey = (AzureCryptoToken.KeyVaultPrivateKey)key;            
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
