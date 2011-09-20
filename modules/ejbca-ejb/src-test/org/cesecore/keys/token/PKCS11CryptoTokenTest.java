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

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Assert;
import org.junit.Test;

/**
 * Tests PKCS11 keystore crypto token. To run this test a slot 1 must exist on the hsm, with a user with user pin "userpin1" that can use the slot.
 * 
 * Based on EJBCA version: CATokenContainerTest.java 10288 2010-10-26 11:27:21Z anatom $
 * 
 * @version $Id$
 */
public class PKCS11CryptoTokenTest extends CryptoTokenTestBase {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(PKCS11CryptoTokenTest.class);

	private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
	private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
	private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String LUNASA_PKCS11_LINUX32_LIB = "/usr/lunasa/lib/libCryptoki2.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_LINUX32_LIB = "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_WINDOWS_LIB = "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll";

    public PKCS11CryptoTokenTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCryptoTokenRSA() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doCryptoTokenRSA(catoken);
    }

	@Test
    public void testCryptoTokenECC() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doCryptoTokenECC(catoken, "secp256r1", 256, "secp384r1", 384);
    }

	@Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doActivateDeactivate(catoken);
    }

	@Test
    public void testAutoActivate() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
    	doAutoActivate(catoken);
    }

	@Test
    public void testStoreAndLoad() throws Exception {
    	CryptoToken token = createPKCS11Token();
    	doStoreAndLoad(token);
	}

	@Test
    public void testGenerateSymKey() throws Exception {
    	CryptoToken token = createPKCS11Token();
    	doGenerateSymKey(token);
	}

    @Test
    public void testPKCS11TokenCreation() throws Exception {
        PKCS11CryptoToken token1 = (PKCS11CryptoToken) createPKCS11Token();
        PKCS11CryptoToken token2 = (PKCS11CryptoToken) createPKCS11Token();
        Assert.assertSame("Same token was expected!", token1.getP11slot(), token2.getP11slot());

        PKCS11CryptoToken token3 = (PKCS11CryptoToken) createPKCS11Token("token3", true);
        PKCS11CryptoToken token4 = (PKCS11CryptoToken) createPKCS11Token("token4", true);
        Assert.assertNotSame("Differen token was expected!", token3.getP11slot(), token4.getP11slot());

        PKCS11CryptoToken token5 = (PKCS11CryptoToken) createPKCS11Token("token5", false);
        Assert.assertNotSame("Differen token was expected!", token3.getP11slot(), token5.getP11slot());
    }

//	private String attributesHmac = "attributes(*, *, *) = {\n"+
//		  "CKA_TOKEN = true\n"+
//		"}\n"+
//		"attributes(*, CKO_PUBLIC_KEY, *) = {\n"+
//		  "CKA_ENCRYPT = true\n"+
//		  "CKA_VERIFY = true\n"+
//		  "CKA_WRAP = true\n"+
//		"}\n"+
//		"attributes(*, CKO_PRIVATE_KEY, *) = {\n"+
//		  "CKA_PRIVATE = true\n"+
//		  "CKA_SENSITIVE = true\n"+
//		  "CKA_EXTRACTABLE = false\n"+
//		  "CKA_DECRYPT = true\n"+
//		  "CKA_SIGN = true\n"+
//		  "CKA_UNWRAP = true\n"+
//		"}\n"+
//		"attributes(*, CKO_SECRET_KEY, *) = {\n"+
//		  "CKA_SENSITIVE = true\n"+
//		  "CKA_EXTRACTABLE = false\n"+
//		  "CKA_ENCRYPT = true\n"+
//		  "CKA_DECRYPT = true\n"+
//		  "CKA_SIGN = true\n"+
//		  "CKA_VERIFY = true\n"+
//		  "CKA_WRAP = true\n"+
//		  "CKA_UNWRAP = true\n"+
//		"}";

	/**
	 * This test is hard to make working on different HSMs due to algorithms restrictions
	 * Not implemented yet, see CESECORE-42 
	 */
//	@Test
//    public void testGenerateHMACKey() throws Exception {
//		File f = File.createTempFile("tokentest", "txt");
//		f.deleteOnExit();
//		FileOutputStream fos = new FileOutputStream(f);
//		fos.write(attributesHmac.getBytes());
//		fos.close();
//    	CryptoToken token = createPKCS11TokenWithAttributesFile(f.getAbsolutePath());
//    	doGenerateHmacKey(token);
//	}

	@Test
	public void testExtractKeyFalse() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, CryptoTokenOfflineException, IOException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException{
    	CryptoToken token = createPKCS11Token("testExtractKeyFalse", false);
		doExtractKeyFalse(token);
	}

	private String attributesExtract = "attributes(*, *, *) = {\n"+
	  "CKA_TOKEN = true\n"+
	"}\n"+
	"attributes(*, CKO_PUBLIC_KEY, *) = {\n"+
	  "CKA_ENCRYPT = true\n"+
	  "CKA_VERIFY = true\n"+
	  "CKA_WRAP = true\n"+
	"}\n"+
	"attributes(*, CKO_PRIVATE_KEY, *) = {\n"+
	  "CKA_PRIVATE = true\n"+
	  "CKA_SENSITIVE = false\n"+
	  "CKA_EXTRACTABLE = true\n"+
	  "CKA_DECRYPT = true\n"+
	  "CKA_SIGN = true\n"+
	  "CKA_UNWRAP = true\n"+
	  "}\n"+
	"attributes(*, CKO_SECRET_KEY, *) = {\n"+
	  "CKA_SENSITIVE = false\n"+
	  "CKA_EXTRACTABLE = true\n"+
	  "CKA_ENCRYPT = true\n"+
	  "CKA_DECRYPT = true\n"+
	  "CKA_SIGN = true\n"+
	  "CKA_VERIFY = true\n"+
	  "CKA_WRAP = true\n"+
	  "CKA_UNWRAP = true\n"+
	"}";

	/**
	 * This test is hard to make working on different HSMs due to algorithms restrictions
	 * This is not implemented yet, see CESECORE-80
	 */
	@Test
	public void testExtractKey() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException, SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, IOException, PrivateKeyNotExtractableException{
		File f = File.createTempFile("tokentest", "txt");
		f.deleteOnExit();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(attributesExtract.getBytes());
		fos.close();
    	CryptoToken token = createPKCS11TokenWithAttributesFile(f.getAbsolutePath(), "testExtractKey", true);
		doExtractKey(token);
	}

	@Override
	String getProvider() {
		return PKCS11CryptoTokenTest.getHSMProvider();
	}

	public static String getHSMProvider() {
	    final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
	    final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
	    final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
	    final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
	    final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
	    final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
	    String ret = null;
	    if (utimacoCSLinux.exists()) {
	        ret = "SunPKCS11-libcs2_pkcs11.so-slot1";
	    } else if (utimacoCSWindows.exists()) {
	        ret = "SunPKCS11-cs2_pkcs11.dll-slot1";
	    } else if (lunaSALinux64.exists()) {
	        ret = "SunPKCS11-libCryptoki2_64.so-slot1";
	    } else if (lunaSALinux32.exists()) {
	        ret = "SunPKCS11-libCryptoki2.so-slot1";
	    } else if (protectServerLinux64.exists()) {
	        ret = "SunPKCS11-libcryptoki.so-slot1";
	    } else if (protectServerLinux32.exists()) {
	        ret = "SunPKCS11-libcryptoki.so-slot1";
	    } else if (protectServerWindows.exists()) {
	        ret = "SunPKCS11-cryptoki.dll-slot1";
	    }
        if (log.isDebugEnabled()) {
        	log.debug("getHSMProvider: "+ret);
        }
	    return ret;		
	}
	
	public static CryptoToken createPKCS11Token() {
		return createPKCS11TokenWithAttributesFile(null, null, true);
	}

    public static CryptoToken createPKCS11Token(String name, boolean extractable){
        return createPKCS11TokenWithAttributesFile(null, name, extractable);
    }

	public static CryptoToken createPKCS11TokenWithAttributesFile(String file, String tokenName, boolean extractable) {
		Properties prop = new Properties();
        String hsmlib = getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_KEY, "1");
        if (file != null) {
            prop.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, file);
        }
        if (tokenName != null) {
            prop.setProperty(PKCS11CryptoToken.TOKEN_FRIENDLY_NAME, tokenName);
        }
        if (extractable){
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "True");
        } else {
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        }
        CryptoToken catoken = CryptoTokenFactory.createCryptoToken(PKCS11CryptoToken.class.getName(), prop, null, 111);
		return catoken;
	}

    public static String getHSMLibrary() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = utimacoCSLinux.getAbsolutePath();
        } else if (utimacoCSWindows.exists()) {
            ret = utimacoCSWindows.getAbsolutePath();
        } else if (lunaSALinux64.exists()) {
            ret = lunaSALinux64.getAbsolutePath();
        } else if (lunaSALinux32.exists()) {
            ret = lunaSALinux32.getAbsolutePath();
        } else if (protectServerLinux64.exists()) {
            ret = protectServerLinux64.getAbsolutePath();
        } else if (protectServerLinux32.exists()) {
            ret = protectServerLinux32.getAbsolutePath();
        } else if (protectServerWindows.exists()) {
            ret = protectServerWindows.getAbsolutePath();
        }
        if (log.isDebugEnabled()) {
        	log.debug("getHSMLibrary: "+ret);
        }
        return ret;
    }
}
