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
 
package org.ejbca.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.5 2006-08-04 17:15:34 anatom Exp $
 */
public class StringTools {
    private static Logger log = Logger.getLogger(StringTools.class);

    // Characters that are not allowed in strings that may be stored in the db
    private static final char[] stripChars = {
        '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?',
        '$', '~'
    };
    // Characters that are not allowed in strings that may be used in db queries
    private static final char[] stripSqlChars = {
        '\'', '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?',
        '$', '~'
    };
    // Characters that are allowed to escape in strings
    private static final char[] allowedEscapeChars = {
        ','
    };
    
    private static final Pattern WS = Pattern.compile("\\s+");

    /**
     * Strips all special characters from a string by replacing them with a forward slash, '/'.
     *
     * @param str the string whose contents will be stripped.
     *
     * @return the stripped version of the input string.
     */
    public static String strip(String str) {
        if (str == null) {
            return null;
        }
        String ret = str;
        for (int i = 0; i < stripChars.length; i++) {
            if (ret.indexOf(stripChars[i]) > -1) {
                // If it is an escape char, we have to process manually
                if (stripChars[i] == '\\') {
                    // If it is an escaped char, allow it if it is an allowed escapechar
                    int index = ret.indexOf('\\');
                    while (index > -1) {
                    	if (!isAllowed(ret.charAt(index+1))) {
                            ret = StringUtils.overlay(ret,"/",index,index+1);
                        }
                        index = ret.indexOf('\\',index+1);
                    }
                } else {
                    ret = ret.replace(stripChars[i], '/');
                }
            }
        }
        return ret;
    } // strip
    /**
     * Checks if a string contains characters that would be stripped by 'strip'
     *
     * @param str the string whose contents would be stripped.
     * @return true if some chars in the string would be stripped, false if not.
     * @see #strip
     */
    public static boolean hasSqlStripChars(String str) {
        if (str == null) {
            return false;
        }
        String ret = str;
        for (int i = 0; i < stripSqlChars.length; i++) {
            if (ret.indexOf(stripSqlChars[i]) > -1) {
                // If it is an escape char, we have to process manually
                if (stripSqlChars[i] == '\\') {
                    // If it is an escaped char, allow it if it is an allowed escapechar
                    int index = ret.indexOf('\\');
                    while (index > -1) {
                        if (isAllowed(ret.charAt(index+1))) {
                            return true;
                        }
                        index = ret.indexOf('\\',index+1);
                    }
                } else {
                    return true;
                }
            }
        }
        return false;
    } // hasSqlStripChars

    /** Checks if a character is an allowed escape characted according to allowedEscapeChars
     * 
     * @param ch the char to check
     * @return true if char is an allowed escape character, false if now
     */ 
    private static boolean isAllowed(char ch) {
    	boolean allowed = false;
    	for (int j = 0; j < allowedEscapeChars.length; j++) {
    		if (ch == allowedEscapeChars[j]) {
    			allowed = true;
    			break;
    		}
    	}
    	return allowed;
    }
    
    /**
     * Strips all whitespace including space, tabs, newlines etc from the given string.
     *
     * @param str the string
     * @return the string with all whitespace removed
     * @since 2.1b1
     */
    public static String stripWhitespace(String str) {
        if (str == null) {
            return null;
        }
        return WS.matcher(str).replaceAll("");
    }
    
    /** Converts an IP-address string to octets of binary ints. 
     * ip is of form a.b.c.d, i.e. at least four octets
     * @param str string form of ip-address
     * @return octets, null if input format is invalid
     */
    public static byte[] ipStringToOctets(String str) {
        String[] toks = str.split("[.:]");
        if (toks.length == 4) {
            // IPv4 address
            byte[] ret = new byte[4];
            for (int i = 0;i<toks.length;i++) {
                int t = Integer.parseInt(toks[i]);
                if (t>255) {
                    log.error("IPv4 address '"+str+"' contains octet > 255.");
                    return null;
                }
                ret[i] = (byte)t;
            }
            return ret;
        }
        if (toks.length == 8) {
            // IPv6 address
            byte[] ret = new byte[16];
            int ind = 0;
            for (int i = 0;i<toks.length;i++) {
                int t = Integer.parseInt(toks[i]);
                if (t>0xFFFF) {
                    log.error("IPv6 address '"+str+"' contains part > 0xFFFF.");
                    return null;
                }
                int b1 = t & 0x00FF;
                ret[ind++] = (byte)b1;
                int b2 = t & 0xFF00;
                ret[ind++] = (byte)b2;
            }
        }
        log.error("Not a IPv4 or IPv6 address.");
        return null;
    }
    
    /** Takes input and converts to Base64 on the format
     * "B64:<base64 endoced string>", if the string is not null or empty.
     * 
     * @param s String to base64 encode
     * @return Base64 encoded string, or original string if it was null or empty
     */
    public static String putBase64String(String s) {
        if (StringUtils.isEmpty(s)) {
            return s;
        }
        if (s.startsWith("B64:")) {
            // Only encode once
            return s;
        }
        String n = null;
        try {
            // Since we used getBytes(s, "UTF-8") in this method, we must use UTF-8 when doing the reverse in another method
            n="B64:"+new String(Base64.encode(s.getBytes("UTF-8"), false));
        } catch (UnsupportedEncodingException e) {
            // Do nothing
            n=s;
        }
        return n;
        
    }

    /** Takes input and converts from Base64 if the string begins with B64:, i.e. is on format
     * "B64:<base64 endoced string>".
     * 
     * @param s String to Base64 decode
     * @return Base64 decoded string, or original string if it was not base 64 encoded
     */
    public static String getBase64String(String s) {
        if (StringUtils.isEmpty(s)) {
            return s;
        }
        String s1 = null;
        if (s.startsWith("B64:")) {
            s1 = s.substring(4);
            String n = null;
            try {
                // Since we used getBytes(s, "UTF-8") in the method putBase64String, we must use UTF-8 when doing the reverse
                n = new String(Base64.decode(s1.getBytes("UTF-8")), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                n = s;
            } catch (ArrayIndexOutOfBoundsException e) {
                // We get this if we try to decode something that is not base 64
                n = s;
            }
            return n;
        }
        return s;
    }

    /** Makes a string "hard" to read. Does not provide any real security, but at
     * least lets you hide passwords so that people with no malicious content don't 
     * accidentaly stumble upon information they should not have.
     * 
     * @param s string to obfuscate
     * @return an obfuscated string
     */
    public static String obfuscate(String s)
    {
        StringBuffer buf = new StringBuffer();
        byte[] b = s.getBytes();
        
        synchronized(buf)
        {
            buf.append("OBF:");
            for (int i=0;i<b.length;i++)
               {
                byte b1 = b[i];
                byte b2 = b[s.length()-(i+1)];
                int i1= b1+b2+127;
                int i2= b1-b2+127;
                int i0=i1*256+i2;
                String x=Integer.toString(i0,36);

                switch(x.length())
                {
                case 1:buf.append('0'); break;
                case 2:buf.append('0'); break;
                case 3:buf.append('0'); break;
                default:buf.append(x); break;
                }
            }
            return buf.toString();
        }
    }
    
    /** Retrieves the clear text from a string obfuscated with the obfuscate methods
     * 
     * @param s obfuscated string, usually (bot not neccesarily) starts with OBF:
     * @return plain text string
     */
    public static String deobfuscate(String s)
    {
        if (s.startsWith("OBF:"))
            s=s.substring(4);
        
        byte[] b=new byte[s.length()/2];
        int l=0;
        for (int i=0;i<s.length();i+=4)
           {
            String x=s.substring(i,i+4);
            int i0 = Integer.parseInt(x,36);
            int i1=(i0/256);
            int i2=(i0%256);
            b[l++]=(byte)((i1+i2-254)/2);
        }

        return new String(b,0,l);
    }
    private static final String q = "OBF:1m0r1kmo1ioe1ia01j8z17y41l0q1abo1abm1abg1abe1kyc17ya1j631i5y1ik01kjy1lxf";
    public static String pbeEncryptStringWithSha256Aes192(String in) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Digest digest = new SHA256Digest();
        final char[] p = deobfuscate(q).toCharArray();
        String saltStr = "1958473059684739584hfurmaqiekcmq";
        byte[] salt = saltStr.getBytes("UTF-8");
        int    iCount = 100;
        
        PKCS12ParametersGenerator   pGen = new PKCS12ParametersGenerator(digest);
        pGen.init(
                PBEParametersGenerator.PKCS12PasswordToBytes(p),
                salt,
                iCount);
        
        ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(192, 128);
        SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), "AES");
        Cipher          c;
        c = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
        
        byte[]          enc = c.doFinal(in.getBytes("UTF-8"));
        
        byte[] hex = Hex.encode(enc);
        return new String(hex);
    }
    
    public static String pbeDecryptStringWithSha256Aes192(String in) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException {
        final char[] p = deobfuscate(q).toCharArray();
        String saltStr = "1958473059684739584hfurmaqiekcmq";
        byte[] salt = saltStr.getBytes("UTF-8");
        int    iCount = 100;

        Cipher c = Cipher.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
        PBEKeySpec          keySpec = new PBEKeySpec(p, salt, iCount);
        SecretKeyFactory    fact = SecretKeyFactory.getInstance("PBEWithSHA256And192BitAES-CBC-BC", "BC");
        
        c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));
        
        byte[] dec = c.doFinal(Hex.decode(in.getBytes("UTF-8")));
        return new String(dec);
    }
    
} // StringTools
