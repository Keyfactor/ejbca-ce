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
import java.text.DecimalFormat;
import java.util.Collection;
import java.util.LinkedList;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.CharUtils;
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
 * @version $Id$
 */
public class StringTools {
    private static Logger log = Logger.getLogger(StringTools.class);

    // Characters that are not allowed in strings that may be stored in the db.
    private static final char[] stripChars = {
        '\n', '\r', ';', '!', '\0', '%', '`', '?', '$', '~'
    };
    // Characters that are not allowed in strings that may be used in db queries
    private static final char[] stripSqlChars = {
        '\'', '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?',
        '$', '~'
    };
    // Characters that are allowed to escape in strings.
    // RFC 2253, section 2.4 lists ',' '"' '\' '+' '<' '>' ';' as valid escaped chars.
    // Also allow '=' to be escaped.
    private static final char[] allowedEscapeChars = {
        ',', '\"', '\\', '+','<', '>', ';', '='  
    };
    
    private static final Pattern WS = Pattern.compile("\\s+");

    public static final int KEY_SEQUENCE_FORMAT_NUMERIC                        = 1; 
    public static final int KEY_SEQUENCE_FORMAT_ALPHANUMERIC                   = 2; 
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC      = 4; 
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC = 8; 

    /**
     * Strips all special characters from a string by replacing them with a forward slash, '/'.
     * This method is used for various Strings, like SubjectDNs and usernames.
     *
     * @param str the string whose contents will be stripped.
     *
     * @return the stripped version of the input string.
     */
    public static String strip(String str) {
        if (str == null) {
            return null;
        }
    	StringBuffer buf = new StringBuffer(str);
		for (int i = 0; i< stripChars.length; i++) {
			int index = 0;
			int end = buf.length();
			while (index < end) {
				if (buf.charAt(index) == stripChars[i]) {
					// Found an illegal character. Replace it with a '/'.
					buf.setCharAt(index, '/');
				} else if (buf.charAt(index) == '\\') {
					// Found an escape character.
					if (index + 1 == end) {
						// If this is the last character we should remove it.
						buf.setCharAt(index, '/');
					} else if (!isAllowed(buf.charAt(index+1))) {
						// We did not allow this character to be escaped. Replace both the \ and the character with a single '/'.
						buf.setCharAt(index, '/');
						buf.deleteCharAt(index+1);
						end--;
					} else {
						index++;
					}
				}
				index++;
			}
		}
        return buf.toString();
    }
    
    /**
     * Checks if a string contains characters that would be potentially dangerous to use in an SQL query.
     *
     * @param str the string whose contents would be stripped.
     * @return true if some chars in the string would be stripped, false if not.
     * @see #strip
     */
    public static boolean hasSqlStripChars(String str) {
        if (str == null) {
            return false;
        }
		for (int i = 0; i< stripSqlChars.length; i++) {
			int index = 0;
			int end = str.length();
			while (index < end) {
				if (str.charAt(index) == stripSqlChars[i] && stripSqlChars[i] != '\\') {
					// Found an illegal character.
					return true;
				} else if (str.charAt(index) == '\\') {
					// Found an escape character.
					if (index + 1 == end) {
						// If this is the last character.
						return true;
					} else if (!isAllowed(str.charAt(index+1))) {
						// We did not allow this character to be escaped.
						return true;
					}
					index++;	// Skip one extra..
				}
				index++;
			}
		}
		return false;
    }

    /** Checks if a character is an allowed escape character according to allowedEscapeChars
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
    
    /** Converts ip-adress octets, according to ipStringToOctets
     * to human readable string in form 10.1.1.1 for ipv4 adresses.
     * 
     * @param octets
     * @return ip address string, null if input is invalid
     * @see #ipStringToOctets(String)
     */
    public static String ipOctetsToString(byte[] octets) {
    	String ret = null;
    	if (octets.length == 4){
    		String ip = "";
    		// IPv4 address
    		for (int i = 0; i < 4; i++) {
    			// What is going on there is that we are promoting a (signed) byte to int, 
    			// and then doing a bitwise AND operation on it to wipe out everything but 
    			// the first 8 bits. Because Java treats the byte as signed, if its unsigned 
    			// value is above > 127, the sign bit will be set, and it will appear to java 
    			// to be negative. When it gets promoted to int, bits 0 through 7 will be the 
    			// same as the byte, and bits 8 through 31 will be set to 1. So the bitwise 
    			// AND with 0x000000FF clears out all of those bits. 
    			// Note that this could have been written more compactly as; 0xFF & buf[index]
    			int intByte = (0x000000FF & ((int)octets[i]));
    			short t = (short)intByte;
        		if (StringUtils.isNotEmpty(ip)) {
        			ip += ".";
        		}
        		ip += t;
    		}
    		ret = ip;
    	}
    	// TODO: IPv6
    	return ret;
    }
    
    /** Converts an IP-address string to octets of binary ints. 
     * ipv4 is of form a.b.c.d, i.e. at least four octets for example 192.168.5.54 
     * ipv6 is of form a:b:c:d:e:f:g:h, for example 2001:0db8:85a3:0000:0000:8a2e:0370:7334
     * 
     * Result is tested with openssl, that it's subjectAltName displays as intended.
     * 
     * @param str string form of ip-address
     * @return octets, null if input format is invalid
     */
    public static byte[] ipStringToOctets(String str) {
        String[] toks = str.split("[.:]");
        if (toks.length == 4) {
            // IPv4 address such as 192.168.5.45
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
            // IPv6 address such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            byte[] ret = new byte[16];
            int ind = 0;
            for (int i = 0;i<toks.length;i++) {
                int t = Integer.parseInt(toks[i], 16);
                if (t>0xFFFF) {
                    log.error("IPv6 address '"+str+"' contains part > 0xFFFF.");
                    return null;
                }
                int t1 = t >> 8;
    		    int b1 = t1 & 0x00FF;
                //int b1 = t & 0x00FF;
                ret[ind++] = (byte)b1;
                //int b2 = t & 0xFF00;
                int b2 = t & 0x00FF;
                ret[ind++] = (byte)b2;
            }
            return ret;
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
     * "B64:<base64 encoded string>".
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
            s1 = new String(s.substring(4));
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
        if (s.startsWith("OBF:")) {
            s=s.substring(4);
        }
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
    private static byte[] getSalt() throws UnsupportedEncodingException {
        final String saltStr = "1958473059684739584hfurmaqiekcmq";
        return saltStr.getBytes("UTF-8");
    }
    private static final char[] p = deobfuscate("OBF:1m0r1kmo1ioe1ia01j8z17y41l0q1abo1abm1abg1abe1kyc17ya1j631i5y1ik01kjy1lxf").toCharArray();
    private static final int iCount = 100;
    public static String pbeEncryptStringWithSha256Aes192(String in) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
    	if (CryptoProviderTools.isUsingExportableCryptography()) {
    		log.warn("Obfuscation not possible due to weak crypto policy.");
    		return in;
    	}
        final Digest digest = new SHA256Digest();
        
        final PKCS12ParametersGenerator   pGen = new PKCS12ParametersGenerator(digest);
        pGen.init(
                PBEParametersGenerator.PKCS12PasswordToBytes(p),
                getSalt(),
                iCount);
        
        final ParametersWithIV params = (ParametersWithIV)pGen.generateDerivedParameters(192, 128);
        final SecretKeySpec   encKey = new SecretKeySpec(((KeyParameter)params.getParameters()).getKey(), "AES");
        final Cipher          c;
        c = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(params.getIV()));
        
        final byte[]          enc = c.doFinal(in.getBytes("UTF-8"));
        
        final byte[] hex = Hex.encode(enc);
        return new String(hex);
    }
    
    public static String pbeDecryptStringWithSha256Aes192(String in) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException {
    	if (CryptoProviderTools.isUsingExportableCryptography()) {
    		log.warn("De-obfuscation not possible due to weak crypto policy.");
    		return in;
    	}

    	final String algorithm = "PBEWithSHA256And192BitAES-CBC-BC";
        final Cipher c = Cipher.getInstance(algorithm, "BC");
        final PBEKeySpec          keySpec = new PBEKeySpec(p, getSalt(), iCount);
        final SecretKeyFactory    fact = SecretKeyFactory.getInstance(algorithm, "BC");
        
        c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));
        
        final byte[] dec = c.doFinal(Hex.decode(in.getBytes("UTF-8")));
        return new String(dec);
    }
    
    public static String passwordDecryption(final String in, String sDebug) {
        try {
            final String tmp = pbeDecryptStringWithSha256Aes192(in);
            log.debug("Using encrypted "+sDebug);
            return tmp;
        } catch( Throwable t ) {
            log.debug("Using cleartext "+sDebug);
            return in;
        }
    }
    
    public static String incrementKeySequence(int keySequenceFormat, String oldSequence) {
    	if (log.isTraceEnabled()) {
        	log.trace(">incrementKeySequence: " + keySequenceFormat + ", " + oldSequence);
    	}
        // If the sequence does not contain any number in it at all, we can only return the same
        String ret = null; 
        // If the sequence starts with a country code we will increment the remaining characters leaving
        // the first two untouched. Per character 10 [0-9] or 36 [0-9A-Z] different values 
        // can be coded
        if (keySequenceFormat == KEY_SEQUENCE_FORMAT_NUMERIC) {
            ret = incrementNumeric(oldSequence);
        } else if (keySequenceFormat == KEY_SEQUENCE_FORMAT_ALPHANUMERIC) {
            ret = incrementAlphaNumeric(oldSequence);
        } else if (keySequenceFormat == KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC) {
            String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            log.debug("countryCode: " + countryCode);
            String inc = incrementNumeric(oldSequence.substring(2));
            // Cut off the country code
            if (oldSequence.length() > 2 && inc != null) {
                ret = countryCode + inc;
            }
        } else if (keySequenceFormat == KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC) {
            String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            log.debug("countryCode: " + countryCode);
            String inc = incrementAlphaNumeric(oldSequence.substring(2));
            // Cut off the country code
            if (oldSequence.length() > 2 && inc != null) {
                ret = countryCode + inc;
            }
        }
        // unknown, fall back to old implementation
        if (ret == null) {
            ret = oldSequence;
            // A sequence can be 00001, or SE001 for example
            // Here we will strip any sequence number at the end of the key label and add the new sequence there
            // We will only count decimal (0-9) to ensure that we will not accidentally update the first to 
            // characters to the provided country code
            StringBuffer buf = new StringBuffer();
            for (int i = oldSequence.length()-1; i >= 0; i--) {
                char c = oldSequence.charAt(i);     
                if (CharUtils.isAsciiNumeric(c)) {
                    buf.insert(0, c);                       
                } else {
                    break; // at first non numeric character we break
                }
            }
            int restlen = oldSequence.length() - buf.length();
            String rest = oldSequence.substring(0, restlen);
    
            String intStr = buf.toString();
            if (StringUtils.isNotEmpty(intStr)) {
                Integer seq = Integer.valueOf(intStr);
                seq = seq + 1;
                // We want this to be the same number of numbers as we converted and incremented 
                DecimalFormat df = new DecimalFormat("0000000000".substring(0,intStr.length()));
                String fseq = df.format(seq);
                ret = rest + fseq;
                if (log.isTraceEnabled()) {
                    log.trace("<incrementKeySequence: "+ ret);          
                }
            } else {
                log.info("incrementKeySequence - Sequence does not contain any nummeric part: "+ret);
            }
        }
    	return ret;
    }
    
    private static String incrementNumeric(String s) {
        // check if input is valid, if not return null
        if (!s.matches("[0-9]{1,5}")) {
            return null;
        }
        int len = s.length();
        // Parse to int and increment by 1
        int incrSeq = Integer.parseInt(s, 10) + 1;
        // Reset if the maximum value is exceeded
        if (incrSeq == Math.pow(10, len)) {
            incrSeq = 0;
        }
        // Make a nice String again
        String newSeq = "00000" + Integer.toString(incrSeq, 10);
        newSeq = newSeq.substring(newSeq.length()-len);
        return newSeq.toUpperCase();
    }
    
    private static String incrementAlphaNumeric(String s) {
        // check if input is valid, if not return null
        if (!s.matches("[0-9A-Z]{1,5}")) {
            return null;
        }
        int len = s.length();
        // Parse to int and increment by 1
        int incrSeq = Integer.parseInt(s, 36) + 1;
        // Reset if the maximum value is exceeded
        if (incrSeq == Math.pow(36, len)) {
            incrSeq = 0;
        }
        // Make a nice String again
        String newSeq = "00000" + Integer.toString(incrSeq, 36);
        newSeq = newSeq.substring(newSeq.length()-len);
        return newSeq.toUpperCase();
    }
    
	/**
	 * Splits a string with semicolon separated and optionally double-quoted 
	 * strings into a collection of strings.
	 * <p>
	 * Strings that contains semicolon has to be quoted.
	 * Unbalanced quotes (the end quote is missing) is handled as if there 
	 * was a quote at the end of the string.
	 * <pre>
	 * Examples:
	 * splitURIs("a;b;c") =&gt; [a, b, c]
	 * splitURIs("a;\"b;c\";d") =&gt; [a, b;c, d]
	 * splitURIs("a;\"b;c;d") =&gt; [a, b;c;d]
	 * </pre>
	 * <p>
	 * See org.ejbca.core.model.ca.certextensions.TestCertificateExtensionManager#test03TestSplitURIs() 
	 * for more examples.
	 * @param dispPoints The semicolon separated string and which optionally 
	 * uses double-quotes
	 * @return A collection of strings
	 */
	public static Collection/*String*/ splitURIs(String dispPoints) {

        LinkedList/*String*/ result = new LinkedList/*String*/();

        dispPoints = dispPoints.trim();
        
        for(int i = 0; i < dispPoints.length(); i++) {
            int nextQ = dispPoints.indexOf('"', i);
            if(nextQ == i) {
                nextQ = dispPoints.indexOf('"', i+1);
                if(nextQ == -1) {
                    nextQ = dispPoints.length(); // unbalanced so eat(the rest)
                }
                // eat(to quote)
                result.add(dispPoints.substring(i+1, nextQ).trim());
                i = nextQ;
            } else {
                int nextSep = dispPoints.indexOf(';', i);
                if(nextSep != i) {   
	                if(nextSep != -1) { // eat(to sep)
	                    result.add(dispPoints.substring(i, nextSep).trim());
	                    i = nextSep;
	                } else if (i < dispPoints.length()) { // eat(the rest)
	                    result.add(dispPoints.substring(i).trim());
	                    break;
	                }
                } // Else skip
            }
        }
        return result;
    }
    
} // StringTools
