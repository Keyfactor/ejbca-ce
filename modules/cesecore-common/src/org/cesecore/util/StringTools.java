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
package org.cesecore.util;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.ConfigurationHolder;

import com.google.common.net.InternetDomainName;

/**
 * This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id$
 */
public final class StringTools {
    private static final Logger log = Logger.getLogger(StringTools.class);

    private static Pattern VALID_IPV4_PATTERN = null;
    private static Pattern VALID_IPV6_PATTERN = null;
    private static Pattern windowsOrMacNewlines = Pattern.compile("\r\n?"); // Matches Windows \r\n and Mac \r
    private static final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
    private static final String ipv6Pattern = "(([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}|[0-9a-f]{1,4}(:[0-9a-f]{1,4})*::[0-9a-f]{1,4}(:[0-9a-f]{1,4})*)";

    static {
      try {
        VALID_IPV4_PATTERN = Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
        VALID_IPV6_PATTERN = Pattern.compile(ipv6Pattern, Pattern.CASE_INSENSITIVE);
      } catch (PatternSyntaxException e) {
        log.error("Unable to compile IP address validation pattern", e);
      }
    }

    private StringTools() {
    } // Not for instantiation

    /**
     * Class that will be used to see if a character belong to a specific category.
     * This is a singleton, with static initialization, meaning that it is thread safe. It also means that the
     * CesecoreConfiguration.getForbiddenCharacters() can not be changed dynamically, but a re-start of EJBCA is needed
     * if this calue is changed in the properties file
     *
     */
    public static class CharSet {
        public static CharSet INSTANCE = new CharSet(CesecoreConfiguration.getForbiddenCharacters());

        private Set<Character> charSet = null;
        /**
         * Create a set of characters from a char array.
         * @param array
         */
        private CharSet(char[] array) {
            final Set<Character> set = new HashSet<>();
            for (final char c : array) {
                set.add(c);
            }
            this.charSet = set;
        }
        /**
         * Check if a character is belonging to the set.
         * @param c the character to test
         * @return true if belonging
         */
        boolean contains(char c) {
            return this.charSet.contains(c);
        }

        /** Used to reset the value so we can JUnit test the class */
        public static void reset() {
            INSTANCE = new CharSet(CesecoreConfiguration.getForbiddenCharacters());
        }
    }

    // Characters that are not allowed in XSS compatible strings
    private static final CharSet STRIP_XSS = new CharSet(new char[]{'<', '>'});
    // Characters that are not allowed in strings that may be used in db queries
    private static final CharSet STRIP_SQL_CHARS = new CharSet(new char[]{ '\'', '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?', '$', '~' });
    // Characters that are not allowed in Subject Directory Attributes
    private static final CharSet STRIP_SDATT_STRIP_CHARS = new CharSet(new char[]{'\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?', '$', '~' });
    // Characters that are not allowed in strings that may be used in db queries, assuming single quote is escaped
    private static final CharSet STRIP_SQL_CHARS_SINGLE_QUOTE_ESCAPED = new CharSet(new char[]{ '\"', '\n', '\r', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?', '$', '~' });
    // Characters that are not allowed in filenames
    private static final CharSet STRIP_FILENAME_CHARS = new CharSet(new char[]{ '\0', '\n', '\r', '/', '\\', '?', '%', '$', '*', ':', ';', '|', '\"', '\'', '`', '<', '>' });
    // Characters that are allowed to escape in strings.
    // RFC 2253, section 2.4 lists ',' '"' '\' '+' '<' '>' ';' as valid escaped chars.
    // Also allow '=' to be escaped.
    private static final CharSet ALLOWED_ESCAPE_CHARS = new CharSet(new char[]{ ',', '\"', '\\', '+', '<', '>', ';', '=', '#', ' ' });

    private static final Pattern WS = Pattern.compile("\\s+");    
    private static final Pattern SPACE_AND_COLON = Pattern.compile("[: ]");


    /** plain numeric format 00001, 00002, etc */
    public static final int KEY_SEQUENCE_FORMAT_NUMERIC = 1;
    /** alphanumeric format, i.e. hex AAAAA, AAAAB, etc*/
    public static final int KEY_SEQUENCE_FORMAT_ALPHANUMERIC = 2;
    /** country code followed by a numeric sequence, i.e. SE001, SE002, etc */
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC = 4;
    /** country code followed by a alphanumeric sequence, i.e. SEFAA, SEFAB, etc */
    public static final int KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC = 8;

    /**
     * Converts every string in a list to lower case.
     * @param strings the strings to convert
     * @return all strings converted to lower case
     */
    public static List<String> toLowerCase(final List<String> strings) {
        final List<String> lowerCaseStrings = new ArrayList<>();
        for (final String string : strings) {
            lowerCaseStrings.add(string.toLowerCase());
        }
        return lowerCaseStrings;
    }

    /**
     * Strips all special characters from a string by replacing them with a forward slash, '/'. This method is used for various Strings, like
     * SubjectDNs.
     *
     * @param str the string whose contents will be stripped.
     * @return the stripped version of the input string.
     */
    public static String strip(final String str) {
    	return strip(str, CharSet.INSTANCE);
    }

    /**
     * Strips '<' and '>' as well as all special characters from a string by replacing them with a forward slash, '/'.
     * @param str the string whose contents will be stripped.
     * @return the stripped version of the input string.
     */
    public static String stripUsername(final String str) {
        String xssStripped = strip(str, STRIP_XSS);
        return strip(xssStripped);
    }

    /**
     * Strips characters that are not allowed in filenames
     * @param str the string whose contents will be stripped.
     * @return the stripped version of the input string.
     */
    public static String stripFilename(final String str) {
        // The strip() method does not work here, because it replaces forbidden characters with /
        // Also, there's no need to unescape anything here.
        return stripWithEscapesDisallowed(str, STRIP_FILENAME_CHARS);
    }

    /**
     * Strips characters that are not allowed in filenames, and replaces spaces with underscores
     * @param str the string whose contents will be stripped.
     * @return the stripped version of the input string.
     */
    public static String stripFilenameReplaceSpaces(final String str) {
        return stripFilename(str.replace(' ', '_'));
    }

    /**
     * Removes all characters in stripThis from the given string
     * @param str original string, to be stripped.
     * @param stripThis set of characters that should be stripped.
     * @return the stripped string
     */
    private static String stripWithEscapesDisallowed(final String str, final CharSet stripThis) {
        if (str == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            if (!stripThis.contains(str.charAt(i))) {
                sb.append(str.charAt(i));
            }
        }
        return sb.toString();
    }

    /**
     * Removes control characters (characters 0-31) that should not be included in the server log.
     */
    public static String stripLog(final String str) {
        if (str == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) >= 32) {
                sb.append(str.charAt(i));
            }
        }
        return sb.toString();
    }

    /**
     * Characters from 'str' will be stripped like this:
     * any character that is in the 'stripThis' set will be replaced with '/'.
     * any character that is escaped (preceded with '\') and not in the {@value #ALLOWED_ESCAPE_CHARS} set will be replaced with '/'.
     * when a character is replaced with '/' and also escaped then the preceding escape character '\' will be removed.
     *
     * @param str the original string
     * @param stripThis set of characters that should be stripped.
     * @return the stripped string
     */
    private static String strip(final String str, final CharSet stripThis) {
        if (str == null) {
            return null;
        }
        final StringBuilder buf = new StringBuilder(str);
        int index = 0;
        int end = buf.length();
        while (index < end) {
            if (buf.charAt(index) == '\\') {
                // Found an escape character.
                if (index + 1 == end) {
                    // If this is the last character we should remove it.
                    buf.setCharAt(index, '/');
                } else if (!isAllowedEscape(buf.charAt(index + 1))) {
                    // We did not allow this character to be escaped. Replace both the \ and the character with a single '/'.
                    buf.setCharAt(index, '/');
                    buf.deleteCharAt(index + 1);
                    end--;
                } else {
                    index++;
                }
            } else if ( stripThis.contains( buf.charAt(index)) ) {
                // Illegal character. Replace it with a '/'.
                buf.setCharAt(index, '/');
            }
            index++;
        }
        final String result = buf.toString();
        if ( log.isDebugEnabled() && !result.equals(str)) {
            log.debug("Some chars stripped. Was '"+str+"' is now '"+result+"'.");
        }
        return result;
    }

    /**
     * Checks if a string contains characters that would be potentially dangerous to use in an SQL query.
     *
     * @param str the string whose contents would be verified.
     * @return the offending characters with descriptions, or an empty set otherwise.
     * @see #strip
     */
    public static  Set<String> hasSqlStripChars(final String str) {
    	return hasStripChars(str, STRIP_SQL_CHARS);
    }

    /**
     * Checks if a Subject Directory Attribute contains characters that would be potentially dangerous to use
     * in an SQL query.
     *
     * @param str the string whose contents would be verified.
     * @return the offending characters with descriptions, or an empty set otherwise.
     * @see #strip
     */
    public static  Set<String> hasSDAttrStripChars(final String str) {
    	return hasStripChars(str, STRIP_SDATT_STRIP_CHARS);
    }

    /**
     * Checks if a string contains characters that would be potentially dangerous to use in a non-parameterized SQL query,
     * assuming the the '-char is properly handled (escaped).
     *
     * @param str the string whose contents would be stripped.
     * @return the offending characters with descriptions, or an empty set otherwise.
     * @see #strip
     */
    public static  Set<String> hasSqlStripCharsAssumingSingleQuoteEscape(final String str) {
        return hasStripChars(str, STRIP_SQL_CHARS_SINGLE_QUOTE_ESCAPED);
    }

    /**
     * Checks if a string contains characters that would be potentially dangerous to use as DN, username etc.
     *
     * @param str the string whose contents would be stripped.
     * @return the offending characters with descriptions, or an empty set otherwise.
     * @see #strip
     */
    public static  Set<String> hasStripChars(final String str) {
    	return hasStripChars(str, CharSet.INSTANCE);
    }

    /**
     * Check if 'str' has any chars that should be stripped by a call to {@link #strip(String, CharSet)}.
     * @param str the string to be tested.
     * @param checkThese characters that must be stripped.
     * @return the offending characters with descriptions, or an empty set otherwise.
     */
    private static Set<String> hasStripChars(final String str, final CharSet checkThese) {
        Set<String> result = new HashSet<>();
        if (str == null) {
            return result;
        }
        int index = 0;
        final int end = str.length();
        while (index < end) {
            if (str.charAt(index) == '\\') {
                // Found an escape character.
                if (index + 1 == end) {
                    // If this is the last character.
                     result.add("A trailing escape charater ('\').");
                     break;
                }
                if (!isAllowedEscape(str.charAt(index + 1))) {
                    result.add("Character that may not be escaped: " + str.charAt(index + 1));
                    break;
                }
                index++; // Skip one extra..
            } else if ( checkThese.contains(str.charAt(index)) ) {
                // Found an illegal character.
                result.add("'" + str.charAt(index) + "'");
            }
            index++;
        }
        return result;
    }

    /**
     * Checks if a character is an allowed escape character according to ALLOWED_ESCAPE_CHARS
     *
     * @param ch the char to check
     * @return true if char is an allowed escape character, false if now
     */
    private static boolean isAllowedEscape(final char ch) {
        return ALLOWED_ESCAPE_CHARS.contains(ch) && !CharSet.INSTANCE.contains(ch);
    }

    /**
     * Strips all whitespace including space, tabs, newlines etc from the given string.
     *
     * @param str the string
     * @return the string with all whitespace removed
     * @since 2.1b1
     */
    public static String stripWhitespace(final String str) {
        if (str == null) {
            return null;
        }
        return WS.matcher(str).replaceAll("");
    }
    
    /**
     * Remove all whitespace and colon
     * Remove "0x" if the serialNumber from input contain a "0x" prefix
     *
     * @param str
     * @return a string/serialNumber from input without whitespace,colon and "0x" prefix, null if input is invalid
     */
    public static String removeAllWhitespaceAndColon(final String str) {
        if(str == null) {
            return null;
        }        
        return SPACE_AND_COLON.matcher(StringUtils.removeStart(str, "0x")).replaceAll("");
    }

    /**
     * Converts ip-adress octets, according to ipStringToOctets to human readable string in form 10.1.1.1 for ipv4 adresses.
     *
     * @param octets ip-adress
     * @return ip address string, null if input is invalid
     * @see #ipStringToOctets(String)
     */
    public static String ipOctetsToString(final byte[] octets) {
        String ret = null;
        if (octets.length == 4) {
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
                final int intByte = 0x000000FF & octets[i];
                final short t = (short) intByte; // NOPMD, we need short
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

    /**
     * Converts an IP-address string to octets of binary ints. ipv4 is of form a.b.c.d, i.e. at least four octets for example 192.168.5.54 ipv6 is of
     * form a:b:c:d:e:f:g:h, for example 2001:0db8:85a3:0000:0000:8a2e:0370:7334
     *
     * Result is tested with openssl, that it's subjectAltName displays as intended.
     *
     * @param str string form of ip-address
     * @return octets, empty array if input format is invalid, never null
     */
    public static byte[] ipStringToOctets(final String str) {
        byte[] ret = null;
        if (StringTools.isIpAddress(str)) {
            try {
                final InetAddress adr = InetAddress.getByName(str);
                ret = adr.getAddress();
            } catch (UnknownHostException e) {
                log.info("Error parsing ip address (ipv4 or ipv6): ", e);
            }
        }
        if (ret == null) {
            log.info("Not a IPv4 or IPv6 address, returning empty array.");
            ret = new byte[0];
        }
        return ret;
    }

    /**
     * Determine if the given string is a valid IPv4 or IPv6 address.  This method
     * uses pattern matching to see if the given string could be a valid IP address.
     * Snitched from http://www.java2s.com/Code/Java/Network-Protocol/DetermineifthegivenstringisavalidIPv4orIPv6address.htm
     * Under LGPLv2 license.
     *
     * @param ipAddress A string that is to be examined to verify whether or not
     *  it could be a valid IP address.
     * @return <code>true</code> if the string is a value that is a valid IP address,
     *  <code>false</code> otherwise.
     */
    public static boolean isIpAddress(String ipAddress) {
      Matcher m1 = StringTools.VALID_IPV4_PATTERN.matcher(ipAddress);
      if (m1.matches()) {
        return true;
      }
      Matcher m2 = StringTools.VALID_IPV6_PATTERN.matcher(ipAddress);
      return m2.matches();
    }

    /**
     * Determines if the given string is a valid URI
     * @param uri to verify
     * @return true if input is a valid URI
     */
    public static boolean isValidUri(final String uri) {
        try {
            new URL(uri).toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }
        return true;
    }
    
    /**
     * Check if a string constitutes a valid hostname for the dNSName attribute of the Subject
     * Alternative Name X.509 certificate extension. This method does NOT check if the hostname
     * can be resolved to an IP address, is registered with ICANN ect. Instead, the following
     * checks are performed:
     * <ul>
     * <li>Any leading wildcard is stripped.</li>
     * <li>The DNS name is not allowed to end with a dot.</li>
     * <li>The input most be a syntactically valid hostname as per RFC 2181 and RFC 3490.</li>
     * <li>T̶h̶e̶ ̶d̶o̶m̶a̶i̶n̶ ̶n̶a̶m̶e̶ ̶m̶u̶s̶t̶ ̶n̶o̶t̶ ̶b̶e̶ ̶a̶ ̶r̶e̶g̶i̶s̶t̶r̶y̶ ̶s̶u̶f̶f̶i̶x̶.</li>
     * <li>T̶h̶e̶ ̶d̶o̶m̶a̶i̶n̶ ̶n̶a̶m̶e̶ ̶m̶u̶s̶t̶ ̶n̶o̶t̶ ̶b̶e̶ ̶a̶ ̶t̶o̶p̶-̶l̶e̶v̶e̶l̶ ̶d̶o̶m̶a̶i̶n̶.</li>
     * </ul>
     * This implementation is null-safe and relies on Guava's <code>InternetDomainName</code>
     * implementation for hostname validation a̶n̶d̶ ̶i̶d̶e̶n̶t̶i̶f̶i̶c̶a̶t̶i̶o̶n̶ ̶o̶f̶ ̶r̶e̶g̶i̶s̶t̶r̶y̶ ̶s̶u̶f̶f̶i̶c̶e̶s̶ ̶a̶n̶d̶ ̶T̶L̶D̶s̶.
     * <p>
     * Identification of TLDs and registry suffices are currently not supported because this
     * functionality requires a newer version of the Guava library.
     * @param dnsName the DNS name to check
     * @return true if the input is valid SAN dNSName attribute value
     */
    public static boolean isValidSanDnsName(String dnsName) {
        if (dnsName == null) {
            return false;
        }
        // FQDN ending with a dot is accepted by Guava, so we need to check for that separately
        if (dnsName.endsWith(".")) {
            return false;
        }
        // Strip any leading wildcard
        dnsName = dnsName.startsWith("*.") ? dnsName.substring(2) : dnsName;
        return InternetDomainName.isValid(dnsName);
        // TODO Once we get Guava >=23.4 (requires Java 8)
        //final InternetDomainName internetDomainName = InternetDomainName.from(dnsName);
        //return !internetDomainName.isRegistrySuffix() && !internetDomainName.isTopLevelDomain();
    }

    /**
     * Takes input and converts to Base64 on the format "B64:<base64 endoced string>", if the string is not null or empty.
     *
     * @param s String to base64 encode
     * @return Base64 encoded string, or original string if it was null or empty
     */
    public static String putBase64String(final String s) {
    	return putBase64String(s, false);
    }

    /**
     * Takes input and converts to Base64 on the format "B64:<base64 endoced string>", if the string is not null or empty.
     *
     * @param s String to base64 encode
     * @param dontEncodeAsciiPrintable if the String is made up of pure ASCII printable characters, we will not B64 encode it
     * @return Base64 encoded string, or original string if it was null or empty
     */
    public static String putBase64String(final String s, boolean dontEncodeAsciiPrintable) {
        if (StringUtils.isEmpty(s)) {
            return s;
        }
        if (s.startsWith("B64:")) {
            // Only encode once
            return s;
        }
        if (dontEncodeAsciiPrintable && StringUtils.isAsciiPrintable(s)) {
        	return s;
        }
        // Since we used getBytes(s, StandardCharsets.UTF_8) in this method, we must use UTF-8 when doing the reverse in another method
        return "B64:" + new String(Base64.encode(s.getBytes(StandardCharsets.UTF_8), false));
    }

    /**
     * Takes a string given as input and converts it from Base64 if the string
     * begins with the case-insensitive prefix b64, i.e. is on format "b64:<base64 encoded string>".
     *
     * @param input String to Base64 decode
     * @return Base64 decoded string, or original string if it was not base64 encoded
     */
    public static String getBase64String(final String input) {
        if (StringUtils.isEmpty(input)) {
            return input;
        }
        if (!input.toLowerCase().startsWith("b64:")) {
            return input;
        }
        final String base64Data = input.substring(4);
        if (base64Data.length() == 0) {
            return input;
        }
        try {
            // Since we used getBytes(s, StandardCharsets.UTF_8) in the method putBase64String, we must use UTF-8 when doing the reverse
            return new String(Base64.decode(base64Data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        } catch (DecoderException e) {
            return input;
        }
    }

    /**
     * Converts hexadecimal string to BigInteger. Hex prefix (0x) is ignored
     * @param hexString HEX value with or without '0x' prefix
     * @return BigInteger value
     */
    public static BigInteger getBigIntegerFromHexString(String hexString) {
        if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
            hexString = hexString.substring(2, hexString.length());
        }
        return new BigInteger(hexString, 16);
    }

    /** Obfuscates a String if it does not already start with "OBF:"
     * @see #obfuscate(String)
     * @param s string to obfuscate
     * @return an obfuscated string, or the original if it started with OBF:
     */
    public static String obfuscateIfNot(final String s) {
        if (s.startsWith("OBF:")) {
            return s;
        }
        return obfuscate(s);
    }
    /**
     * Makes a string "hard" to read. Does not provide any real security, but at least lets you hide passwords so that people with no malicious
     * intent don't accidentally stumble upon information they should not have.
     *
     * @param s string to obfuscate
     * @return an obfuscated string, or same as input if null or empty
     */
    public static String obfuscate(final String s) {
        // Don't try to obfuscate null or empty strings
        if (StringUtils.isEmpty(s)) {
            return s;
        }
        final StringBuilder buf = new StringBuilder("OBF:");
        final byte[] b = s.getBytes();

        for (int i = 0; i < b.length; i++) {
            final byte b1 = b[i];
            final byte b2 = b[s.length() - (i + 1)];
            final int i1 = b1 + b2 + 127;
            final int i2 = b1 - b2 + 127;
            final int i0 = i1 * 256 + i2;
            final String x = Integer.toString(i0, 36);

            switch (x.length()) {
            case 1:
            case 2:
            case 3:
                buf.append('0');
                break;
            default:
                buf.append(x);
                break;
            }
        }
        return buf.toString();

    }

    /** Deobfuscates a String if it does start with "OBF:"
     * @see #deobfuscate(String)
     * @param s string to deobfuscate
     * @return a deobfuscated string, or the original if it does not start with OBF:
     */
    public static String deobfuscateIf(final String s) {
        if (s != null && s.startsWith("OBF:")) {
            return deobfuscate(s);
        }
        return s;
    }
    /**
     * Retrieves the clear text from a string obfuscated with the obfuscate methods
     *
     * @param in obfuscated string, usually (but not necessarily) starts with OBF:
     * @return plain text string, or original if it was empty
     */
    public static String deobfuscate(final String in) {
        String s = in;
        if (s != null && s.startsWith("OBF:")) {
            s = s.substring(4);
        }
        if (StringUtils.isEmpty(s)) {
            return s;
        }
        byte[] b = new byte[s.length() / 2];
        int l = 0;
        for (int i = 0; i < s.length(); i += 4) {
            final String x = s.substring(i, i + 4);
            final int i0 = Integer.parseInt(x, 36);
            final int i1 = (i0 / 256);
            final int i2 = (i0 % 256);
            b[l++] = (byte) ((i1 + i2 - 254) / 2);
        }

        return new String(b, 0, l);
    }

    private static String getEncryptionVersion() {
        return "encv1";
    }

    /**
     * Method takes an encrypted string (by using the methods in this class) and returns the method used to encrypt the string with
     * @param in indata that is encrypted/obfuscated
     * @return "legacy" for old data, "encv1" or later to describe a specific version
     */
    public static String getEncryptVersionFromString(final String in) {
        if (in != null && in.contains(":")) {
            // this is a newer version that has encryption version and parameters in it
            String[] strs = StringUtils.split(in, ':');
            if (strs == null || strs.length != 4) {
                log.warn("Input contains : but is not an encryption string from EJBCA (with 4 fields).");
            } else {
                return strs[0];
            }
        } else {
            try {
                Hex.decode(in);
            } catch (DecoderException e) {
                // it means it was not hex encoded
                return "none";
            }

        }
        return "legacy";
    }

    private static byte[] getSalt() {
        final boolean legacy = DEFAULT_P.equals(ConfigurationHolder.getString("password.encryption.key"));
        if (legacy) {
            log.debug("Using legacy password encryption/decryption");
            return getDefaultSalt();
        } else {
            // Generate 32 random bytes
            final SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return bytes;
        }
    }

    private static byte[] getDefaultSalt() {
        return "1958473059684739584hfurmaqiekcmq".getBytes(StandardCharsets.UTF_8);
    }

    private static final String DEFAULT_P = deobfuscate("OBF:1m0r1kmo1ioe1ia01j8z17y41l0q1abo1abm1abg1abe1kyc17ya1j631i5y1ik01kjy1lxf");

    private static int getDefaultCount() {
        return 100;
    }

    /** number of rounds for password based encryption. FIXME 100 is not secure and can easily be broken.
     */
    private static int getCount() {
        final String str = ConfigurationHolder.getString("password.encryption.count");
        final boolean legacy = DEFAULT_P.equals(ConfigurationHolder.getString("password.encryption.key"));
        if (StringUtils.isNumeric(str) && !legacy) {
            return Integer.valueOf(str);
        } else {
            return getDefaultCount(); // Old default value before EJBCA 6.8.0
        }
    }

    /**
     * Method used for encrypting a string.
     *
     * Note that this method does provide limited security (e.g. DBA's won't be able to access encrypted passwords in database)
     * as long as the 'password.encryption.key' is set, otherwise, it won't provide any real encryption more than obfuscation.
     */
    public static String pbeEncryptStringWithSha256Aes192(final String in) {
        char[] p = ConfigurationHolder.getString("password.encryption.key").toCharArray();
        return pbeEncryptStringWithSha256Aes192(in, p);
    }

    /**
     *
     * @param in clear text string to encrypt
     * @param p encryption passphrase
     * @return hex encoded encrypted data in form "encryption_version:salt:count:encrypted_data" or clear text string if no strong crypto is available (Oracle JVM without unlimited strength crypto policy files)
     */
    public static String pbeEncryptStringWithSha256Aes192(final String in, char[] p) {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        if (CryptoProviderTools.isUsingExportableCryptography()) {
            log.warn("Encryption not possible due to weak crypto policy.");
            return in;
        }
        final byte[] salt = getSalt();
        final int count = getCount();

        final PBEKeySpec keySpec = new PBEKeySpec(p, salt, count);
        final Cipher c;
        final String algorithm = "PBEWithSHA256And192BitAES-CBC-BC";
        final byte[] enc;
        try {
            c = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.ENCRYPT_MODE, fact.generateSecret(keySpec));
            enc = c.doFinal(in.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard coded algorithm " + algorithm + " was not found.", e);
        } catch(NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not installed.", e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for hard coded algorithm " + algorithm + " was not found.", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password-Based Encryption (PBE) failed.", e);
        }
        // Create a return value which is "encryption_version:salt:count:encrypted_data"
        StringBuilder ret = new StringBuilder(64);
        final boolean legacy = DEFAULT_P.equals(ConfigurationHolder.getString("password.encryption.key"));
        if (legacy) {
            // In the old legacy system we only return the encrypted data without extra info
            ret.append(Hex.toHexString(enc));
        } else {
            ret.append(getEncryptionVersion()).append(':').append(Hex.toHexString(salt)).append(':').append(count).append(':').append(Hex.toHexString(enc));
        }
        if (log.isTraceEnabled()) {
            log.trace("Encrypted data: "+ret.toString());
        }
        return ret.toString();
    }

    /**
    *
    * @param in hex encoded encrypted string in form "encryption_version:salt:count:encrypted_data", or just "encrypted_data" for older versions
    * @return decrypted clear text string
    */
   public static String pbeDecryptStringWithSha256Aes192(final String in) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
       char[] p = ConfigurationHolder.getString("password.encryption.key").toCharArray();
       return pbeDecryptStringWithSha256Aes192(in, p);
   }
    
    /**
     *
     * @param in hex encoded encrypted string in form "encryption_version:salt:count:encrypted_data", or just "encrypted_data" for older versions
     * @param p decryption passphrase
     * @return decrypted clear text string
     */
    public static String pbeDecryptStringWithSha256Aes192(final String in, char[] p) throws IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, InvalidKeySpecException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        if (CryptoProviderTools.isUsingExportableCryptography()) {
            log.warn("Decryption not possible due to weak crypto policy.");
            return in;
        }
        final byte[] salt;
        String data = in;
        int count;
        if (in != null && in.contains(":")) {
            // this is a newer version that has encryption version and parameters in it
            String[] strs = StringUtils.split(in, ':');
            if (strs == null || strs.length != 4) {
                log.warn("Input contains : but is not an encryption string from EJBCA (with 4 fields).");
                return in;
            }
            salt = Hex.decode(strs[1].getBytes(StandardCharsets.UTF_8));
            count = Integer.valueOf(strs[2]);
            data = strs[3];
        } else {
            salt = getDefaultSalt();
            count = getDefaultCount();
        }
        // We can do different handling here depending on version, but currently we only have one so.
        final String algorithm = "PBEWithSHA256And192BitAES-CBC-BC";
        try {
            final Cipher c = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final PBEKeySpec keySpec = new PBEKeySpec(p, salt, count);
            final SecretKeyFactory fact = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            c.init(Cipher.DECRYPT_MODE, fact.generateSecret(keySpec));
            final byte[] dec = c.doFinal(Hex.decode(data.getBytes(StandardCharsets.UTF_8)));
            return new String(dec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hard coded algorithm " + algorithm + " was not found.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider was not installed.", e);
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException("Padding for hard coded algorithm " + algorithm + " was not found.", e);
        }

    }

    /** Method to handle different versions of password encryption transparently
     * 
     * @param in The encrypted or clear text password to try to decrypt
     * @param sDebug A message to put in the debug log indicating where the password came from, for example 'autoactivation pin', do NOT put the password itself here
     * @return The decrypted password, or same as input if it was not encrypted
     */
    public static String passwordDecryption(final String in, final String sDebug) {
        try {
            final String tmp = pbeDecryptStringWithSha256Aes192(in, ConfigurationHolder.getString("password.encryption.key").toCharArray());
            if (log.isDebugEnabled()) {
                log.debug("Using encrypted " + sDebug);
            }
            return tmp;
        } catch (Throwable t) { // NOPMD: we want to catch everything here
            try {
                final String tmp = pbeDecryptStringWithSha256Aes192(in, ConfigurationHolder.getDefaultValue("password.encryption.key").toCharArray());
                log.warn("Using encrypted " + sDebug + " (falling back to default 'password.encryption.key')");
                return tmp;
            } catch (Throwable t2) { // NOPMD: we want to catch everything here
                if (in.matches("[0-9a-fA-F]+") && in.length() % 32 == 0) { // If input is hexadecimal and its length is multiple of 32 (i.e. 16 bytes, AES block size) we assume it is an encrypted password.
                    log.error("Password decryption failed. 'password.encryption.key' might have been modified more than once.");
                }
                if (log.isDebugEnabled()) {
                    log.debug("Using cleartext " + sDebug);
                }
                return in;
            }
        }
    }

    public static String incrementKeySequence(final int keySequenceFormat, final String oldSequence) {
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
            final String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            if (log.isDebugEnabled()) {
                log.debug("countryCode: " + countryCode);
            }
            final String inc = incrementNumeric(oldSequence.substring(2));
            // Cut off the country code
            if (oldSequence.length() > 2 && inc != null) {
                ret = countryCode + inc;
            }
        } else if (keySequenceFormat == KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC) {
            final String countryCode = oldSequence.substring(0, Math.min(2, oldSequence.length()));
            if (log.isDebugEnabled()) {
                log.debug("countryCode: " + countryCode);
            }
            final String inc = incrementAlphaNumeric(oldSequence.substring(2));
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
            final StringBuilder buf = new StringBuilder();
            for (int i = oldSequence.length() - 1; i >= 0; i--) {
                final char c = oldSequence.charAt(i);
                if (CharUtils.isAsciiNumeric(c)) {
                    buf.insert(0, c);
                } else {
                    break; // at first non numeric character we break
                }
            }
            final int restlen = oldSequence.length() - buf.length();
            final String rest = oldSequence.substring(0, restlen);

            final String intStr = buf.toString();
            if (StringUtils.isNotEmpty(intStr)) {
                Integer seq = Integer.valueOf(intStr);
                seq = seq + 1;
                // We want this to be the same number of numbers as we converted and incremented
                final DecimalFormat df = new DecimalFormat("0000000000".substring(0, intStr.length()));
                final String fseq = df.format(seq);
                ret = rest + fseq;
                if (log.isTraceEnabled()) {
                    log.trace("<incrementKeySequence: " + ret);
                }
            } else {
                log.info("incrementKeySequence - Sequence does not contain any nummeric part: " + ret);
            }
        }
        return ret;
    }

    private static String incrementNumeric(final String s) {
        // check if input is valid, if not return null
        if (!s.matches("[0-9]{1,5}")) {
            return null;
        }
        final int len = s.length();
        // Parse to int and increment by 1
        int incrSeq = Integer.parseInt(s, 10) + 1;
        // Reset if the maximum value is exceeded
        if (incrSeq == Math.pow(10, len)) {
            incrSeq = 0;
        }
        // Make a nice String again
        String newSeq = "00000" + Integer.toString(incrSeq, 10);
        newSeq = newSeq.substring(newSeq.length() - len);
        return newSeq.toUpperCase(Locale.ENGLISH);
    }

    private static String incrementAlphaNumeric(final String s) {
        // check if input is valid, if not return null
        if (!s.matches("[0-9A-Z]{1,5}")) {
            return null;
        }
        final int len = s.length();
        // Parse to int and increment by 1
        int incrSeq = Integer.parseInt(s, 36) + 1;
        // Reset if the maximum value is exceeded
        if (incrSeq == Math.pow(36, len)) {
            incrSeq = 0;
        }
        // Make a nice String again
        String newSeq = "00000" + Integer.toString(incrSeq, 36);
        newSeq = newSeq.substring(newSeq.length() - len);
        return newSeq.toUpperCase(Locale.ENGLISH);
    }

    /**
     * Splits a string with semicolon separated and optionally double-quoted strings into a collection of strings.
     * <p>
     * Strings that contains semicolon has to be quoted. Unbalanced quotes (the end quote is missing) is handled as if there was a quote at the end of
     * the string.
     *
     * <pre>
     * Examples:
     * splitURIs("a;b;c") =&gt; [a, b, c]
     * splitURIs("a;\"b;c\";d") =&gt; [a, b;c, d]
     * splitURIs("a;\"b;c;d") =&gt; [a, b;c;d]
     * </pre>
     * <p>
     * See org.ejbca.core.model.ca.certextensions.TestCertificateExtensionManager#test03TestSplitURIs() for more examples.
     *
     * @param dPoints The semicolon separated string and which optionally uses double-quotes
     * @return A collection of strings
     */
    public static Collection<String> splitURIs(String dPoints) {

        String dispPoints = dPoints.trim();

        final LinkedList<String> result = new LinkedList<>();
        for (int i = 0; i < dispPoints.length(); i++) {
            int nextQ = dispPoints.indexOf('"', i);
            if (nextQ == i) {
                nextQ = dispPoints.indexOf('"', i + 1);
                if (nextQ == -1) {
                    nextQ = dispPoints.length(); // unbalanced so eat(the rest)
                }
                // eat(to quote)
                result.add(dispPoints.substring(i + 1, nextQ).trim());
                i = nextQ;
            } else {
                final int nextSep = dispPoints.indexOf(';', i);
                if (nextSep != i) {
                    if (nextSep != -1) { // eat(to sep)
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

    /**
     * Parses the given string according to a specific format based on the certificate-data stored in the LogEntryData table in the database.
     *
     * @param certdata the string containing the certificate details
     * @return a String array with two elements, the first is the certificate serialnumber and the second one is the certificate issuerDN
     */
    public static String[] parseCertData(final String certdata) {
        if (certdata == null) {
            return null;
        }

        final String dnStrings = "([a-zA-Z0-9]+|(([0-9]+\\.)*[0-9]+))";
        final String formats[] = { "(^[0-9A-Fa-f]+), ?((" + dnStrings + "=[^,]+,)*(" + dnStrings + "=[^,]+)*)",
                "(^[0-9A-Fa-f]+) : DN : \"([^\"]*)\"( ?: SubjectDN : \"[^\"]*\")?"

        };

        String ret[] = null;

        for (String format : formats) {
            final Pattern p = Pattern.compile(format);
            final Matcher m = p.matcher(certdata);
            if (m.find()) {
                ret = new String[2];
                ret[0] = m.group(1);
                ret[1] = m.group(2);
                break;
            }
        }
        return ret;
    }

    /** @return the IP address of the X-Forwarded-For HTTP header with illegal chars replaced with '?'. IPv6 address hex chars are converted to lower case. */
    public static String getCleanXForwardedFor(final String rawHeaderValue) {
        if (rawHeaderValue==null) {
            return null;
        }
        /*
         * In EJBCA 6.3.2 and earlier we allowed "[^a-zA-Z0-9.:-_]". There is however no source
         * that non IP-addresses would be allowed.
         *
         * Closest thing to a standardized example is available in RFC 7239 where the example
         *  "X-Forwarded-For: 192.0.2.43, 2001:db8:cafe::17"
         * is used.
         */
        return rawHeaderValue.trim().toLowerCase().replaceAll("[^0-9a-f.,: ]", "?");
    }

    /** @return the items as a String separated by the provided separator. */
    public static String getAsStringWithSeparator(final String separator, final Collection<?> values) {
        final StringBuilder names = new StringBuilder();
        for (final Object value : values) {
            if (names.length()!=0) {
                names.append(separator);
            }
            names.append(value);
        }
        return names.toString();
    }

    /** Method that checks if an array contains a string, ignoring case
     * @param l array that we hope contains the string s (ignoring case)
     * @param s string that we hope is in the array l (ignoring case)
     * @return true if the string (ignoring case) is contained in the array
     */
    public static boolean containsCaseInsensitive(String[] l, String s){
        for (String string : l){
            if (string.equalsIgnoreCase(s)){
                return true;
            }
        }
        return false;
    }
//    /** Method that parses a date by format strings.
//     * @param dateString the date string.
//     * @param formatStrings the format strings.
//     * @return the date if it as possible to parse it, otherwise null. */
//    public static final Date tryParseDate(final String dateString, final List <String> formatStrings) {
//        Date result = null;
//        for (String formatString : formatStrings) {
//            try {
//                return new SimpleDateFormat(formatString).parse( dateString);
//            } catch(ParseException e) {
//                // NOOP
//                if (log.isTraceEnabled()) {
//                    log.trace("Coild not parse date " + dateString + " with format " + formatString);
//                }
//            }
//        }
//        return result;
//    }

    /**
     * Transforms a string of ids into a list of integer.
     * @param ids the id string
     * @param listSeparator the list separator.
     * @return a list of Integer.
     */
    public static List<Integer> idStringToListOfInteger(final String ids, final String listSeparator) {
        final ArrayList<Integer> result = new ArrayList<>();
        if (StringUtils.isNotEmpty(ids)) {
            for (final String id : ids.split(listSeparator)) {
                result.add(Integer.valueOf(id));
            }
        }
        return result;
    }

    /**
     * Checks a string for legal chars (not containing "/[^\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff_ 0-9@\\.\\*\\,\\-:\\/\\?\\'\\=\\(\\)\\|.]/g").
     * @param value the string value
     * @return true if the string only contains legal characters.
     */
    public static boolean checkFieldForLegalChars(final String value) {
        final String whiteList = "[\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff_ 0-9@\\.\\*\\,\\-:\\/\\?\\'\\=\\(\\)\\|.]+";
        return Pattern.matches(whiteList, value);
    }

    /** @return false of if the string contains any characters that are neither a letter (unicode) or an asciiPrintable character */
    public static boolean isAlphaOrAsciiPrintable(String str) {
        if (str == null) {
            return false;
        }
        int sz = str.length();
        for (int i = 0; i < sz; i++) {
            if ( !Character.isLetter(str.charAt(i)) && !CharUtils.isAsciiPrintable(str.charAt(i)) ) {
                return false;
            }
        }
        return true;
    }

    /** Takes two versions and compares the first and the second versions to each other
     * Compares the max amount of numbers on both. So 6.1.2.3,6.1.2 will try to compare 4 numbers, adding a 0, i.e. 6.1.2.3,6.1.2.0
     *
     * @param first a version number
     * @param second a version number
     * @return true of the first version is lower (1.0 < 2.0) than the second, false otherwise.
     **/
    public static boolean isLesserThan(final String first, final String second) {
        if (log.isTraceEnabled()) {
            log.trace("isLesserThan("+first+", "+second+")");
        }
        final String delimiter = "\\.";
        if (first == null) {
            if (second != null) {
                return true;    // No version is before a specified version
            }
            throw new IllegalArgumentException("First version argument may not be null");
        }
        if (second == null) {
            throw new IllegalArgumentException("Second version argument may not be null");
        }
        String[] firstSplit = first.split(delimiter);
        String[] secondSplit = second.split(delimiter);
        for (int i = 0; i < Math.max(firstSplit.length, secondSplit.length); i++) {
            String firstString;
            String secondString;
            String regex = "[^0-9].*";
            if (i >= firstSplit.length) {
                //We've gotten this far and passed the number of digits in first, so treat next first as a 0
                firstString = "0";
                secondString = secondSplit[i].replaceAll(regex, "");
            } else if (i >= secondSplit.length) {
                //We've gotten this far and passed the number of digits in second, so treat next second as a 0
                firstString = firstSplit[i].replaceAll(regex, "");    // Remove trailing Beta2, _alpha1 etc
                secondString = "0";
            } else {
                firstString = firstSplit[i].replaceAll(regex, "");    // Remove trailing Beta2, _alpha1 etc
                secondString = secondSplit[i].replaceAll(regex, "");
            }
            if (firstString.isEmpty()) {
                firstString = "0";  // Treat ".x" as ".0"
            }
            if (secondString.isEmpty()) {
                secondString = "0";
            }
            if (StringUtils.isNumeric(firstString) && StringUtils.isNumeric(secondString)) {
                final int firstNumber = Integer.valueOf(firstString);
                final int secondNumber = Integer.valueOf(secondString);
                if (firstNumber != secondNumber) {
                    return firstNumber < secondNumber;
                }
            } else {
                throw new IllegalArgumentException("Unable to parse version numbers.");
            }
        }
        //Versions must be the same then
        return false;
    }

    /**
     * Changes Windows (\r\n) and Mac (\r) line endings into \n line endings.
     * @param s Input string. May be null
     * @return Output string, or null if input string was null
     */
    public static String normalizeNewlines(final String s) {
        return s != null ? windowsOrMacNewlines.matcher(s).replaceAll("\n") : null;
    }
    
    /**
     * Splits a string by newlines (may be \n, \r\n or \r).
     * @param s Input string. May <b>not</b> be null.
     * @return Array of lines, never null. May be an empty list and may contains empty strings.
     */
    public static String[] splitByNewlines(final String s) {
        return normalizeNewlines(s).split("\n");
    }

    /**
     * Converts a byte array to hex. Null safe.
     * @param data Input byte array
     * @return Hex encoded string, or null if the input byte array was null.
     */
    public static String hex(final byte[] data) {
        if (data == null) {
            return null;
        }
        return Hex.toHexString(data);
    }

    /**
     * Compares two values (for example strings) using compareTo. Null is considered to come before all other values.
     */
    public static <T extends Comparable<T>> int compare(final T a, final T b) {
        if (a == null) {
            return -1;
        } else if (b == null) {
            return 1;
        } else {
            return a.compareTo(b);
        }
    }

}
