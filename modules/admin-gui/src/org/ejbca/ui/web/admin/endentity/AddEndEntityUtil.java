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
package org.ejbca.ui.web.admin.endentity;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class holding methods used by {@link AddEndEntityMBean}
 */
public final class AddEndEntityUtil {
    
    private static final String LEGAL_DN_CHARS_REGEX = "^[^~?`!|%$;^&{}\0\r\t\n\\\\\"]*$"; // Excluding disallowed DN characters
    private static final String USERNAME_CHARS_REGEX = "^[^%$~;`\"?!^#{}\n\t\r\0\\\\]*$"; // Excluding disallowed username characters
    private static final String OID_REGEX = "^([0-2])((\\.0)|(\\.[1-9][0-9]*))*$";
    private static final String EMAIL_REGEX = "[\\u0041-\\u005a\\u0061-\\u007a\\u00a1-\\ud7ff\\ue000-\\uffff0-9_.\\-@+']+";
    private static final String IPV4_REGEX =
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";
    private static final String IPV6_REGEX =
            "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$";    
    private static final String GENDER_REGEX = "([MFmf])$";
    private static final String DATE_OF_BIRTH_REGEX = "yyyyMMdd";
    
    private AddEndEntityUtil() {
    }

    protected static boolean isValidEmail(final String email) {
        Pattern pattern = Pattern.compile(EMAIL_REGEX);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    protected static boolean isValidOID(final String oid) {
        Pattern pattern = Pattern.compile(OID_REGEX);
        Matcher matcher = pattern.matcher(oid);
        return matcher.matches();
    }
    
    protected static boolean isValidIPv6(final String ipv6) {
        Pattern pattern = Pattern.compile(IPV6_REGEX);
        Matcher matcher = pattern.matcher(ipv6);
        return matcher.matches();
    }

    protected static boolean isValidIPv4(final String ipv4) {
        Pattern pattern = Pattern.compile(IPV4_REGEX);
        Matcher matcher = pattern.matcher(ipv4);
        return matcher.matches();
    }
    
    protected static boolean isValidDNField(final String value) {
        Pattern pattern = Pattern.compile(LEGAL_DN_CHARS_REGEX);
        Matcher matcher = pattern.matcher(value);
        return matcher.matches();
    }

    protected static boolean isValidUserNameField(final String value) {
        Pattern pattern = Pattern.compile(USERNAME_CHARS_REGEX);
        Matcher matcher = pattern.matcher(value);
        return matcher.matches();
    }
    
    protected static boolean isValidGender(final String gender) {
        Pattern pattern = Pattern.compile(GENDER_REGEX);
        Matcher matcher = pattern.matcher(gender);
        return matcher.matches();
    }
    
    protected static boolean isValidDateOfBirth(final String birthDate) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(DATE_OF_BIRTH_REGEX);

        try {
            formatter.parse(birthDate, LocalDate::from);
        } catch (DateTimeParseException e) {
            return false;
        }
        return true;
    }

}
