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

package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.keyfactor.util.certificate.DnComponents;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for the EndEntityValidationHelper class.
 *
 * @version $Id$
 */
public class EndEntityValidationHelperTest {

    private static final String COUNTRY_REGEXP = "^(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)$";

    // A regexp that validates valid domain name
    // (note that it is a java string below, so when copying to be used as a regexp all \\ should be \)
    // Reference: https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
    //String domainNameRegexp = "^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";
    // An updated regexp (by Samuel) that allows * (wildcard certificates) and disallows _ in the beginning
    private static final String DOMAIN_NAME_REGEXP = "^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();


    @Test
    public void testCheckValidatorValidDNRegex() throws EndEntityFieldValidatorException {
        // The regex validator ignored the dn component, so that can be set to anything
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*");
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*@([a-z.-]+|localhost)");
    }

    @Test
    public void testCheckValidatorInvalidDNRegexShouldThrowException() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Invalid regex for field COMMONNAME: Dangling meta character '*' near index 0\n*\n^");

        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "*");
    }


    @Test
    public void testCheckValueValidValue() throws EndEntityFieldValidatorException {
        // Test some values
        EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "123");
    }

    @Test
    public void testCheckValueInvalidValueShouldThrowException() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Technical details: Value \"abc\" does not match regex [0-9]*");

        EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "abc");
    }

    @Test
    public void testCheckValueValidCountryCodes() throws EndEntityFieldValidatorException {
        EndEntityValidationHelper.checkValue(DnComponents.COUNTRY, makeRegexValidator(COUNTRY_REGEXP), "SE");
    }

    @Test
    public void testCheckValueInvalidCountryCodeShouldThrowException() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Technical details: Value \"QZ\" does not match regex ^(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)$");

        // A Regexp that validates valid country codes according to ISO3166 (as or 2018)
        EndEntityValidationHelper.checkValue(DnComponents.COUNTRY, makeRegexValidator(COUNTRY_REGEXP), "QZ");
    }

    @Test
    public void testCheckValueValidDomainNames() throws EndEntityFieldValidatorException {
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "www.primekey.com");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "xn--primekey.se");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "a.b.primekey.cu.uk");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "*.primekey.com");
    }

    @Test
    public void testCheckValueDomainNamesEdgeCase() throws EndEntityFieldValidatorException {
        // This is actually invalid and should not be allowed to pass, but it does with the above regexp (i.e. the regexp is not a perfect dnsName validator)
        // Anything with hyphens for 3rd/4th char is reserved, and xn— needs to be well formed & normalized
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "aa--primekey.se");
    }

    @Test
    public void testCheckValueInvalidDNShouldThrowException01() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Technical details: Value \"foo_.primekey.se\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");

        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "foo_.primekey.se");
    }

    @Test
    public void testCheckValueInvalidDNShouldThrowException02() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Technical details: Value \"_www.primekey.com\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");

        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "_www.primekey.com");
    }

    @Test
    public void testCheckValueInvalidDNShouldThrowException03() throws EndEntityFieldValidatorException {
        expectedException.expect(EndEntityFieldValidatorException.class);
        expectedException.expectMessage("Technical details: Value \"http://www.primekey.se\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");

        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(DOMAIN_NAME_REGEXP), "http://www.primekey.se");
    }

    @Test
    public void testGetValidationMapFromRegex() {
        final String regex = "\\d";
        final String className = "RegexValidator.class";

        final LinkedHashMap<String, Serializable> expectedValidation = new LinkedHashMap<>();
        expectedValidation.put(className, StringUtils.defaultString(regex));

        assertEquals(expectedValidation, EndEntityValidationHelper.getValidationMapFromRegex(regex, className));
    }

    private static Map<String,Serializable> makeRegexValidator(final String regex) {
        return EndEntityValidationHelper.getValidationMapFromRegex(regex, RegexFieldValidator.class.getName());
    }
}
