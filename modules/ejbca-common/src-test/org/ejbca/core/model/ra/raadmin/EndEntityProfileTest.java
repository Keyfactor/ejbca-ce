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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.junit.Test;

/**
 * Unit tests for the EndEntityProfile class.
 * 
 * @version $Id$
 *
 */
public class EndEntityProfileTest {

    @Test
    public void testEndEntityProfileDiff() {
        EndEntityProfile foo = new EndEntityProfile();
        EndEntityProfile bar = new EndEntityProfile();
        bar.addField(DnComponents.ORGANIZATIONALUNIT);
        Map<Object, Object> diff = foo.diff(bar);
        assertFalse(diff.isEmpty());
    }
    
    /**
     * Tests the validation system, and the regex validator in particular.
     */
    @Test
    public void testRegexValidation() throws EndEntityFieldValidatorException {
        // The regex validator ignored the dn component, so that can be set to anything
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*");
        EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "[0-9-]*@([a-z.-]+|localhost)");
        try {
            EndEntityValidationHelper.checkValidator(DnComponents.COMMONNAME, RegexFieldValidator.class.getName(), "*");
            fail("should throw EndEntityFieldValidatorException on invalid regex");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Invalid regex for field COMMONNAME: Dangling meta character '*' near index 0\n*\n^");
        }
        
        // Test some values
        EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "123");
        try {
            EndEntityValidationHelper.checkValue(DnComponents.COMMONNAME, makeRegexValidator("[0-9]*"), "abc");
           fail("should throw EndEntityFieldValidatorException on invalid value");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Technical details: Value \"abc\" does not match regex [0-9]*");
        }

        // A Regexp that validates valid country codes according to ISO3166 (as or 2018)
        String countryRegexp = "^(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)$";
        EndEntityValidationHelper.checkValue(DnComponents.COUNTRY, makeRegexValidator(countryRegexp), "SE");
        try {
            EndEntityValidationHelper.checkValue(DnComponents.COUNTRY, makeRegexValidator(countryRegexp), "QZ");
           fail("should throw EndEntityFieldValidatorException on invalid value: QZ");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Technical details: Value \"QZ\" does not match regex ^(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW)$");
        }
        
        // A regexp that validates valid domain name
        // (note that it is a java string below, so when copying to be used as a regexp all \\ should be \)
        // Reference: https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
        //String domainNameRegexp = "^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";
        // An updated regexp (by Samuel) that allows * (wildcard certificates) and disallows _ in the beginning
        String domainNameRegexp = "^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$";
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "www.primekey.com");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "xn--primekey.se");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "a.b.primekey.cu.uk");
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "*.primekey.com");
        // This is actually invalid and should not be allowed to pass, but it does with the above regexp (i.e. the regexp is not a perfect dnsName validator)
        // Anything with hyphens for 3rd/4th char is reserved, and xn— needs to be well formed & normalized
        EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "aa--primekey.se");
        try {
            EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "foo_.primekey.se");
            fail("should throw EndEntityFieldValidatorException on invalid value: foo_.primekey.se");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Technical details: Value \"foo_.primekey.se\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");
        }
        try {
            EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "_www.primekey.com");
            fail("should throw EndEntityFieldValidatorException on invalid value: _www.primekey.se");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Technical details: Value \"_www.primekey.com\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");
        }
        try {
            EndEntityValidationHelper.checkValue(DnComponents.DNSNAME, makeRegexValidator(domainNameRegexp), "http://www.primekey.se");
            fail("should throw EndEntityFieldValidatorException on invalid value: http://www.primekey.se");
        } catch (EndEntityFieldValidatorException e) {
            assertEquals("Validation error message is not the expected", e.getMessage(), "Technical details: Value \"http://www.primekey.se\" does not match regex ^(\\*.)?(((?!-))(xn--)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\\.)*(xn--)?([a-z0-9\\-]{1,61}|[a-z0-9-]{1,30}\\.[a-z]{2,})$");
        }
    }
    
    @Test
    public void testProfileValuesEE() {
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.JURISDICTIONLOCALITY);
        profile.addField(DnComponents.JURISDICTIONSTATE);
        profile.addField(DnComponents.JURISDICTIONCOUNTRY);
        profile.addField(DnComponents.DATEOFBIRTH);
        profile.addField(DnComponents.ORGANIZATIONIDENTIFIER);
        profile.addField("Foo");
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, true);
        profile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        
        assertTrue(profile.getUse(DnComponents.ORGANIZATION, 0));
        assertFalse(profile.getUse("Foo", 0));

    }
    
    @Test
    public void testUserFulfillEndEntityProfile() {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        
        // First an end entity without subjectDN. It's uncommon, but the RFC supports certificates with only altName and no subjectDN
        // we need to unset the default required DN component in order to pass with empty DN
        profile.setRequired(DnComponents.COMMONNAME,0,false); 
        EndEntityInformation userdata = new EndEntityInformation("foo", "", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        try {
            // Should pass
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            e.printStackTrace();
            fail("En empty subjectDN should be OK when nothing is required: " + e.getMessage());
        }
        profile.setRequired(DnComponents.COMMONNAME,0,true); // restore defaults

        // CommonName is allowed, and required, by default in an end entity profile
        profile.addField(EndEntityProfile.CARDNUMBER);
        profile.setRequired(EndEntityProfile.CARDNUMBER, 0, true);

        // Test generic that required fields are required
        userdata = new EndEntityInformation("foo", "CN=foo", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("cardnumber should be required");
        } catch (EndEntityProfileValidationException e) {
            // NOPMD: ignore this is what we want
        }
        userdata.setCardNumber("123456789");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("cardnumber was in and should be ok: "+e.getMessage());
        }
        
        // Test that email address can be required as well, and that it does not require an @ sign in it 
        // (see ECA-5650 about Cisco ISE using the rfc822Name field for MAC address)
        profile.addField(DnComponents.RFC822NAME);
        profile.setRequired(DnComponents.RFC822NAME, 0, true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("rfc822Name should be required");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Data does not contain required RFC822NAME field.", e.getMessage());
        }
        userdata.setSubjectAltName("rfc822Name=foo@bar.com");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("rfc822Name was in and should be ok: "+e.getMessage());
        }
        userdata.setSubjectAltName("rfc822Name=AB:CD:32:45");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("rfc822Name was not an email address, but it should be ok: "+e.getMessage());
        }
        // Add another DN component
        userdata.setDN("CN=Foo,O=PrimeKey");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("O should not be allowed");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of ORGANIZATION fields in Subject DN.", e.getMessage());
        }
        profile.addField(DnComponents.ORGANIZATION);
        profile.setRequired(DnComponents.ORGANIZATION, 0, true);
        try {
            // Should pass now
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("Organization should be ok now: "+e.getMessage());
        }
        // Add yet one more DN component
        userdata.setDN("CN=Foo,O=PrimeKey,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("C should not be allowed");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of COUNTRY fields in Subject DN.", e.getMessage());
        }
        profile.addField(DnComponents.COUNTRY);
        profile.setRequired(DnComponents.COUNTRY, 0, true);
        try {
            // Should pass now
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("Country should be ok now: "+e.getMessage());
        }
    }
    
    @Test
    public void testUserFulfillEndEntityProfileMultiValueRDN() {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.ORGANIZATION);
        profile.setRequired(DnComponents.ORGANIZATION, 0, true);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.setRequired(DnComponents.ORGANIZATIONALUNIT, 0, false);
        profile.addField(DnComponents.DNSERIALNUMBER);
        profile.setRequired(DnComponents.DNSERIALNUMBER, 0, false);
        profile.addField(DnComponents.COUNTRY);
        profile.setRequired(DnComponents.COUNTRY, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, "123");
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=User,SN=134566,O=PrimeKey,C=SE", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        try {
            // Should pass
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("Normal non multi value DN should work: "+e.getMessage());
        }
        userdata.setDN("CN=User+UID=123,SN=134566,O=PrimeKey,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("Multi value RDN, and UID should not be allowed, because we don't allow multi value RDNs in the EE profile: "+userdata.getDN());
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Subject DN has multi value RDNs, which is not allowed.", e.getMessage());
        }
        // Allow multi value RDNs, but it should still not be allowed due to us not allowing IUD in the profile
        profile.setAllowMultiValueRDNs(true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("Multi value RDN, and UID should not be allowed, because we don't allow UID in the EE profile: "+userdata.getDN());
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of UID fields in Subject DN.", e.getMessage());
        }
        // Add UID
        profile.addField(DnComponents.UID);
        profile.setRequired(DnComponents.UID, 0, true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("UID was in the profile and should be ok: "+e.getMessage());
        }

        // Verify that we don't allow multi-value RDNs on strange fields
        userdata.setDN("CN=User+UID=123,SN=134566,O=PrimeKey+OU=SubO,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
            fail("Multi value RDN, and UID should not be allowed, because we don't allow UID in the EE profile: "+userdata.getDN());
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Subject DN is illegal.", e.getMessage());
        }
        
    }

    @Test(expected = EndEntityProfileValidationException.class)
    public void testUserFulfillEndEntityProfileDnsFromCnNotPresent() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setUse(DnComponents.DNSNAME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, false);
    }

    @Test
    public void testUserFulfillEndEntityProfileDnsFromCnPresent() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setUse(DnComponents.DNSNAME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=UserDns", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, false);
    }

    @Test(expected = EndEntityProfileValidationException.class)
    public void testUserFulfillEndEntityProfileDnsFromCnWrongDnsForNonMidifiableField() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setUse(DnComponents.DNSNAME, 0, true);
        profile.setModifyable(DnComponents.DNSNAME, 0, false);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=wrong", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, false);
    }


    @Test
    public void testUserFulfillEndEntityProfileDnsFromCnMultipleDns() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setUse(DnComponents.DNSNAME, 0, true);
        profile.setModifyable(DnComponents.DNSNAME, 0, false);

        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 1, true);

        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=UserDns, DNSNAME=wrong", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, false);
    }

    @Test(expected = EndEntityProfileValidationException.class)
    public void testUserFulfillEndEntityProfilePsd2QcStatementAssertFailure() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setPsd2QcStatementUsed(false);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=Psd2User", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setQCEtsiPSD2NcaName("SomePsd2NCName");
        profile.doesUserFulfillEndEntityProfile(userdata, false);
    }
    
    @Test
    public void testUserFulfillEndEntityProfilePsd2QcStatementAssertSuccess() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setPsd2QcStatementUsed(true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=Psd2User", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setQCEtsiPSD2NcaName("SomePsd2NCName");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, false);
        } catch (EndEntityProfileValidationException e) {
            fail("Expected profile validation to success when 'Psd2QcStatement' was allowed");
            throw e;
        }
    }
    
    private static Map<String,Serializable> makeRegexValidator(final String regex) {
        final Map<String,Serializable> map = new LinkedHashMap<String,Serializable>();
        map.put(RegexFieldValidator.class.getName(), regex);
        return map;
    }
    
}
