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

import java.util.Collections;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.SecConst;
import org.junit.Test;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Unit tests for the EndEntityProfile class.
 *
 *
 */
public class EndEntityProfileTest {

    private static final Logger log = Logger.getLogger(EndEntityProfileTest.class);

    /** Dummy certificate profile */
    private static final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

    @Test
    public void testEndEntityProfileDiff() {
        EndEntityProfile foo = new EndEntityProfile();
        EndEntityProfile bar = new EndEntityProfile();
        bar.addField(DnComponents.ORGANIZATIONALUNIT);
        Map<Object, Object> diff = foo.diff(bar);
        assertFalse(diff.isEmpty());
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
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        
        // First an end entity without subjectDN. It's uncommon, but the RFC supports certificates with only altName and no subjectDN
        // we need to unset the default required DN component in order to pass with empty DN
        profile.setRequired(DnComponents.COMMONNAME,0,false); 
        EndEntityInformation userdata = new EndEntityInformation("foo", "", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        try {
            // Should pass
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
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
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("cardnumber should be required");
        } catch (EndEntityProfileValidationException e) {
            // NOPMD: ignore this is what we want
        }
        userdata.setCardNumber("123456789");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("cardnumber was in and should be ok: "+e.getMessage());
        }
        
        // Test that email address can be required as well, and that it does not require an @ sign in it 
        // (see ECA-5650 about Cisco ISE using the rfc822Name field for MAC address)
        profile.addField(DnComponents.RFC822NAME);
        profile.setRequired(DnComponents.RFC822NAME, 0, true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("rfc822Name should be required");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Data does not contain required RFC822NAME field.", e.getMessage());
        }
        userdata.setSubjectAltName("rfc822Name=foo@bar.com");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("rfc822Name was in and should be ok: "+e.getMessage());
        }
        userdata.setSubjectAltName("rfc822Name=AB:CD:32:45");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("rfc822Name was not an email address, but it should be ok: "+e.getMessage());
        }
        // Add another DN component
        userdata.setDN("CN=Foo,O=PrimeKey");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("O should not be allowed");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of ORGANIZATION fields in Subject DN.", e.getMessage());
        }
        profile.addField(DnComponents.ORGANIZATION);
        profile.setRequired(DnComponents.ORGANIZATION, 0, true);
        try {
            // Should pass now
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("Organization should be ok now: "+e.getMessage());
        }
        // Add yet one more DN component
        userdata.setDN("CN=Foo,O=PrimeKey,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("C should not be allowed");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of COUNTRY fields in Subject DN.", e.getMessage());
        }
        profile.addField(DnComponents.COUNTRY);
        profile.setRequired(DnComponents.COUNTRY, 0, true);
        try {
            // Should pass now
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
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
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        try {
            // Should pass
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("Normal non multi value DN should work: "+e.getMessage());
        }
        userdata.setDN("CN=User+UID=123,SN=134566,O=PrimeKey,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("Multi value RDN, and UID should not be allowed, because we don't allow multi value RDNs in the EE profile: "+userdata.getDN());
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Subject DN has multi value RDNs, which is not allowed.", e.getMessage());
        }
        // Allow multi value RDNs, but it should still not be allowed due to us not allowing IUD in the profile
        profile.setAllowMultiValueRDNs(true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("Multi value RDN, and UID should not be allowed, because we don't allow UID in the EE profile: "+userdata.getDN());
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Error message was not the expected", "Wrong number of UID fields in Subject DN.", e.getMessage());
        }
        // Add UID
        profile.addField(DnComponents.UID);
        profile.setRequired(DnComponents.UID, 0, true);
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("UID was in the profile and should be ok: "+e.getMessage());
        }

        // Verify that we don't allow multi-value RDNs on strange fields
        userdata.setDN("CN=User+UID=123,SN=134566,O=PrimeKey+OU=SubO,C=SE");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
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
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
    }

    @Test
    public void testUserFulfillEndEntityProfileDnsFromCnPresent() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=UserDns", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
    }

    @Test(expected = EndEntityProfileValidationException.class)
    public void testUserFulfillEndEntityProfileDnsFromCnWrongDnsForNonMidifiableField() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        profile.setModifyable(DnComponents.DNSNAME, 0, false);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=wrong", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
    }


    @Test
    public void testUserFulfillEndEntityProfileDnsFromCnMultipleDns() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        // CommonName is allowed by default in an end entity profile
        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 0, true);
        profile.setCopy(DnComponents.DNSNAME, 0, true);
        profile.setModifyable(DnComponents.DNSNAME, 0, false);

        profile.addField(DnComponents.DNSNAME);
        profile.setRequired(DnComponents.DNSNAME, 1, true);

        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=UserDns", 123, "DNSNAME=UserDns, DNSNAME=wrong", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
    }

    @Test(expected = EndEntityProfileValidationException.class)
    public void testUserFulfillEndEntityProfilePsd2QcStatementAssertFailure() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setPsd2QcStatementUsed(false);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=Psd2User", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setQCEtsiPSD2NcaName("SomePsd2NCName");
        profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
    }
    
    @Test
    public void testUserFulfillEndEntityProfilePsd2QcStatementAssertSuccess() throws EndEntityProfileValidationException {
        EndEntityProfile profile = new EndEntityProfile();
        profile.setPsd2QcStatementUsed(true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=Psd2User", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setQCEtsiPSD2NcaName("SomePsd2NCName");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
        } catch (EndEntityProfileValidationException e) {
            fail("Expected profile validation to success when 'Psd2QcStatement' was allowed");
            throw e;
        }
    }
    
    @Test
    public void testUserEepCpExtensionsMatch() throws EndEntityProfileValidationException {
        log.trace(">testUserEepCpExtensionsMatch");
        final CertificateProfile certProfileWithExt = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfileWithExt.setUseCabfOrganizationIdentifier(true); // use extension in CP
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(SecConst.ALLCAS));
        profile.setCabfOrganizationIdentifierUsed(true);
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=CP Extension Check", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setCabfOrganizationIdentifier("SEVAT-112233123401"); // use extension in EE
        profile.doesUserFulfillEndEntityProfile(userdata, certProfileWithExt, false, null);
        log.trace("<testUserEepCpExtensionsMatch");
    }
    
    @Test
    public void testUserEepCpExtensionsNoMatch() {
        log.trace(">testUserEepCpExtensionsNoMatch");
        final EndEntityProfile profile = new EndEntityProfile();
        profile.setAvailableCAs(Collections.singletonList(SecConst.ALLCAS));
        profile.setCabfOrganizationIdentifierUsed(true);
        EndEntityInformation userdata = new EndEntityInformation("foo", "CN=CP Extension Check", 123, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                123, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, null);
        userdata.setPassword("foo123");
        userdata.setExtendedInformation(new ExtendedInformation());
        userdata.getExtendedInformation().setCabfOrganizationIdentifier("SEVAT-112233123401");
        try {
            profile.doesUserFulfillEndEntityProfile(userdata, certProfile, false, null);
            fail("Validation should fail when extension is present in EE but not enabled in CP");
        } catch (EndEntityProfileValidationException e) {
            assertEquals("Certificate Extension 'cabforganizationidentifier' is not allowed in Certificate Profile, but was present with value 'SEVAT-112233123401'", e.getMessage());
        }
        log.trace("<testUserEepCpExtensionsNoMatch");
    }

    @Test
    public void testOnlyUsernameValidationFieldIsChanged() {
        final EndEntityProfile foo = new EndEntityProfile();
        foo.addField(DnComponents.ORGANIZATION);
        foo.addField(EndEntityProfile.CARDNUMBER);
        foo.addField(DnComponents.COUNTRY);
        foo.addField(DnComponents.COMMONNAME);
        foo.addField(DnComponents.JURISDICTIONLOCALITY);
        foo.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        foo.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        foo.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        foo.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, true);
        foo.setRequired(DnComponents.COMMONNAME,0,false);

        final EndEntityProfile bar = (EndEntityProfile) foo.clone();

        bar.setUseValidationForUsername(true);
        bar.setUsernameDefaultValidation("validation");

        Map<Object, Object> diff = foo.diff(bar);
        assertEquals(1, diff.size());
    }

}
