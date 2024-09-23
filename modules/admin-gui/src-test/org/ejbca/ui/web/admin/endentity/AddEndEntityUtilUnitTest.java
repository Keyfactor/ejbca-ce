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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AddEndEntityUtilUnitTest {
    
    private static final String VALID_SDN = "Snd is valid!";
    private static final String VALID_DOB = "Dob is valid!";
    private static final String VALID_GENDER = "Gender is valid!";
    private static final String INVALID_SDN = "Snd is invalid!";
    private static final String INVALID_GENDER = "Gender is invalid!";
    private static final String INVALID_DOB = "DOB is invalid!";
    private static final String INVALID_USERNAME = "Username invalid!";
    private static final String VALID_USERNAME = "Username valid!";
    
    @Test
    public void validSubjectDN() {
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("user.name@subdomain.example.co.uk"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test*"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test*孩儿"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test=*"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test*)"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test*(孩儿"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test*孩儿/"));
        assertTrue(INVALID_SDN, AddEndEntityUtil.isValidDNField("test#"));
    }

    @Test
    public void invalidSubjectDN() {
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test;"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("?test%"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("?test|"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("?test\n"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test\r"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test`"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test&"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test&"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test{"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test}"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test^"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test$"));
        assertFalse(VALID_SDN, AddEndEntityUtil.isValidDNField("test\\"));
    }
    
    @Test
    public void validUserName() {
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("blabla"));
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("200:"));
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("200:+"));
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("孩儿"));
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("'="));
        assertTrue(INVALID_USERNAME, AddEndEntityUtil.isValidUserNameField("  "));
    }

    @Test
    public void invalidUserName() {
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("blabla%"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("200:?"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("200:+`"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("孩儿\t"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("'=\r"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("'=\t"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("'=\n"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("'=\0"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("\""));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("\\"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("~"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("^"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("}"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("{"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("\\"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("$"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("#"));
        assertFalse(VALID_USERNAME, AddEndEntityUtil.isValidUserNameField("!"));
    }
    
    @Test
    public void invalidDOB() {
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("test;"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("19822320"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("1982111"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("19820134"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("-19820125"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("blabla"));
        assertFalse(VALID_DOB, AddEndEntityUtil.isValidDateOfBirth("fa341rqwer%4"));
    }
    
    @Test
    public void validDOB() {
        assertTrue(INVALID_DOB, AddEndEntityUtil.isValidDateOfBirth("19830223"));
        assertTrue(INVALID_DOB, AddEndEntityUtil.isValidDateOfBirth("20020612"));
    }

    @Test
    public void validGender() {
        assertTrue(INVALID_GENDER, AddEndEntityUtil.isValidGender("M"));
        assertTrue(INVALID_GENDER, AddEndEntityUtil.isValidGender("F"));
        assertTrue(INVALID_GENDER, AddEndEntityUtil.isValidGender("m"));
        assertTrue(INVALID_GENDER, AddEndEntityUtil.isValidGender("f"));        
    }

    @Test
    public void invalidGender() {
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("Male"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("Female"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("mal"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("fem"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("test"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("bla;"));
        assertFalse(VALID_GENDER, AddEndEntityUtil.isValidGender("?$%"));
    }
}
