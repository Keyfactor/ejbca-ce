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
 
 
package org.ejbca.core.ejb.ra;

import org.junit.Test;

import static org.junit.Assert.*;

public class EndEntityManagementSessionBeanUnitTest {

    @Test
    public void isUsernameValidOnlyChars() {
        assertTrue("Username with characters is a valid one", EndEntityManagementSessionBean.isUsernameValid("Someusername"));
    }

    @Test
    public void isUsernameValidOnlyCharsAndNumbers() {
        assertTrue("Username with numbers is a valid one", EndEntityManagementSessionBean.isUsernameValid("Someusername874"));
    }
    @Test
    public void isUsernameValidCyrillicChar() {
        assertTrue("Username with characters is a valid one", EndEntityManagementSessionBean.isUsernameValid("Шишка"));
    }

    @Test
    public void isUsernameValidMinus() {
        assertTrue("Username with minus is a valid one", EndEntityManagementSessionBean.isUsernameValid("Some-username"));
    }

    @Test
    public void isUsernameValidPlus() {
        assertTrue("Username with plus is a valid one", EndEntityManagementSessionBean.isUsernameValid("Some+username"));
    }

    @Test
    public void isUsernameValidHash() {
        assertFalse("Username with Hash is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some#username"));
    }

    @Test
    public void isUsernameValidAmpersand() {
        assertTrue("Username with Ampersand is a valid one", EndEntityManagementSessionBean.isUsernameValid("Some&username"));
    }

    @Test
    public void isUsernameValidQuestionMark() {
        assertFalse("Username with Question Mark is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some?username"));
    }

    @Test
    public void isUsernameValidTilde() {
        assertFalse("Username with Tilde is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some~username"));
    }

    @Test
    public void isUsernameValidAsterisk() {
        assertTrue("Username with Asterisk is valid", EndEntityManagementSessionBean.isUsernameValid("Some*username"));
    }

    @Test
    public void isUsernameValidSlash() {
        assertTrue("Username with Slash is valid", EndEntityManagementSessionBean.isUsernameValid("Some/username"));
    }

    @Test
    public void isUsernameValidUnderscore() {
        assertTrue("Username with Underscore is valid", EndEntityManagementSessionBean.isUsernameValid("Some_username"));
    }

    @Test
    public void isUsernameValidManyChars() {
        assertTrue("Username with ':/=(*@)_-,. A1' is valid", EndEntityManagementSessionBean.isUsernameValid(":/=(*@)_-,. 'A1"));
    }
}