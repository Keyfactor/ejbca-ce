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
        assertFalse("Username with plus is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some+username"));
    }

    @Test
    public void isUsernameValidHash() {
        assertFalse("Username with Hash is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some#username"));
    }

    @Test
    public void isUsernameValidAmpersand() {
        assertFalse("Username with Ampersand is a invalid", EndEntityManagementSessionBean.isUsernameValid("Some&username"));
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
        assertTrue("Username with '?:/=(*@~)_-,. A1' is valid", EndEntityManagementSessionBean.isUsernameValid("?:/=(*@~)_-,. 'A1"));
    }
}