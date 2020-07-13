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

package org.ejbca.webtest.helper;

import static org.junit.Assert.assertEquals;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * System configuration (Administrator Web) helper class for EJBCA Web Tests.
 * @version $Id$
 *
 */
public class SystemConfigurationHelper extends BaseHelper {

    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/sysconfig/systemconfiguration.xhtml";
        static final By PAGE_LINK = By.id("sysConfigGlobal");
        
        // Buttons
        static final By BUTTON_SAVE_BASIC_CONFIG = By.xpath("//input[@value='Save']");
        static final By BUTTON_CANCEL_BASIC_CONFIG = By.xpath("//input[@value='Cancel']");
        
        // Check boxes
        static final By CHECKBOX_ENABLE_KEY_RECOVERY = By.id("systemconfiguration:keyrecoverycheckbox");
        static final By CHECKBOX_ENABLE_CA_NAME_CHANGE = By.id("systemconfiguration:enableicaocanamechange");
        
        // Dynamic references
        static By getSystemConfigTabContainingText(final String text) {
            return By.xpath("//div/span/a[contains(text(),'" + text + "' )]");
        }
        static By getEnableButtonFromProtocolsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Enable']");
        }
        static By getDisableButtonFromProtocolsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Disable']");
        }
        static By getEnabledStatusFromProtocolsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td/div[contains(text(), 'Enabled')]");
        }
    }
    
    /**
     * Enum of available tabs with corresponding locator
     */
    public enum SysConfigTabs {
        BASICCONFIG("Basic Configurations"),
        ADMINPREFERENCES("Administrator Preferences"),
        PROTOCOLCONFIG("Protocol Configuration"),
        EXTENDEDKEYUSAGE("Extended Key Usages"),
        CTLOGS("Certificate Transparency Logs"),
        CUSTOMCERTEXTENSIONS("Custom Certificate Extensions"),
        CUSTOMRASTYLES("Custom RA Styles"),
        STATEDUMP("Statedump"),
        EXTERNALSCRIPTS("External Scripts");

        private final String locator;

        private SysConfigTabs(String locator) {
            this.locator = locator;
        }

        public String getLocatorId() {
            return locator;
        }
    }

    /**
     * Enum of available Protocols with corresponding labels
     */
    public enum SysConfigProtokols {
        ACME("ACME"),
        CERTSTORE("Certstore"),
        REST_CERTIFICATE_MANAGEMENT("REST Certificate Management");

        private final String label;

        private SysConfigProtokols(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }
    
    public SystemConfigurationHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    /**
     * Opens the page 'System Configuration' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    /**
     * Opens the given tab in the 'System Configuration' page by clicking on the tab link
     * @param tab enum of type SysConfigTabs
     */
    public void openTab(final SysConfigTabs tab) {
        clickLink(Page.getSystemConfigTabContainingText(tab.getLocatorId()));
    }
    
    /**
     * Toggles 'Enabled CA Name Change'
     * @param enable true if button should be enabled (checked)
     */
    public void triggerEnableCaNameChange(boolean enable) {
        toggleCheckbox(Page.CHECKBOX_ENABLE_CA_NAME_CHANGE, enable);
    }
    
    /**
     * Asserts the check box 'Enable CA Name Change' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertEnableCaNameChangeIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Enable CA Name Change' checkbox saved in wrong state isEnabled [" + isEnabled + "]",
                isEnabled,
                isSelectedElement(Page.CHECKBOX_ENABLE_CA_NAME_CHANGE)
        );
    }
    
    /**
     * Toggles 'Enabled Key Recovery'
     * @param enable true if button should be enabled (checked)
     */
    public void triggerEnableKeyRecovery(boolean enable) {
        toggleCheckbox(Page.CHECKBOX_ENABLE_KEY_RECOVERY, enable);
    }
    
    /**
     * Asserts the check box 'Enable Key Recovery' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertEnableKeyRecoveryEnabled(final boolean isEnabled) {
        assertEquals(
                "'Enable Key Recovery' checkbox saved in wrong state isEnabled [" + isEnabled + "]",
                isEnabled,
                isSelectedElement(Page.CHECKBOX_ENABLE_KEY_RECOVERY)
        );
    }
    
    /**
     * Saves configuration by clicking the 'Save' Button on the 'Basic Configuration' page (tab in 'System Configuration')
     */
    public void saveBasicConfiguration() {
        clickLink(Page.BUTTON_SAVE_BASIC_CONFIG);
    }
    
    /**
     * Cancels configuration by clicking the 'Cancel' Button on the 'Basic Configuration' page (tab in 'System Configuration')
     */
    public void cancelBasicConfiguration() {
        clickLink(Page.BUTTON_CANCEL_BASIC_CONFIG);
    }

    /**
     * Enables selected protocol
     * @param protocol protocol to enable
     */
    public void enableProtocol(SysConfigProtokols protocol) {
        clickLinkIfExists(Page.getEnableButtonFromProtocolsTableRowContainingText(protocol.getLabel()));
    }
    
    /**
     * Disables selected protocol
     * @param protocol protocol to disable
     */
    public void disableProtocol(SysConfigProtokols protocol) {
        clickLinkIfExists(Page.getDisableButtonFromProtocolsTableRowContainingText(protocol.getLabel()));
    }
    
    /**
     * Asserts the specified protocol is enabled
     * @param protocol protocol to assert
     */
    public void assertProtocolEnabled(SysConfigProtokols protocol) {
        assertElementExists(Page.getEnabledStatusFromProtocolsTableRowContainingText(protocol.getLabel()), protocol.getLabel() + " is not in enabled state");
    }

}
