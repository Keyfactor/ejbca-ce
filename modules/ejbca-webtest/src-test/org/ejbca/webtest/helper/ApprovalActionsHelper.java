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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;


// TODO JavaDoc
/**
 * Helper class for handling 'Approve Actions' page in automated web tests.
 *
 */
public class ApprovalActionsHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Approve Actions' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/approval/approvalactions.xhtml";
        static final By PAGE_LINK = By.id("supervisionApproveactionlist");

        // Dynamic references
        static By getTableRowContainingText(final String text) {
            return By.xpath("//tbody/tr/td[contains(text(), '" + text + "')]");
        }
        
        static By getTableRowContainingActionNameAndStatus(final String actionName, final String status) {
            return By.xpath("//tbody/tr/td[contains(text(), '" + status + "')]/preceding-sibling::td/a[contains(text(), '" + actionName + "')]");
        }
    }

    public ApprovalActionsHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Approve Actions' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    /**
     * Asserts the Approve Action exists in the table.
     *
     * @param actionName Approval Action Name.
     * @param 
     */
    public void assertApprovalActionTableLinkExists(final String actionName, final String status) {
        assertElementExists(
                Page.getTableRowContainingActionNameAndStatus(actionName, status),
                actionName + " with the status " + status + " was not found on 'Approve Actions' page."
        );
    }
}
