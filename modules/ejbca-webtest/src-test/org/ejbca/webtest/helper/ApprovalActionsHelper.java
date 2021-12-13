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

import org.apache.commons.lang.StringUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;


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
        
        static final By SELECT_STATUS = By.id("approvalsearchform:status");
        static final By SELECT_TIME_SPAN = By.id("approvalsearchform:timespan");
        static final By BUTTON_SEARCH = By.id("approvalsearchform:list");

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
     * Sets Approval Action status in the search form.
     *
     * @param status Approval Action status to be selected.
     */
    public void setApprovalActionSearchStatus(final String status) {
        selectOptionByName(Page.SELECT_STATUS, status);
    }
    
    /**
     * Sets Approval Action search time span.
     *
     * @param timeSpan Approval Action time span to be selected.
     */
    public void setApprovalActionSearchTimeSpan(final String timeSpan) {
        selectOptionByName(Page.SELECT_TIME_SPAN, timeSpan);
    }
    
    /**
     * Searches for approval actions.
     */
    public void searchForApprovals() {
        clickLink(Page.BUTTON_SEARCH);
    }
    
    /**
     * Asserts the Approve Action exists in the table.
     *
     * @param actionName approval action name.
     * @param status status of the approval action.
     */
    public void assertApprovalActionTableLinkExists(final String actionName, final String status) {
        assertElementExists(
                Page.getTableRowContainingActionNameAndStatus(actionName, status),
                actionName + " with the status " + status + " was not found on 'Approve Actions' page."
        );
    }
    
    /**
     * Extracts the approval id from HTML.
     *
     * @param actionName approval action name.
     * @param status status of the approval action.
     * @return the id of the approval.
     */
    public int extractApprovalId(final String actionName, final String status) {
        WebElement approvalLink = findElement(Page.getTableRowContainingActionNameAndStatus(actionName, status));
        if (approvalLink == null) {
            return -1;
        }
        String onMouseDownString = approvalLink.getAttribute("onmousedown");
        if (onMouseDownString == null) {
            return -1;
        }
        String idString = StringUtils.substringBetween(onMouseDownString, "uniqueId=", "'");
        if (idString == null) {
            return -1;
        }
        return Integer.valueOf(idString);
    }
}
