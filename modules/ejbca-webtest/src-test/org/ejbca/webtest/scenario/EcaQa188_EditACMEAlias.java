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
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AcmeHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test verifies that editing an Acme alias works.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-188">ECAQA-188</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa188_EditACMEAlias extends WebTestBase {
    //Helpers
    private static AcmeHelper acmeHelper;

    //Test Data
    public static class TestData {
        private static final String ACME_ALIAS = "EcaQa188TestAlias";
        private static final String SITE_URL_DEFAULT = "https://www.example.com/";
        private static final String TERMS_URL_DEFAULT = "https://example.com/acme/terms";
        private static final String DNS_RESOLVER_DEFAULT = "8.8.8.8";
        private static final String DNS_PORT_DEFAULT = "53";
        private static final String DNSSEC_TRUST_ANCHOR_DEFAULT = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5\n" + 
                ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        acmeHelper = new AcmeHelper(getWebDriver());
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void stepA_AddAcme() {
        acmeHelper.openPage(getAdminWebUrl());
        acmeHelper.clickAdd();
        acmeHelper.alertTextfieldAndAccept(TestData.ACME_ALIAS);
    }

    @Test
    public void stepB_OpenAliasEditPage() {
        acmeHelper.clickAlias(TestData.ACME_ALIAS);
        acmeHelper.assertEEPIsEnabled(false);
        acmeHelper.assertPreAuthorizationAllowedIsEnabled(false);
        acmeHelper.assertWildcardIsEnabled(false);
        acmeHelper.assertVersionApprovalIsEnabled(false);
        acmeHelper.assertValidateDNSSECIsEnabled(false);

        acmeHelper.assertPreAuthorizationAllowedIsSelected(false);
        acmeHelper.assertWildcardIsSelected(false);
        acmeHelper.assertSiteURLText(TestData.SITE_URL_DEFAULT);
        acmeHelper.assertTermsURLText(TestData.TERMS_URL_DEFAULT);
        acmeHelper.assertVersionApprovalIsSelected(true);
        acmeHelper.assertDNSResolverText(TestData.DNS_RESOLVER_DEFAULT);
        acmeHelper.assertDNSPortText(TestData.DNS_PORT_DEFAULT);
        acmeHelper.assertValidateDNSSECIsSelected(true);
        acmeHelper.assertDNSSECTrustAnchorText(TestData.DNSSEC_TRUST_ANCHOR_DEFAULT);
    }

    @Test
    public void stepC_ChangeMode() {
        acmeHelper.clickEdit();
        acmeHelper.assertEEPIsEnabled(true);
        acmeHelper.assertPreAuthorizationAllowedIsEnabled(true);
        acmeHelper.assertWildcardIsEnabled(true);
        acmeHelper.assertVersionApprovalIsEnabled(true);
        acmeHelper.assertDNSResolverIsEnabled(true);
        acmeHelper.assertDNSPortIsEnabled(true);
        acmeHelper.assertValidateDNSSECIsEnabled(true);
        acmeHelper.assertDNSSECTrustAnchorIsEnabled(true);
    }

    @Test
    public void stepD_DeleteAcme() {
        acmeHelper.openPage(getAdminWebUrl());
        acmeHelper.deleteWithName(TestData.ACME_ALIAS);
    }
}