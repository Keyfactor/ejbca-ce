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

import java.io.IOException;

import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.OauthProvidersHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Adds, edits, views and removes a Trusted OAuth Provider.
 *  <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-301">ECAQA-301</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa301_ManageOAuthProvider extends WebTestBase {

    private static final OAuthProviderType TYPE = OAuthProviderType.TYPE_AZURE;
    private static final String LABEL = "ECAQA-301";
    private static final String URL = "https://ecaqa301test.ejbcatest.com";
    private static final String KEYID = "ecaqa-301";
    private static final String LABEL_EDITED = "ECAQA-301_edited";
    private static final String SKEWLIMIT = "40000";
    private static final String SKEWLIMIT_EDITED = "60000";
    private static final String TENANT = "tenant";
    private static final String AUDIENCE = "audience";
    private static final String SCOPE = "scope";
    private static final String CLIENT = "client";
    private static final String SECRET = "secret";

    private static OauthProvidersHelper oauthProvidersHelper;
    private static SystemConfigurationHelper sysConfigHelper;
    
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        oauthProvidersHelper = new OauthProvidersHelper(webDriver);
        sysConfigHelper = new SystemConfigurationHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeOauthProviders(LABEL, LABEL_EDITED);
        afterClass();
    }

    @Test
    public void stepA_addOauthProvider() throws IOException {
        goToProvidersConfigurationPage();
        oauthProvidersHelper.startAddingProvider();
        
        oauthProvidersHelper.selectProviderType(TYPE);
        oauthProvidersHelper.fillProviderNameField(LABEL);
        oauthProvidersHelper.fillUrlField(URL);
        oauthProvidersHelper.fillSkewLimitField(SKEWLIMIT);
        oauthProvidersHelper.fillTenantField(TENANT);
        oauthProvidersHelper.fillAudienceField(AUDIENCE);
        oauthProvidersHelper.fillScopeField(SCOPE);
        oauthProvidersHelper.fillClientField(CLIENT);
        oauthProvidersHelper.fillPublicKeyFileField(oauthProvidersHelper.createPublicKeyFile(folder, OauthProvidersHelper.PUBLIC_KEY));
        oauthProvidersHelper.fillKeyIdField(KEYID);
        oauthProvidersHelper.pressUploadButton();
        oauthProvidersHelper.fillClientSecretField(SECRET);
        oauthProvidersHelper.pressAddOauthProviderButton();

        oauthProvidersHelper.assertElementExistsInTable(LABEL);
    }
    
    @Test
    public void stepB_editOauthProvider() {
        oauthProvidersHelper.pressEditOauthProviderButton(LABEL);
        
        oauthProvidersHelper.fillProviderNameField(LABEL_EDITED);
        oauthProvidersHelper.fillSkewLimitField(SKEWLIMIT_EDITED);
        oauthProvidersHelper.fillClientSecretField(SECRET);
        oauthProvidersHelper.pressSaveOauthProviderButton();
        
        oauthProvidersHelper.assertElementExistsInTable(LABEL_EDITED);
    }
    
    @Test
    public void stepC_viewOauthProvider() {
        oauthProvidersHelper.pressViewOauthProviderButton(LABEL_EDITED);
        
        oauthProvidersHelper.assertProviderNameText(LABEL_EDITED);
        oauthProvidersHelper.assertElementExistsInTable("NdKo3LkMXyL7hAVfdHveLaJrPAFHvhTIJGrvPx+jhps=");
        oauthProvidersHelper.assertSkewLimitText(SKEWLIMIT_EDITED);
        oauthProvidersHelper.pressBackButton();
        
        oauthProvidersHelper.assertElementExistsInTable(LABEL_EDITED);
    }
    
    @Test
    public void stepD_deleteOauthProvider() throws InterruptedException {
        oauthProvidersHelper.pressRemoveOauthProviderButton(LABEL_EDITED);
        Thread.sleep(5000);
        oauthProvidersHelper.assertElementDoesNotExistInTable(LABEL_EDITED);
    }

    private void goToProvidersConfigurationPage() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SystemConfigurationHelper.SysConfigTabs.OAUTHPROVIDERS);
    }
}
