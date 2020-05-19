package org.ejbca.webtest.scenario;

import org.ejbca.webtest.helper.CmpConfigurationHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import static org.ejbca.webtest.WebTestBase.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa43_ClonedCmpTestAlias {
       
    //Helpers
    private static CmpConfigurationHelper cmpConfigHelper;

    public static class TestData {
        static final String cmpAlias = "EcaQa43CmpAlias";
        static final String cloneCmpAlias = "EcaQa43CloneCmpAlias";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        cmpConfigHelper = new CmpConfigurationHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated test data
        removeCmpAliasByName(TestData.cmpAlias);
        removeCmpAliasByName(TestData.cloneCmpAlias);
        // super
        afterClass();
    }

    /**
     * Add an alias and verify that the added alias exists .
     */
    @Test
    public void testA_createCmpAlias() {
        cmpConfigHelper.openPage(getAdminWebUrl());
        cmpConfigHelper.addCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAlias);
    }

    /**
     * Clone an alias and verify that the cloned alias exists .
     */
    @Test
    public void testB_cloneCmpAlias() {
        cmpConfigHelper.cloneCmpAlias(TestData.cmpAlias, TestData.cloneCmpAlias);
        cmpConfigHelper.assertCmpAliasExists(TestData.cloneCmpAlias);
    }
}
