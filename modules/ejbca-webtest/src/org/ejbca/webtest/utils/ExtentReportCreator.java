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
package org.ejbca.webtest.utils;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

import com.aventstack.extentreports.ExtentReports;
import com.aventstack.extentreports.ExtentTest;
import com.aventstack.extentreports.MediaEntityBuilder;
import com.aventstack.extentreports.Status;
import com.aventstack.extentreports.reporter.ExtentSparkReporter;
import com.aventstack.extentreports.reporter.JsonFormatter;
import com.aventstack.extentreports.reporter.configuration.Theme;
import org.apache.commons.io.FileUtils;
import org.ejbca.webtest.utils.extentreports.EjbcaTestModelReportBuilder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

/**
 * Helper class used for writing reports using ExtentReport plugin.
 *
 * @version $Id$
 */
public class ExtentReportCreator {

    private static ExtentReports extent;
    private static ExtentTest testCase;
    private static String currTest;
    private static WebDriver browser;
    private static String reportDir
            = (System.getProperty("user.dir").contains("ejbca-webtest"))
            ? System.getProperty("user.dir") + "/../.." : System.getProperty("user.dir");

    // Setter method for WebDriver
    public static void setBrowser(final WebDriver browser) {
        ExtentReportCreator.browser = browser;
    }

    /**
     * Initially builds a new test report at the beginning of the testrun.
     * Afterwards, it appends new tests to the report.
     */
    @BeforeClass
    public static void setUp() throws IOException {
        extent = new ExtentReports();
        final EjbcaTestModelReportBuilder ejbcaTestModelReportBuilder = new EjbcaTestModelReportBuilder();
        // Load results of previous tests if any through JSON
        ejbcaTestModelReportBuilder.createDomainFromJsonArchive(extent, new File(reportDir + "/reports/test-report.json"));
        final ExtentSparkReporter spark = new ExtentSparkReporter(reportDir + "/reports/QaEjbcaTestReport.html");
        spark.config().setDocumentTitle("EJBCA QA Test Report");
        spark.config().setReportName("EJBCA Test Results!");
        spark.config().setTheme(Theme.DARK);
        // Add a JSON formatter to record current's test result
        final JsonFormatter json = new JsonFormatter(reportDir + "/reports/test-report.json");
        extent.attachReporter(spark, json);
    }

    // Flushes all events to test report.
    @AfterClass
    public static void tearDown() {
        // writing everything to document
        extent.flush();
    }

    // Using JUnit TestWatcher as a rule
    @Rule
    public TestRule watchman = new TestWatcher() {

        // Override the Junit failed method to report results and take screenshot
        @Override
        protected void failed(final Throwable throwable, final Description description) {
            // step log
            createTest(description);
            final ExtentTest failed = testCase.createNode(description.getDisplayName());
            failed.log(Status.FAIL, "Message: " + throwable.getMessage());
            try {
                if (!description.getDisplayName().contains("CmdLine")) {
                    // Add log events
                    failed.fail(throwable);
                    failed.fail("Screenshot: ", MediaEntityBuilder.createScreenCaptureFromBase64String(screenshotAsBase64String()).build());
                }
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            extent.flush();
        }

        // When passed only write to the log with screenshot.
        @Override
        protected void succeeded(final Description description) {
            // step log
            createTest(description);
            final ExtentTest passed = testCase.createNode(description.getDisplayName());
            passed.log(Status.PASS, "-");
            try {
                if (!description.getDisplayName().contains("CmdLine")) {
                    // Add log events
                    passed.pass("Screenshot: ", MediaEntityBuilder.createScreenCaptureFromBase64String(screenshotAsBase64String()).build());
                }
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            extent.flush();
        }

        // Adds a new test node for each Junit test.
        void createTest(Description description) {
            String test = description.getTestClass().getSimpleName();
            if ((currTest == null) || !(currTest.equalsIgnoreCase(test))) {
                testCase = extent.createTest(description.getTestClass().getSimpleName());
                currTest = test;
            }
        }

        // Takes a screenshot as base64 string
        private String screenshotAsBase64String() {
            final TakesScreenshot takesScreenshot = (TakesScreenshot) browser;
            final File scrFile = takesScreenshot.getScreenshotAs(OutputType.FILE);
            try {
                final byte[] scrFileContent = FileUtils.readFileToByteArray(scrFile);
                return Base64.getEncoder().encodeToString(scrFileContent);
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }
    };
}
