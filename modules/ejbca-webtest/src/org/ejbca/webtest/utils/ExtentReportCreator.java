package org.ejbca.webtest.utils;

import com.aventstack.extentreports.ExtentReports;
import com.aventstack.extentreports.ExtentTest;
import com.aventstack.extentreports.Status;
import com.aventstack.extentreports.reporter.ExtentHtmlReporter;
import com.aventstack.extentreports.reporter.configuration.ChartLocation;
import com.aventstack.extentreports.reporter.configuration.Theme;
import org.apache.commons.io.FileUtils;
import org.ejbca.webtest.WebTestBase;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

public class ExtentReportCreator {
    static ExtentReports extent;
    static ExtentHtmlReporter htmlReporter;
    static ExtentTest testCase;
    static String currTest;
    static WebDriver browser;

    public static void setBrowser(WebDriver browser) {
        ExtentReportCreator.browser = browser;
    }


    @BeforeClass
    public static void setUp() throws IOException {
        System.out.println("Do we reach it?");
        extent = new ExtentReports();


        htmlReporter = new ExtentHtmlReporter(System.getProperty("user.dir") +
                "/reports/QaEjbcaTestReport.html");
        extent.attachReporter(htmlReporter);

        htmlReporter.config().setDocumentTitle("EJBCA QA Test Report");
        htmlReporter.config().setReportName("EJBCA Test Results!");
        htmlReporter.config().setTestViewChartLocation(ChartLocation.BOTTOM);
        htmlReporter.config().setTheme(Theme.DARK);

    }

    @AfterClass
    public static void tearDown() throws IOException {
    // writing everything to document
        extent.flush();
    }

    @Rule
    public TestRule watchman = new TestWatcher() {

        @Override
        protected void failed(Throwable e, Description description) {
            // step log
            createTest(description);
            ExtentTest failed = testCase.createNode(description.getDisplayName());
            failed.log(Status.FAIL, "Failure trace Selenium:  " + e.toString());
            try {
                failed.addScreenCaptureFromPath(snap(description));
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            extent.flush();
        }


        //When passed only write to the log.
        @Override
        protected void succeeded(Description description) {
            // step log
            createTest(description);
            ExtentTest passed = testCase.createNode(description.getDisplayName());
            passed.log(Status.PASS, "-");
            try {
                passed.addScreenCaptureFromPath(snap(description));
            } catch (IOException e1) {
                e1.printStackTrace();
            }

            extent.flush();
        }

        public void createTest(Description description) {
            String test = description.getTestClass().getSimpleName();
            if ( (currTest == null) || !(currTest.equalsIgnoreCase(test)) ) {
                testCase = extent.createTest(description.getTestClass().getSimpleName());
                currTest = test;
            }
        }

        private String snap(Description description) {
            TakesScreenshot takesScreenshot = (TakesScreenshot) browser;

            File scrFile = takesScreenshot.getScreenshotAs(OutputType.FILE);
            File destFile = getDestinationFile(description);
            try {
                FileUtils.copyFile(scrFile, destFile);
            } catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
            return (destFile.getAbsolutePath());
        }

        private File getDestinationFile(Description description) {
            String userDirectory = "reports/images/";
            String date = getDateTime();
            String fileName = description.getDisplayName() + "_" + date + ".png";
            //add date of today
            String dateForDir = getDateTime();
            String absoluteFileName = userDirectory + "/" + dateForDir + "/" + fileName;

            return new File(absoluteFileName);
        }

    };

    private String getDateTime() {
        Date date = Calendar.getInstance().getTime();

        // Display a date in day, month, year format
        DateFormat formatter = new SimpleDateFormat("dd-MM-yyyy_HH_mm_ss");
        String today = formatter.format(date);
        return today;
    }
}
