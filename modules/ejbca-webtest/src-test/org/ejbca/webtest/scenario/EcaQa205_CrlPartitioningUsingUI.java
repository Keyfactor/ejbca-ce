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

import org.apache.commons.lang.RandomStringUtils;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.util.CertTools;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigProtokols;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigTabs;
import org.ejbca.webtest.util.WebTestUtil;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

// The ignored testcase, stepM_GenerateAndRevokeCertificates, works when executing locally but not within a build machine
// environment.  The steps relying on the SwaggerUIHelper should be replaced with methods to call REST programmatically.
/**
 * This test the CRL partitioning feature which includes UI and database level modifications.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-205">ECAQA-205</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa205_CrlPartitioningUsingUI extends WebTestBase {

    // Helpers
    private static CaHelper caHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static CaStructureHelper caStructureHelper;
    private static ServicesHelper servicesHelper;
    private static AddEndEntityHelper addEndEntityHelperDefault;
    private static SwaggerUIHelper swaggerUIHelper;
    private static SystemConfigurationHelper systemConfigurationHelper;

    // Test Data
    private static class TestData {
        static final String CA_NAME = "CrlPartitionCATest";
        static final String CA_VALIDITY = "1y";
        static final String CERTIFICATE_PROFILE_NAME = "CrlPartitionTestCertProfile";
        static final String ENTITY_NAME = "EndEntityProfile";
        static final String CRL_SERVICE = "ServiceCrlPartition";
        static final String ISSUER_DN = "CN=" + CA_NAME;
        static final String USERNAME = "Crl" + RandomStringUtils.randomAlphanumeric(8);
        static final String PASSWORD = "123" + RandomStringUtils.randomAlphanumeric(5);
        static final String END_ENTITY_NAME = "EcaQa205EE" + new Random().nextInt();
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        eeProfileHelper = new EndEntityProfileHelper(webDriver);
        caStructureHelper = new CaStructureHelper(webDriver);
        servicesHelper = new ServicesHelper(webDriver);
        addEndEntityHelperDefault = new AddEndEntityHelper(webDriver);
        swaggerUIHelper = new SwaggerUIHelper(webDriver);
        systemConfigurationHelper = new SystemConfigurationHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        removeEndEntityByUsername(TestData.USERNAME);
        removeCertificateByUsername(TestData.USERNAME);
        removeCrlByIssuerDn(TestData.ISSUER_DN);
        removeCaAndCryptoToken(TestData.CA_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeEndEntityProfileByName(TestData.ENTITY_NAME);
        removeServiceByName(TestData.CRL_SERVICE);
        // super
        afterClass();
    }

    @Test
    public void stepA_GotoCertificateAuthorityPage() {
        //Verify CA using cryptotoken exists
        caHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void stepB_AddCA() {
        caHelper.addCa(TestData.CA_NAME);
    }

    @Test
    public void stepC_setValidity() {
        caHelper.setValidity(TestData.CA_VALIDITY);
    }

    @Test
    public void stepD_configureCRLPartitioning() {
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.checkUseCrlPartitions(true);
        caHelper.setNumberOfPartitions("3");
        caHelper.setNumberOfSuspendedPartitions("1");
        caHelper.setCrlPeriod("5m");
    }

    @Test
    public void stepE_GenerateDefaultCrlDistributionPoint() {
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.assertDefaultCrlDistributionPointUri(
                getCrlUri()
                        + TestData.CA_NAME + "&partition=*");
    }

    @Test
    public void stepF_createCA() {
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepG_createCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void stepH_EditCertificateProfile() {
        // Edit certificate Profile
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);

        // Set validity
        certificateProfileHelper.fillValidity("360d");
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCrlDistributionPoints();
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPoint();
    }

    @Test
    public void stepI_SaveCertificateProfile() {
        // Save
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepJ_AddEndEntityProfile() {
        eeProfileHelper.openPage(getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.ENTITY_NAME);
    }

    @Test
    public void stepK_EditEntityProfile() {
        eeProfileHelper.openEditEndEntityProfilePage(TestData.ENTITY_NAME);
        eeProfileHelper.addSubjectDnAttribute("O, Organization");
        eeProfileHelper.addSubjectDnAttribute("ST, State or Province");
        eeProfileHelper.addSubjectDnAttribute("L, Locality");
        eeProfileHelper.addSubjectDnAttribute("C, Country (ISO 3166)");

        eeProfileHelper.setSubjectAlternativeName("DNS Name");
        eeProfileHelper.setSubjectAlternativeName("IP Address");

        eeProfileHelper.selectAvailableCp(TestData.CERTIFICATE_PROFILE_NAME);
        eeProfileHelper.selectDefaultCp(TestData.CERTIFICATE_PROFILE_NAME);
        eeProfileHelper.selectDefaultCa(TestData.CA_NAME);
    }

    @Test
    public void stepL_SaveEntityProfile() {
        eeProfileHelper.saveEndEntityProfile(true);
    }

    @Test
    public void stepM1_CreateEndEntity(){
        //First add an end entity for the end user
        Map<String, String> INPUT_END_ENTITY_FIELDMAP = new HashMap<>();
        {
            INPUT_END_ENTITY_FIELDMAP.put("Username", TestData.USERNAME);
            INPUT_END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", TestData.PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("Confirm Password", TestData.PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("CN, Common name", TestData.END_ENTITY_NAME);
        }
        System.out.println("User:  " + TestData.USERNAME);

        addEndEntityHelperDefault.openPage(getAdminWebUrl());
        addEndEntityHelperDefault.setEndEntityProfile(TestData.ENTITY_NAME);
        addEndEntityHelperDefault.fillFields(INPUT_END_ENTITY_FIELDMAP);
        addEndEntityHelperDefault.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelperDefault.setCa(TestData.CA_NAME);
        addEndEntityHelperDefault.setToken("JKS file");
        addEndEntityHelperDefault.addEndEntity();
    }

    @Test
    public void stepM2_enableSwagger(){
        systemConfigurationHelper.openPage(getAdminWebUrl());
        systemConfigurationHelper.openTab(SysConfigTabs.PROTOCOLCONFIG);
        systemConfigurationHelper.enableProtocol(SysConfigProtokols.REST_CERTIFICATE_MANAGEMENT);
    }

    //@Ignore
    @Test()
    public void stepO_GenerateAndRevokeCertificates() throws InterruptedException {
        //Open Swagger
        swaggerUIHelper.openPage(getSwaggerWebUrl());
        //First Generate a certificate for the user
        swaggerUIHelper.postEnrollKeystore();
        swaggerUIHelper.tryEnrollKeystore();
        swaggerUIHelper.setEnrollKeystoreAsJson(TestData.USERNAME, TestData.PASSWORD, "RSA", "2048");
        swaggerUIHelper.executeEnrollKeystoreRequest();
        //Now verify the response
        swaggerUIHelper.assertEnrollKeystoreSuccess();
        //**Wait a minute for the certificate to propagate in the system**
        Thread.sleep(30000);
        //Get the certificate serial number from database
        Collection<CertificateWrapper> certificateDataList = findSerialNumber(TestData.USERNAME);
        String certificateSerialNumber = CertTools.getSerialNumberAsString(certificateDataList.iterator().next().getCertificate());
        //Revoke certificate
        swaggerUIHelper.putCertificateRevoke();
        swaggerUIHelper.tryCertificateRevoke();
        swaggerUIHelper.setCaSubjectDnForCertificateRevoke(TestData.ISSUER_DN);
        swaggerUIHelper.setCertificateSerialNumber(certificateSerialNumber);
        swaggerUIHelper.setReasonToRevoke("UNSPECIFIED");
        // Get date -2 days from now
        final ZonedDateTime zonedDateTime = WebTestUtil.getUtcLocalDateTime(0, 0 , -2);
        swaggerUIHelper.setDateToRevoke(DateTimeFormatter.ISO_INSTANT.format(zonedDateTime));
        swaggerUIHelper.executeCertificateRevoke();
        swaggerUIHelper.assertCertificateRevokeSuccess();
    }

    @Test
    public void stepN_CreateCRL() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(TestData.CA_NAME);
        caStructureHelper.assertCrlLinkWorks(TestData.CA_NAME);
    }

    @Test
    public void stepP_AssertCrlPartitionLinksInCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertDefaultCrlDistributionPointUri(getCrlUri()
                + TestData.CA_NAME + "&partition=*");
    }

    @Test
    public void stepQ_AssertCrlPartitionLinksInCertProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void stepR_OpenServicePage() {
        servicesHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void stepS_AddServices() {
        servicesHelper.addService(TestData.CRL_SERVICE);
    }

    @Test
    public void stepT_EditServices() {
        servicesHelper.openEditServicePage(TestData.CRL_SERVICE);
        servicesHelper.editService("CRL Updater");
        servicesHelper.setPeriod("1");
        servicesHelper.selectCaToCheck(TestData.CA_NAME);
        servicesHelper.checkActive(true);
    }

    @Test(timeout = 65000)
    public void stepU_SaveService() {
        servicesHelper.saveService();
    }

    @Test
    public void stepV_AssertCrlCount() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(TestData.CA_NAME);
    }

}
