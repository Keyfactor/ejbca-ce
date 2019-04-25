package org.ejbca.webtest.helper;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.ejbca.webtest.utils.GetADate;
import org.hamcrest.CoreMatchers;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import java.io.File;
import java.io.FileReader;
import java.util.Collection;

public class SwaggerUIHelper extends BaseHelper {

    private final String csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIDWDCCAkACAQAwYTELMAkGA1UEBhMCRUUxEDAOBgNVBAgTB0FsYWJhbWExEDAO\n"
            + "BgNVBAcTB3RhbGxpbm4xFDASBgNVBAoTC25hYWJyaXZhbHZlMRgwFgYDVQQDEw9o\n"
            + "ZWxsbzEyM3NlcnZlcjYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDe\n"
            + "lRzGyeXlCQL3lgLjzEn4qcbD0qtth8rXAwjg/eEN1u8lpQp3GtByWm6LeeB7CEyP\n"
            + "fyy+rW9C7nQmXvJ09cJaLAlETpGjjfZLy6pHzle/D192THB2MYZRuvvAPCfpjjnV\n"
            + "hP9sYn7GN7kCaYh61fvlD2fVquzqRdz9kjib3mVEmswkS6lHuAPIsmI7SG9UuvPR\n"
            + "ND1DOsmVwqOL62EOE/RlHRStxZDHQDoYMqZISAO5arpbDujn666IVqLs1QpsQ5Ih\n"
            + "Avxlw+EGNzzYMCbFEkuGs5JK/YNS7JL3JrvMor8XLngaatbteztK0o+khgT2K9x7\n"
            + "BCkqEoz9iJrmO3B8JDATAgMBAAGggbEwga4GCSqGSIb3DQEJDjGBoDCBnTBQBgNV\n"
            + "HREESTBHggtzb21lZG5zLmNvbYcEwKgBB4ISc29tZS5vdGhlci5kbnMuY29tpB4w\n"
            + "HDENMAsGA1UEAxMEVGVzdDELMAkGA1UEBxMCWFgwMQYDVR0lBCowKAYIKwYBBQUH\n"
            + "AwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUHAwQwCQYDVR0TBAIwADALBgNV\n"
            + "HQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAM2cW62D4D4vxaKVtIYpgolbD0zv\n"
            + "WyEA6iPa4Gg2MzeLJVswQoZXCj5gDOrttHDld3QQTDyT9GG0Vg8N8Tr9i44vUr7R\n"
            + "gK5w+PMq2ExGS48YrCoMqV+AJHaeXP+gi23ET5F6bIJnpM3ru6bbZC5IUE04YjG6\n"
            + "xQux6UsxQabuaTrHpExMgYjwJsekEVe13epUq5OiEh7xTJaSnsZm+Ja+MV2pn0gF\n"
            + "3V1hMBajTMGN9emWLR6pfj5P7QpVR4hkv3LvgCPf474pWA9l/4WiKBzrI76T5yz1\n"
            + "KoobCZQ2UrqnKFGEbdoNFchb2CDgdLnFu6Tbf6MW5zO5ypOIUih61Zf9Qyo=\n"
            + "-----END CERTIFICATE REQUEST-----\n";

    public SwaggerUIHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    public static class Page {
        //General
        static final String PAGE_URI = "/ejbca/swagger-ui";


        //pcks10enroll
        static final By BUTTON_POST_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] span.opblock-summary-method");
        static final By BUTTON_TRYIT_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] div.try-out > button");
        static final By BODY_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] textarea");
        static final By BUTTON_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] button[class*='execute']");

        static final By BUTTON_DOWNLOAD_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] div.download-contents");
        static final By TEXT_RESPONSE_CODE_PKCS10ENROLL = By.cssSelector("div[id$='certificate-enrollPkcs10Certificate'] tr[class*='response'] td[class*=\"col_status\"]");

        //enrollkeystore
        static final By BUTTON_POST_ENROLLKEYSTORE = By.cssSelector("div[id$=\"certificate-enrollKeystore\"] span.opblock-summary-method");
        static final By BUTTON_TRYIT_ENROLLKEYSTORE = By.cssSelector("div[id$='certificate-enrollKeystore'] div.try-out > button");
        static final By BODY_ENROLLKEYSTORE = By.cssSelector("div[id$='certificate-enrollKeystore'] textarea");
        static final By BUTTON_EXECUTE_ENROLLKEYSTORE = By.cssSelector("div[id$=certificate-enrollKeystore] button[class*='execute']");

        static final By BUTTON_DOWNLOAD_ENROLLKEYSTORE = By.cssSelector("div[id$=certificate-enrollKeystore] div.download-contents");
        static final By TEXT_RESPONSE_CODE_ENROLLKEYSTORE = By.cssSelector("div[id$=certificate-enrollKeystore] table.responses-table:nth-child(4) tbody tr[class*='response'] td[class*=\"col_status\"]");

        //Revoke
        static final By BUTTON_PUT_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] span.opblock-summary-method");
        static final By BUTTON_TRYIT_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] div.try-out > button");

        static final By TEXT_CA_SUBJECT_DN_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] [placeholder*=\"issuer_dn\"]");
        static final By TEXT_CERT_SERIAL_NUMBER_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] [placeholder*='certificate_serial_number']");
        static final By TEXT_REASON_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] [placeholder*='reason']");
        static final By TEXT_DATE_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] [placeholder*='date']");

        static final By BUTTON_EXECUTE_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] button[class*='execute']");

        static final By BUTTON_DOWNLOAD_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] div.download-contents");
        static final By TEXT_RESPONSE_CODE_CERTREVOKE = By.cssSelector("div[id$=certificate-revokeCertificate] table.responses-table:nth-child(4) tbody tr[class*='response'] td[class*=\"col_status\"]");
    }

    //General Operations

    public void openPage(final String webUrl) {
            openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }

    /**
     * Return the certificate serial number.
     * The returned serial number can be used to revoke
     *
     * @return
     */
    public String getCertificateSerialNumber() {
        return getDownloadedResponse().get("serial_number").toString();
    }

    public String getErrorMessage() {
        return getDownloadedResponse().get("error_message").toString();
    }


    //PKCS10 Enroll Certificate (UNTESTED AT THIS TIME)

    /**
     * Click the post button for pkcs10enroll
     *
     */
    public void postPkcs10Enroll() {
        clickLink(Page.BUTTON_POST_PKCS10ENROLL);
    }

    /**
     * Click the Try It button for pkcs10enroll
     *
     */
    public void tryPkcs10Enroll() {
        clickLink(Page.BUTTON_TRYIT_PKCS10ENROLL);
    }

    /**
     * Set PKCS request as JSON to body
     *
     * @param certProfile
     * @param endEntity
     * @param caName
     * @param uname
     * @param pword
     */
    public void setPkcs10RequestAsJson(String certProfile, String endEntity,
                                       String caName, String uname, String pword) {

        StringBuilder sb = new StringBuilder("\n\"certificate_request\": \"" + csr + "\",");

        //append the remaining JSON lines
        sb.append("\n\"certificate_profile_name\": \"" + certProfile + "\",");
        sb.append("\n\"end_entity_profile_name\": \"" + endEntity + "\",");
        sb.append("\n\"certificate_authority_name\": \"" + caName + "\",");
        sb.append("\n\"username\": \"" + uname + "\",");
        sb.append("\n\"password\": \"" + pword + "\"\n");

        fillSwaggerTextarea(Page.BODY_PKCS10ENROLL, sb.toString(), true);
    }

    /**
     * Click the Execute request button.
     *
     */
    public void executePkcs10Request() {
        clickLink(Page.BUTTON_PKCS10ENROLL);
    }

    /**
     * Click to download the response as a file.
     *
     */
    public void downloadEnrollPkcsResponse() {
        clickLink(Page.BUTTON_DOWNLOAD_PKCS10ENROLL);
    }

    /**
     * Assert enrollment was successful
     *
     */
    public void assertEnrollPkcsSuccess() {
        assertEquals("Unsuccessful certificate enrollment by pkcs10",
                getElementText(Page.TEXT_RESPONSE_CODE_PKCS10ENROLL).equals("200"),
                "200");
    }


    //Enroll Keystore

    /**
     * Click the post button for enroll keystore
     *
     */
    public void postEnrollKeystore() {
        clickLink(Page.BUTTON_POST_ENROLLKEYSTORE);
    }

    /**
     * Click the Try It button for enroll keystore
     *
     */
    public void tryEnrollKeystore() {
        clickLink(Page.BUTTON_TRYIT_ENROLLKEYSTORE);
    }

    /**
     * Set the enroll keystore as JSON to the body
     *
     * @param username
     * @param password
     * @param keySig
     * @param keySpec
     */
    public void setEnrollKeystoreAsJson(String username, String password,
                                       String keySig, String keySpec) {

        StringBuilder sb = new StringBuilder("\n\"username\": \"" + username + "\",");

        //append the remaining JSON lines
        sb.append("\n\"password\": \"" + password + "\",");
        sb.append("\n\"key_alg\": \"" + keySig + "\",");
        sb.append("\n\"key_spec\": \"" + keySpec + "\"\n");

        fillSwaggerTextarea(Page.BODY_ENROLLKEYSTORE, sb.toString(), true);
    }

    /**
     * Click the Execute request button.
     *
     */
    public void executeEnrollKeystoreRequest() {
        try {
            clickLink(Page.BUTTON_EXECUTE_ENROLLKEYSTORE);
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Click to download the response as a file.
     *
     */
    public void downloadEnrollKeystoreResponse() {
        clickLink(Page.BUTTON_DOWNLOAD_ENROLLKEYSTORE);
    }

    /**
     * Assert enrollment was successful
     *
     */
    public String assertEnrollKeystoreSuccess() {
        String responseCode = getElementText(Page.TEXT_RESPONSE_CODE_ENROLLKEYSTORE);
        assertThat("Unsuccessful certificate enrollment by enroll keystore",
                getElementText(Page.TEXT_RESPONSE_CODE_ENROLLKEYSTORE),
                CoreMatchers.containsString("201"));
        return responseCode;
    }


    //Revoke Certificate

    /**
     * Click put certificate revoke button
     *
     */
    public void putCertificateRevoke() {
        clickLink(Page.BUTTON_PUT_CERTREVOKE);
    }

    /**
     * Click try it certificate revoke button
     *
     */
    public void tryCertificateRevoke() {
        clickLink(Page.BUTTON_TRYIT_CERTREVOKE);
    }

    /**
     * Set the subject dn of the certificate to revoke in the field.
     *
     * @param subjectDn
     */
    public void setCaSubjectDnForCertificateRevoke(String subjectDn) {
        fillInput(Page.TEXT_CA_SUBJECT_DN_CERTREVOKE, subjectDn);
    }

    /**
     * Set the serial number of the certificate to revoke in the field.
     *
     * @param certSerialNumber
     */
    public void setCertificateSerialNumber(String certSerialNumber) {
        fillInput(Page.TEXT_CERT_SERIAL_NUMBER_CERTREVOKE, certSerialNumber);
    }

    /**
     * Set the reason to revoke the certificate in the field.
     *
     * @param reason
     */
    public void setReasonToRevoke(String reason) {
        fillInput(Page.TEXT_REASON_CERTREVOKE, reason);
    }

    /**
     * Set the date to revoke certificate in the field.
     *
     */
    public void setDateToRevoke() {
        String date = new GetADate().getIso8601Date();
        fillInput(Page.TEXT_DATE_CERTREVOKE, date);
    }

    /**
     * Click execute to revoke the certificate
     *
     */
    public void executeCertificateRevoke() {
        clickLink(Page.BUTTON_EXECUTE_CERTREVOKE);
    }

    /**
     * Assert certificate revoke was successful
     *
     */
    public String assertCertificateRevokeSuccess() {
        String responseCode = getElementText(Page.TEXT_RESPONSE_CODE_CERTREVOKE);
        assertThat("Unsuccessful certificate revoke",
                getElementText(Page.TEXT_RESPONSE_CODE_CERTREVOKE),
                CoreMatchers.containsString("200"));
        return responseCode;
    }

    /**
     * Click to download the response as a file.
     *
     */
    public void downloadCertificateRevokeResponse() {
        clickLink(Page.BUTTON_DOWNLOAD_CERTREVOKE);
    }

    //Private internal utility methods

    /**
     * Fetch downloaded response
     *
     */
    private JSONObject getDownloadedResponse() {
        JSONParser parser = new JSONParser();
        JSONObject jsonObject = new JSONObject();

        try {
            //Determine the OS
            String os = System.getProperty("os.name");
            String downloadDir = null;

            if (os.contains("win")) {
                downloadDir = "C:/tmp/";
            } else {
                downloadDir = "/tmp/";
            }


            File directory = new File(downloadDir);
            Collection<File> f = FileUtils.listFiles(directory, new WildcardFileFilter("response*.json"), null);
            System.out.println("how many:  " + f.size());

            File file = f.iterator().next();

            Object obj = parser.parse(new FileReader(file.getAbsolutePath()));
            jsonObject =  (JSONObject) obj;

            file.delete();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return jsonObject;
    }


}
