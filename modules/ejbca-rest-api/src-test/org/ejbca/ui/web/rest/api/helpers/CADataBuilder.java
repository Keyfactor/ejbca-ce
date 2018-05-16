package org.ejbca.ui.web.rest.api.helpers;

import org.cesecore.certificates.ca.*;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;

import java.util.Properties;

// TODO Javadoc
// TODO Proper creation of CAData
/**
 *
 * @version $Id: CADataBuilder.java 28909 2018-05-10 12:16:53Z aminkh $
 */
public class CADataBuilder {

    private String subjectDn;
    private String name;
    private int status;
    private CA ca;

    CADataBuilder() {
    }

    public static CADataBuilder builder() {
        return new CADataBuilder();
    }

    public static CAData withDefaults() {
        final String caName = "TestCA";
        final String caDn = "CN=" + caName;
        final CA defaultCa = getDefaultX509Ca();
        final CAData caData = builder()
                .subjectDn(caDn)
                .name(caName)
                .status(CAConstants.CA_ACTIVE)
                .ca(defaultCa)
                .build();
        caData.setCaId(1);
        return caData;
    }

    public CADataBuilder subjectDn(final String subjectDn) {
        this.subjectDn = subjectDn;
        return this;
    }

    public CADataBuilder name(final String name) {
        this.name = name;
        return this;
    }

    public CADataBuilder status(final int status) {
        this.status = status;
        return this;
    }

    public CADataBuilder ca(final CA ca) {
        this.ca = ca;
        return this;
    }

    public CAData build() {
        return new CAData(subjectDn, name, status, ca);
    }

    private static X509CAInfo getDefaultX509CaInfo() {
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT , CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken caToken = new CAToken(1, caTokenProperties);
        final X509CAInfo x509CaInfo = new X509CAInfo("CN=TestCA", "TestCA", CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "1d", 0, null, caToken);
        x509CaInfo.setDescription("JUnit RSA CA");
        return x509CaInfo;
    }

    // TODO Doesn't create a proper data for testing
    private static X509CA getDefaultX509Ca() {
        return new X509CA(getDefaultX509CaInfo());
    }

}
