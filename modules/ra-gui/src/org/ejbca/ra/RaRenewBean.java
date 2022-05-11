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
package org.ejbca.ra;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;


/**
 * Backing bean for the Renew Certificate page
 */
@ManagedBean
@ViewScoped
public class RaRenewBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRenewBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private boolean initialized = false;
    private boolean continuePressed = false;
    private String currentSubjectDn;
    private String currentIssuerDn;
    private BigInteger currentSerialNumber;
    private String currentExpirationDate;
    private String caName;
    private String endEntityProfileName;
    private String certificateProfileName;
    private String username;
    private String newSubjectDn;
    private boolean subjectDnChanged;
    private byte[] newToken;
    private String newTokenContentType;
    private String newTokenFileExtension;
    private Integer newApprovalRequestId;
    private boolean certGenerationDone;

    public void initialize() {
        if (initialized) {
            return;
        }
        initialized = true;
        final AuthenticationToken admin = raAuthenticationBean.getAuthenticationToken();
        if (log.isDebugEnabled()) {
            log.debug("Checking authentication token details for '" + admin + "'");
        }
        if (admin instanceof X509CertificateAuthenticationToken) {
            final X509CertificateAuthenticationToken x509AuthToken = (X509CertificateAuthenticationToken) admin;
            final X509Certificate adminCert = x509AuthToken.getCertificate();
            currentSubjectDn = CertTools.getSubjectDN(adminCert);
            final Date notAfter = CertTools.getNotAfter(adminCert);
            if (notAfter != null) {
                currentExpirationDate = ValidityDate.formatAsISO8601ServerTZ(notAfter.getTime(), TimeZone.getDefault());
            } else {
                log.warn("Existing admin certificate has no expiration date.");
            }
            currentIssuerDn = CertTools.getIssuerDN(adminCert);
            currentSerialNumber = CertTools.getSerialNumber(adminCert);
        }
    }

    public String getCurrentSubjectDn() { return currentSubjectDn; }
    public String getCurrentIssuerDn() { return currentIssuerDn; }
    public String getCurrentSerialNumber() { return currentSerialNumber != null ? currentSerialNumber.toString(16) : ""; }
    public String getCurrentExpirationDate() { return currentExpirationDate; }

    public boolean isContinueButtonShown() {
        return currentSerialNumber != null && !continuePressed;
    }

    /** Called when the Continue button is pressed */
    public void checkAndShowDetails() {
        log.debug("Performing dry run of admin client certificate renewal.");
        if (renewCertificate(true)) {
            subjectDnChanged = !newSubjectDn.equals(currentSubjectDn);
            continuePressed = true;
        }
    }

    public boolean isNewDetailsShown() {
        return continuePressed;
    }

    public String getCaName() { return caName; }
    public String getEndEntityProfileName() { return endEntityProfileName; }
    public String getCertificateProfileName() { return certificateProfileName; }
    public String getUsername() { return username; }
    public String getNewSubjectDn() { return newSubjectDn; }
    public boolean isSubjectDnChanged() { return subjectDnChanged; }

    public boolean isRequestRenewalButtonShown() {
        return continuePressed;
    }
    public String renewCertificate() {
        if (certGenerationDone || renewCertificate(false)) {
            certGenerationDone = true; // Don't generate certificate twice, if the user retries the download (or double clicks the button)
            if (newToken != null) {
                log.debug("Admin client certificate renewal was successful. Sending token file to browser.");
                String name = CertTools.getPartFromDN(newSubjectDn, "CN");
                if (name == null){
                    name = "certificate";
                }
                try {
                    DownloadHelper.sendFile(newToken, newTokenContentType, name + newTokenFileExtension);
                } catch (IOException e) {
                    log.info("Token " + name + " could not be downloaded", e);
                    raLocaleBean.addMessageError("enroll_token_could_not_be_downloaded", name);
                }
            } else {
                log.debug("Admin client certificate renewal was requested, and is waiting for approval.");
            }
        }
        return "";
    }

    public Integer getNewApprovalRequestId() { return newApprovalRequestId; }

    public boolean renewCertificate(boolean dryRun) {
        log.debug("Performing admin client certificate renewal.");
        // TODO actually get data and perform renewal (ECA-10706)
        caName = "CA name";
        endEntityProfileName = "EE profile";
        certificateProfileName = "Certificate Profile";
        username = "username";
        newSubjectDn = "CN=test";
        if (!dryRun) {
            if (new Random().nextBoolean()) {
                newToken = new byte[] { 1, 2, 3 };
                newTokenContentType = "application/octet-stream";
                newTokenFileExtension = ".pem";
            } else {
                newApprovalRequestId = new Random().nextInt();
            }
        }
        return true;
    }

}
