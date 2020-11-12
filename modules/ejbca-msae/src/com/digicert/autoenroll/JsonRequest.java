/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.digicert.autoenroll;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.msae.ADObject;
import org.ejbca.msae.EnrollmentException;
import org.ejbca.msae.TemplateSettings;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

class JsonRequest {
    private static final Logger log = Logger.getLogger(JsonRequest.class);

    private String common_name = null;
    private List<String> emails = null;
    private String csr = null;
    private String signature_hash = null;
    private int organization_id = -1;
    private int validity_years = -1;
    private int auto_renew = -1;
    private int renewal_of_order_id = -1;
    private List<String> organization_units = null;
    private int server_platform = -1;
    private int server_platform_id = -1;
    private String profile_option = null;
    private Date custom_expiration_date = null;
    private String comments = null;
    private boolean disable_renewal_notifications = false;
    private String payment_method = null;
    private List<String> dns_names = null;
    private String renewed_thumbprint = null;
    private String product_type_hint = null;
    private String ad_template_oid = null;
    private String ad_major_version = null;
    private String ad_minor_version = null;
    private List<String> domain_components = null;
    private String user_principal_name = null;
    private String service_principal_name = null;
    private String domain_controller_id = null;

    private ADObject adObject;
    private TemplateSettings templateSettings;

    JsonRequest(TemplateSettings templateSettings, ADObject adObject, String domain,
                       String pkcs10request, HashMap<String, String> msTemplateValues) throws EnrollmentException {
        this.adObject = adObject;
        this.templateSettings = templateSettings;
        setCommonName();
        setEmails();
        setDNSNames();
        setCSR(pkcs10request);
        setSignature_hash();
        setOrganization_id();
        setValidity_years();
        setOrganization_units();
        setDomain_components(domain);
        setUser_principal_name();
        setService_principal_name();
        setDomain_controller_id();
        setAd_template_oid(msTemplateValues);
        setAd_major_version(msTemplateValues);
        setAd_minor_version(msTemplateValues);
    }

    private void setCommonName() throws EnrollmentException {
        if (log.isDebugEnabled()) {
            log.debug("*** Building SubjectDN using format: " + templateSettings.getSubject_name_format());
        }

        final String subject_name_format = templateSettings.getSubject_name_format();
        final String cn = adObject.getCn();
        final String dNSHostName = adObject.getDnsHostName();

        // Build SubjectDN
        if (subject_name_format != null) {
            switch (subject_name_format) {
                case "common_name":
                    if (cn != null) {
                        common_name = cn;
                    } else {
                        throw new EnrollmentException("Error: no CN found for the user");
                    }
                    break;
                case "dns_name":
                    if (dNSHostName != null) {
                        common_name = dNSHostName;
                    } else {
                        throw new EnrollmentException("Error: no dNSHostName found for the user");
                    }
                    break;
                default:
                    throw new EnrollmentException("Error: unknown subject_name_format value.");
            }
        } else {
            throw new EnrollmentException("Error: subject_name_format was not set correctly.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Common Name: " + common_name);
        }
    }

    private void setEmails() {
        if (templateSettings.isInclude_email()) {
            // Get emails
            final List<String> emails = getEmailsFromAD();
            if (log.isDebugEnabled()) {
                log.debug("Emails: [" + emails + "]");
            }
            this.emails = emails;
        }
    }

    private List<String> getEmailsFromAD() {
        // Get emails
        List<String> emails = new ArrayList<>();
        String mail = adObject.getMail();

        if (mail != null) {
            emails.add(mail);
        }
        return emails;
    }

    private void setDNSNames () {
        dns_names = getDNSNamesFromAD();
        if (log.isDebugEnabled()) {
            log.debug("Host Names: [" + dns_names + "]");
        }
    }

    private List<String> getDNSNamesFromAD() {
        // Get host names
        List<String> dnsNames = new ArrayList<>();

        final String dNSHostName = adObject.getDnsHostName();
        final String nETBIOSName = adObject.getnETBIOSName();
        final String dnsRoot = adObject.getDnsRoot();

        if (templateSettings.isInclude_dns_name_in_san()) {
            if (dNSHostName != null) {
                dnsNames.add(dNSHostName);
            }
        }

        if (templateSettings.isInclude_netbios_in_san()) {
            if (nETBIOSName != null) {
                dnsNames.add(nETBIOSName);
            }
        }

        if (templateSettings.isInclude_domain_in_san()) {
            if (dnsRoot != null) {
                dnsNames.add(dnsRoot);
            }
        }

        return dnsNames;
    }

    private void setCSR(String pkcs10request) {
        final String BEGINCERTIFICATEREQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
        final String ENDCERTIFICATEREQUEST = "-----END CERTIFICATE REQUEST-----";

        StringBuilder base64FormattedCSR = new StringBuilder();
        base64FormattedCSR.append(BEGINCERTIFICATEREQUEST);
        base64FormattedCSR.append("\n");
        base64FormattedCSR.append(pkcs10request);
        base64FormattedCSR.append("\n");
        base64FormattedCSR.append(ENDCERTIFICATEREQUEST);

        if (log.isDebugEnabled()) {
            log.debug(base64FormattedCSR.toString());
        }

        csr = base64FormattedCSR.toString();
    }

    private void setSignature_hash() {
        signature_hash = templateSettings.getSignature_hash();
    }

    private void setOrganization_id() {
        organization_id = templateSettings.getOrganization_id();
    }

    private void setValidity_years() {
        validity_years = templateSettings.getValidity_years();
    }

    private void setOrganization_units() {
        organization_units = getOrganizationUnits(templateSettings.getOrganization_units());
    }

    private List<String> getOrganizationUnits(String organization_units) {
        // Get organization units
        List<String> organizationUnits = new ArrayList<>();

        if (organization_units != null && !organization_units.equals("")) {
            organizationUnits.add(organization_units);
        }
        return organizationUnits;
    }

    private void setDomain_components(String domain) {
        List<String> domain_components = new ArrayList<>();

        String[] domainSplit = domain.split("\\.");
        Collections.addAll(domain_components, domainSplit);
        this.domain_components = domain_components;
    }

    private void setUser_principal_name() {
        user_principal_name = adObject.getUserPrincipalName();
    }

    private void setService_principal_name() throws EnrollmentException {
        final String userPrincipalName = adObject.getUserPrincipalName();
        if (userPrincipalName != null) {
            service_principal_name = userPrincipalName;
        } else {
            final String sAMAccountName = adObject.getsAMAccountName();
            final String dnsRoot = adObject.getDnsRoot();
            if (sAMAccountName != null && dnsRoot != null) {
                service_principal_name = sAMAccountName + "@" + dnsRoot;
            } else {
                throw new EnrollmentException("Error: no userPrincipalName found for the user");
            }
        }
    }

    private void setDomain_controller_id() {
        final byte[] objectGUID = adObject.getObjectGUID();
        if (null != objectGUID) {
            domain_controller_id = GUIDByteFormat(objectGUID);
        }
    }

    private String GUIDByteFormat(byte[] GUID) {

        String byteGUID = "";

        //Convert the GUID into string using the byte format
        for (byte aGUID : GUID) {
            byteGUID = byteGUID + " " + AddLeadingZero((int) aGUID & 0xFF);
        }

        String octetStringTagLength = "04 10";
        return octetStringTagLength + byteGUID;
    }

    private String AddLeadingZero(int k) {
        return (k < 0xF) ? "0" + Integer.toHexString(k) : Integer.toHexString(k);
    }

    private void setAd_template_oid(HashMap<String, String> msTemplateValues) {
        ad_template_oid = msTemplateValues.get("oid");
    }

    private void setAd_major_version(HashMap<String, String> msTemplateValues) {
        ad_major_version = msTemplateValues.get("majorVersion");
    }

    private void setAd_minor_version(HashMap<String, String> msTemplateValues) {
        ad_minor_version = msTemplateValues.get("minorVersion");
    }

    JsonObject createJsonRequest() {
        final boolean include_email = templateSettings.isInclude_email();
        final boolean include_upn_in_san = templateSettings.isInclude_upn_in_san();
        final boolean include_spn_in_san = templateSettings.isInclude_spn_in_san();
        final boolean include_objectguid_in_san = templateSettings.isInclude_objectguid_in_san();

        JsonObject jsonObj = new JsonObject();

        // Create certificate object
        JsonObject certificateObj = new JsonObject();
        certificateObj.addProperty("common_name", common_name);

        if(include_email) {
            if (null != emails && !emails.isEmpty()) {
                // Create email object from array of emails
                JsonArray emailsArr = new JsonArray();
                for (String email : emails) {
                    emailsArr.add(email);
                }
                certificateObj.add("emails", emailsArr);
            }
        }

        if (null != dns_names && !dns_names.isEmpty()) {
            // Create dns_names object from array of dns_names
            JsonArray dns_namesArr = new JsonArray();
            for (String dns_name : dns_names) {
                dns_namesArr.add(dns_name);
            }
            certificateObj.add("dns_names", dns_namesArr);
        }

        /***** No use for this right now *****
        if (null != domain_components) {
            JsonArray domain_componentsArr = new JsonArray();
            for (String domain_component : domain_components) {
                domain_componentsArr.add(domain_component);
            }
            certificateObj.add("domain_components", domain_componentsArr);
        }
        *************************************/

        if(include_upn_in_san) {
            if (null != user_principal_name) {
                certificateObj.addProperty("user_principal_name", user_principal_name);
            }
        }

        if(include_spn_in_san) {
            if (null != service_principal_name) {
                certificateObj.addProperty("service_principal_name", service_principal_name);
            }
        }

        if(include_objectguid_in_san) {
            if (null != domain_controller_id) {
                certificateObj.addProperty("domain_controller_id", domain_controller_id);
            }
        }

        certificateObj.addProperty("csr", csr);

        if (null != organization_units && !organization_units.isEmpty()) {
            // Create organization units object
            JsonArray organization_unitsArr = new JsonArray();
            for (String organization_unit : organization_units) {
                organization_unitsArr.add(organization_unit);
            }
            certificateObj.add("organization_units", organization_unitsArr);
        }

        // Create server_platform ID object
        if (-1 != server_platform_id) {
            JsonObject serverPlatformIdObj = new JsonObject();
            serverPlatformIdObj.addProperty("id", server_platform_id);
            certificateObj.add("server_platform", serverPlatformIdObj);
        }

        certificateObj.addProperty("signature_hash", signature_hash);

        JsonObject adTemplateObj = new JsonObject();
        adTemplateObj.addProperty("oid", ad_template_oid);
        adTemplateObj.addProperty("major_version", ad_major_version);
        adTemplateObj.addProperty("minor_version", ad_minor_version);
        certificateObj.add("ad_template", adTemplateObj);

        if (null != renewed_thumbprint) {
            certificateObj.addProperty("renewed_thumbprint", renewed_thumbprint);
        }

        if (null != profile_option) {
            certificateObj.addProperty("profile_option", profile_option);
        }

        // Add certificate object
        jsonObj.add("certificate", certificateObj);

        // Create organization ID object
        JsonObject organizationIdObj = new JsonObject();
        organizationIdObj.addProperty("id", organization_id);

        // Add organization object
        jsonObj.add("organization", organizationIdObj);

        // Add validity_years
        jsonObj.addProperty("validity_years", validity_years);

        if (null != custom_expiration_date) {
            jsonObj.addProperty("custom_expiration_date", custom_expiration_date.toString());
        }

        if (null != comments) {
            jsonObj.addProperty("comments", comments);
        }

        if (disable_renewal_notifications) {
            jsonObj.addProperty("disable_renewal_notifications", true);
        }

        if (null != product_type_hint) {
            JsonObject product_type_hintObj = new JsonObject();
            product_type_hintObj.addProperty("type_hint", product_type_hint);
        }

        if (-1 != auto_renew) {
            jsonObj.addProperty("auto_renew", auto_renew);
        }

        if (-1 != renewal_of_order_id) {
            jsonObj.addProperty("renewal_of_order_id", renewal_of_order_id);
        }

        if (null != custom_expiration_date) {
            jsonObj.addProperty("payment_method", payment_method);
        }

        return jsonObj;
    }
}
