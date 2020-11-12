/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import com.digicert.autoenroll.DigicertAPI;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @version $Id$
 */
public class TemplateSettings {
    private static final Logger log = Logger.getLogger(TemplateSettings.class);
    
    private int id;
    private String oid = null;  
    private String certprofile = "";
    private String eeprofile = "";
    private String subject_name_format = "";
    private boolean include_email_in_subjectdn = false;
    private boolean include_email_in_san = false;
    private boolean include_email = false;
    private boolean include_dns_name_in_san = false;
    private boolean include_upn_in_san = false;
    private boolean include_spn_in_san = false;
    private boolean include_netbios_in_san = false;
    private boolean include_domain_in_san = false;
    private boolean include_objectguid_in_san = false;
    private String additional_subjectdn_attributes = "";
    private String signature_hash = "sha256";
    private int organization_id = -1;
    private int validity_years = -1;
    private String product = "";
    private String organization_units = "";
    private boolean publish_to_active_directory = false;

    public String getSignature_hash() {
        return signature_hash;
    }

    public void setSignature_hash(String signature_hash) {
        this.signature_hash = signature_hash;
    }

    public int getOrganization_id() {
        return organization_id;
    }

    public void setOrganization_id(int organization_id) {
        this.organization_id = organization_id;
    }

    public int getValidity_years() {
        return validity_years;
    }

    public void setValidity_years(int validity_years) {
        this.validity_years = validity_years;
    }

    public String getProduct() {
        return product;
    }

    public void setProduct(String product) {
        this.product = product;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getOid() {
        return oid;
    }

    public void setOid(String oid) {
        this.oid = oid;
    }

    public String getCertprofile() {
        return certprofile;
    }

    public void setCertprofile(String certprofile) {
        this.certprofile = certprofile;
    }

    public String getEeprofile() {
        return eeprofile;
    }

    public void setEeprofile(String eeprofile) {
        this.eeprofile = eeprofile;
    }

    public String getSubject_name_format() {
        return subject_name_format;
    }

    public void setSubject_name_format(String subject_name_format) {
        this.subject_name_format = subject_name_format;
    }

    public boolean isInclude_email_in_subjectdn() {
        return include_email_in_subjectdn;
    }

    public void setInclude_email_in_subjectdn(boolean include_email_in_subjectdn) {
        this.include_email_in_subjectdn = include_email_in_subjectdn;
    }

    public boolean isInclude_email_in_san() {
        return include_email_in_san;
    }

    public void setInclude_email_in_san(boolean include_email_in_san) {
        this.include_email_in_san = include_email_in_san;
    }

    public boolean isInclude_dns_name_in_san() {
        return include_dns_name_in_san;
    }

    public void setInclude_dns_name_in_san(boolean include_dns_name_in_san) {
        this.include_dns_name_in_san = include_dns_name_in_san;
    }

    public boolean isInclude_upn_in_san() {
        return include_upn_in_san;
    }

    public void setInclude_upn_in_san(boolean include_upn_in_san) {
        this.include_upn_in_san = include_upn_in_san;
    }

    public boolean isInclude_spn_in_san() {
        return include_spn_in_san;
    }

    public void setInclude_spn_in_san(boolean include_spn_in_san) {
        this.include_spn_in_san = include_spn_in_san;
    }

    public boolean isInclude_netbios_in_san() {
        return include_netbios_in_san;
    }

    public void setInclude_netbios_in_san(boolean include_netbios_in_san) {
        this.include_netbios_in_san = include_netbios_in_san;
    }

    public boolean isInclude_domain_in_san() {
        return include_domain_in_san;
    }

    public void setInclude_domain_in_san(boolean include_domain_in_san) {
        this.include_domain_in_san = include_domain_in_san;
    }

    public boolean isInclude_objectguid_in_san() {
        return include_objectguid_in_san;
    }

    public void setInclude_objectguid_in_san(boolean include_objectguid_in_san) {
        this.include_objectguid_in_san = include_objectguid_in_san;
    }

    public String getAdditional_subjectdn_attributes() {
        return additional_subjectdn_attributes;
    }

    public void setAdditional_subjectdn_attributes(String additional_subjectdn_attributes) {
        this.additional_subjectdn_attributes = additional_subjectdn_attributes;
    }

    public boolean isPublish_to_active_directory() {
        return publish_to_active_directory;
    }

    public void setPublish_to_active_directory(boolean publish_to_active_directory) {
        this.publish_to_active_directory = publish_to_active_directory;
    }

    public String getOrganization_units() {
        return organization_units;
    }

    public void setOrganization_units(String organization_units) {
        this.organization_units = organization_units;
    }

    public boolean isInclude_email() {
        return include_email;
    }

    void setInclude_email(boolean include_email) {
        this.include_email = include_email;
    }

    public void validateTemplateSettings(ApplicationProperties msEnrollmentProperties) throws IOException, EnrollmentException {
        String apiKey = msEnrollmentProperties.getAPIKEY();
        String baseURL = msEnrollmentProperties.getBASEURL();

        DigicertAPI digicertAPI = new DigicertAPI(apiKey, baseURL);
        String details = digicertAPI.viewProductDetails(product);
        JsonObject jsonObject = new JsonParser().parse(details).getAsJsonObject();

        //Validate validity_years
        JsonArray allowed_validity_years = jsonObject.get("allowed_validity_years").getAsJsonArray();
        boolean is_valid_year = false;
        List<String> listValidYears = new ArrayList<>();
        for(JsonElement year : allowed_validity_years) {
            int valid_year = year.getAsInt();
            listValidYears.add(String.valueOf(valid_year));
            if(validity_years == valid_year) {
                is_valid_year = true;
                break;
            }
        }
        if(!is_valid_year) {
            throw new EnrollmentException("Validity years for product [" + product + "] has an invalid value of "
                    + validity_years + ". Valid values are " + String.join(",", listValidYears));
        }

        //Validate additional_dns_names_allowed
        boolean is_additional_dns_names_allowed = jsonObject.get("additional_dns_names_allowed").getAsBoolean();
        if(!is_additional_dns_names_allowed) {
            if(include_domain_in_san || include_netbios_in_san) {
                throw new EnrollmentException("DNS Names such as NETBIOS, domain, and DNS hostname are not allowed for product [" + product + "]");
            }
        }

        //Validate signature_hash_types
        boolean is_valid_hash_type = false;
        JsonObject signature_hash_types = jsonObject.get("signature_hash_types").getAsJsonObject();
        JsonArray allowed_hash_types = signature_hash_types.get("allowed_hash_types").getAsJsonArray();
        List<String> listValidHashTypes = new ArrayList<>();
        for(JsonElement hash_type : allowed_hash_types) {
            JsonObject allowed_hash_type = hash_type.getAsJsonObject();
            String hash_id = allowed_hash_type.get("id").getAsString();
            listValidHashTypes.add(hash_id);
            if(hash_id.equals(signature_hash)) {
                is_valid_hash_type = true;
                break;
            }
        }
        if(!is_valid_hash_type) {
            throw new EnrollmentException("Signature hash for product [" + product + "] has an invalid value of "
                    + signature_hash + ". Valid values are: " + String.join(",", listValidHashTypes));
        }

        if(log.isDebugEnabled()){
            log.debug("Template Settings for id " + id + " and product [" + product + "] is valid");
        }
    }
}
