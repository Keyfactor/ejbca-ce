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

import org.apache.log4j.Logger;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Properties;

/**
 *
 */
class MSTemplateToSettings extends Properties {
    
	private static final long serialVersionUID = -1014415369329076653L;
    private static final Logger log = Logger.getLogger(MSTemplateToSettings.class);

	private LinkedHashMap<String, TemplateSettings> data = new LinkedHashMap<>();
    private static final String strFileName = "MSTemplateToSettings.properties";
    
    private void addTemplateSettings(TemplateSettings ts) {
        data.put(ts.getOid(), ts);
    }
    
    LinkedHashMap<String, TemplateSettings> load(String configPath) throws Exception {

        try{
            Properties props = new Properties();
            try (InputStream is = new FileInputStream(configPath + strFileName)) {
                props.load(is);
            }
            
            int count = 0;
            for(int i=1;i<100;i++){
                if(props.get("id" + i +".oid")!=null){
                    if(log.isDebugEnabled()) {
                        log.debug("found " + props.get("id" + i +".oid"));
                    }
                    final TemplateSettings ts = getTemplateSettingsFromFile(i, props);
                    if(null != ts) {
                        addTemplateSettings(ts);
                        count++;
                    }
                }
            }
            if(log.isDebugEnabled()) {
                log.debug("Nr of read Template Settings from file: " + count);
            }
        }catch(IOException e){
            log.error("Error parsing the 'MSTemplateToSettings.properties' file.", e);
        }
        
        return data;
    }
    
    private TemplateSettings getTemplateSettingsFromFile(int id, Properties propertiesInFile) throws Exception {
        String PROPERTY_ID = "id";
        String PROPERTY_OID = ".oid";
        String PROPERTY_CERTPROFILE = ".certprofile";
        String PROPERTY_EEPROFILE = ".eeprofile";
        String PROPERTY_PRODUCT = ".product";
        String PROPERTY_USED = ".used";
        String PROPERTY_SUBJECTNAMEFORMAT = ".subject_name_format";
        String PROPERTY_INCLUDEEMAILINSUBJECTDN = ".include_email_in_subjectdn";
        String PROPERTY_INCLUDEEMAILINSAN = ".include_email_in_san";
        String PROPERTY_INCLUDEEMAIL = ".include_email";
        String PROPERTY_INCLUDEDNSNAMEINSAN = ".include_dns_name_in_san";
        String PROPERTY_INCLUDEUPNINSAN = ".include_upn_in_san";
        String PROPERTY_INCLUDESPNINSAN = ".include_spn_in_san";
        String PROPERTY_INCLUDENETBIOSINSAN = ".include_netbios_in_san";
        String PROPERTY_INCLUDEDOMAININSAN = ".include_domain_in_san";
        String PROPERTY_INCLUDEOBJECTGUIDINSAN = ".include_objectguid_in_san";
        String PROPERTY_ADDITIONALSUBJECTDNATTRIBUTES = ".additional_subjectdn_attributes";
        String PROPERTY_SIGNATUREHASH = ".signature_hash";
        String PROPERTY_ORGANIZATIONID = ".organization_id";
        String PROPERTY_VALIDITYYEARS = ".validity_years";
        String PROPERTY_ORGANIZATIONUNITS = ".organization_units";
        String PROPERTY_PUBLISHTOACTIVEDIRECTORY = ".publish_to_active_directory";

        try {
            String oid = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_OID);
            String certProfile = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_CERTPROFILE);
            String eeProfile = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_EEPROFILE);
            String product = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_PRODUCT);
            boolean used = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED).trim().equalsIgnoreCase("TRUE");
//            log.debug(PROPERTY_ID + id + PROPERTY_USED + ":" + propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED));
            String subjectNameFormat = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_SUBJECTNAMEFORMAT);
            boolean includeEmailInSubjectDN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEEMAILINSUBJECTDN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeEmailInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEEMAILINSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeEmail = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEEMAIL, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeDNSNameInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEDNSNAMEINSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeUPNInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEUPNINSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeSPNInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDESPNINSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeNETBIOSInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDENETBIOSINSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeDomainInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEDOMAININSAN, "false").trim().equalsIgnoreCase("TRUE");
            boolean includeObjectGUIDInSAN = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_INCLUDEOBJECTGUIDINSAN, "false").trim().equalsIgnoreCase("TRUE");
            String additionalSubjectDNAttributes = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_ADDITIONALSUBJECTDNATTRIBUTES);
            String signatureHash = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_SIGNATUREHASH);
            int organizationID = Integer.parseInt(propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_ORGANIZATIONID, "-1"));
            int validityYears = Integer.parseInt(propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_VALIDITYYEARS, "-1"));
            String organizationUnits = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_ORGANIZATIONUNITS);
            boolean publishToActiveDirectory = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_PUBLISHTOACTIVEDIRECTORY, "false").trim().equalsIgnoreCase("TRUE");

            if (used) {
                if (oid != null) {
                    TemplateSettings ts = new TemplateSettings();
                    ts.setId(id);
                    ts.setOid(oid);
                    ts.setCertprofile(certProfile);
                    ts.setEeprofile(eeProfile);
                    ts.setProduct(product);
                    ts.setSubject_name_format(subjectNameFormat);
                    ts.setInclude_email_in_subjectdn(includeEmailInSubjectDN);
                    ts.setInclude_email_in_san(includeEmailInSAN);
                    ts.setInclude_email(includeEmail);
                    ts.setInclude_dns_name_in_san(includeDNSNameInSAN);
                    ts.setInclude_upn_in_san(includeUPNInSAN);
                    ts.setInclude_spn_in_san(includeSPNInSAN);
                    ts.setInclude_netbios_in_san(includeNETBIOSInSAN);
                    ts.setInclude_domain_in_san(includeDomainInSAN);
                    ts.setInclude_objectguid_in_san(includeObjectGUIDInSAN);
                    ts.setAdditional_subjectdn_attributes(additionalSubjectDNAttributes);
                    ts.setSignature_hash(signatureHash);
                    ts.setOrganization_id(organizationID);
                    ts.setValidity_years(validityYears);
                    ts.setOrganization_units(organizationUnits);
                    ts.setPublish_to_active_directory(publishToActiveDirectory);

                    return ts;
                } else {
                    return null;
                }
            }

        } catch (Exception e) {
            throw new Exception("Template Setting " + id + " seems to be misconfigured in the MSTemplateToSettings.properties - " + e.getMessage());
        }
        return null;
    }
}