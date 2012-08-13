/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.pub;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.util.DNFieldDescriber;

/**
 * Used by enrol/reg*.jsp for self-registration. This bean implements
 * implements listing of certificate types (defined in web.properties),
 * listing of modifiable end-entity fields and submission of requests.
 * 
 * @version $Id$
 */
public class RegisterReqBean {
    
    private static final Logger log = Logger.getLogger(RegisterReqBean.class);
    
    
    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private final EndEntityProfileSessionLocal endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
    private final CertificateProfileSessionLocal certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
    private final EndEntityManagementSessionLocal userAdminSession = ejbLocalHelper.getUserAdminSession();
    private final ApprovalSessionLocal approvalSession = ejbLocalHelper.getApprovalSession();
    private final GlobalConfiguration globalConfiguration = ejbLocalHelper.getGlobalConfigurationSession().getCachedGlobalConfiguration();

    // Form fields
    private final Map<String,String> formFields = new HashMap<String,String>();
    
    private String certType;
    
    private String username;
    private String email;
    private String captcha;
    
    // Form errors
    private final List<String> errors = new ArrayList<String>();
    private boolean initialized = false;
    private String remoteAddress;
    
    /**
     * Finds all properties matching web.selfreg.certtypes.KEY.description=VALUE
     * and returns a map with these keys and values.
     */
    public Map<String,String> getCertificateTypes() {
        Map<String,String> certtypes = new HashMap<String,String>();
        for (Entry<Object,Object> entry : EjbcaConfigurationHolder.getAsProperties().entrySet()) {
            final Object k = entry.getKey();
            final Object v = entry.getValue();
            if (k instanceof String && v instanceof String) {
                String key = (String)k;
                if (key.matches("web\\.selfreg\\.certtypes\\.([^.]+)\\.description")) {
                    certtypes.put(key.split("\\.")[3], (String)v);
                }
            }
        }
        return certtypes;
    }
    
    /**
     * Reads config property web.selfreg.certtypes.CERTTYPE.xxxxx from web.xml
     */
    private String getCertTypeInfo(String certType, String subproperty) {
        String key = "web.selfreg.certtypes."+certType+"."+subproperty;
        String value = EjbcaConfigurationHolder.getString(key);
        if (value == null) {
            throw new IllegalStateException("property "+key+" not configured");
        }
        return value;
    }
    
    public String getCertType() {
        return certType;
    }
    
    public String getCertTypeDescription() {
        return getCertTypeInfo(certType, "description");
    }
    
    public int getEndEntityProfileId() {
        return endEntityProfileSession.getEndEntityProfileId(getCertTypeInfo(certType, "eeprofile"));
    }
    
    public int getCertificateProfileId() {
        return certificateProfileSession.getCertificateProfileId(getCertTypeInfo(certType, "certprofile"));
    }
    
    public String getDefaultCertType() {
        String s = EjbcaConfigurationHolder.getString("web.selfreg.defaultcerttype");
        return (s != null ? s : "1");
    }
    
    /**
     * Returns a list of all modifiable certificate fields in the
     * end-entity profile of the given certtype.
     */
    public List<DNFieldDescriber> getModifiableCertFields() {
        List<DNFieldDescriber> fields = new ArrayList<DNFieldDescriber>();
        EndEntityProfile eeprofile = endEntityProfileSession.getEndEntityProfile(getCertTypeInfo(certType, "eeprofile"));
        
        int numberofsubjectdnfields = eeprofile.getSubjectDNFieldOrderLength();
        for (int i=0; i < numberofsubjectdnfields; i++) {
            int[] fielddata = eeprofile.getSubjectDNFieldsInOrder(i);
            int fieldType = fielddata[EndEntityProfile.FIELDTYPE];
            
            if (eeprofile.isModifyable(fieldType, 0)) {
                fields.add(new DNFieldDescriber(fieldType, eeprofile));
            }
        }
        
        return fields;
    }
    
    public void initialize(final HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            errors.add("Internal error: Invalid request method.");
        }

        // Get all fields
        @SuppressWarnings("rawtypes")
        Enumeration en = request.getParameterNames();
        while (en.hasMoreElements()) {
            String key = (String)en.nextElement();
            if (key.startsWith("field_")) {
                String value = request.getParameter(key);
                if (!value.trim().isEmpty()) {
                    formFields.put(key.replaceFirst("^field_", ""), value);
                }
            }
        }
        
        certType = request.getParameter("certType");
        
        // User account
        username = request.getParameter("username");
        email = request.getParameter("email");
        captcha = request.getParameter("code");
        
        remoteAddress = request.getRemoteAddr();
        initialized = true;
    }
    
    private void checkFormFields() {
        boolean nameError = false;
        
        if (certType == null || certType.isEmpty()) {
            errors.add("Certificate type is not specified.");
        }
        
        // User account
        if (username == null || username.isEmpty()) {
            errors.add("Username is not specified.");
            nameError = true;
        }
        
        if (email == null || !email.matches("[^@]+@.+")) {
            errors.add("E-mail is not specified.");
        }

        // The captcha simply is the last character of the name
        if (!nameError && (captcha == null || !captcha.equalsIgnoreCase(username.substring(username.length()-1)))) {
            errors.add("Captcha code is incorrect.");
        }
    }
    
    /**
     * Returns a list of errors to be displayed by the .jsp
     */
    public List<String> getErrors() {
        return new ArrayList<String>(errors);
    }
    
    private String getSubjectDN() {
        boolean first = true;
        StringBuilder sb = new StringBuilder();
        for (Entry<String,String> field : formFields.entrySet()) {
            if (first) { first = false; } 
            else { sb.append(", "); }
            
            sb.append(org.ietf.ldap.LDAPDN.escapeRDN(field.getKey().toUpperCase(Locale.ROOT) + "=" + field.getValue()));
        }
        return sb.toString();
    }
    
    /**
     * Creates a approval request from the given information in the form.
     * initialize() must have been called before this method is called.  
     */
    public void submit() {
        if (!initialized) {
            throw new IllegalStateException("initialize not called before submit");
        }
        
        // Set up config for admingui (e.g. for e-mails to admins with links to it) 
        globalConfiguration.initializeAdminWeb();
        
        checkFormFields();
        
        if (!errors.isEmpty()) {
            return;
        }
        
        final int eeProfileId = getEndEntityProfileId();
        final EndEntityProfile eeprofile = endEntityProfileSession.getEndEntityProfile(eeProfileId);
        final int caid = eeprofile.getDefaultCA();
        if (caid == -1) {
            errors.add("The selected end-entity profile does not have any default CA. Please make sure you selected the correct profile and contact your administrator.");
        }
        
        String domainRequirement = eeprofile.getValue(EndEntityProfile.EMAIL, 0);
        if (domainRequirement != null && domainRequirement.matches("[^\\s]")) {
            throw new UnsupportedOperationException("Self-registration does not yet support e-mail domain restrictions in end-entity profiles.");
        }
        
        final int certProfileId = getCertificateProfileId();
        
        if (userAdminSession.existsUser(username)) {
            errors.add("A user with that name exists already");
        }
        
        if (!errors.isEmpty()) {
            return;
        }
        
        final String subjectDN = getSubjectDN();
        final int numApprovalsRequired = 1;
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RegisterReqBean: "+remoteAddress));
        
        final EndEntityInformation endEntity = new EndEntityInformation(username, subjectDN, caid, null, 
                null, UserDataConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId,
                null,null, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        endEntity.setSendNotification(true);
        if (email != null && eeprofile.isModifyable("EMAIL", 0)) {
            endEntity.setEmail(email);
        }
        
        try {
            userAdminSession.canonicalizeUser(endEntity);
            if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
                eeprofile.doesUserFullfillEndEntityProfile(endEntity, false);
                
            }
        } catch (EjbcaException e) {
            errors.add("Validation error: "+e.getMessage());
            return;
        } catch (UserDoesntFullfillEndEntityProfile e) {
            errors.add("User information does not fulfill requirements: "+e.getMessage());
            return;
        }
        
        // Add approval request
        final AddEndEntityApprovalRequest approvalReq = new AddEndEntityApprovalRequest(endEntity,
                false, admin, null, numApprovalsRequired, caid, eeProfileId);
        
        try {
            approvalSession.addApprovalRequest(admin, approvalReq, globalConfiguration);
        } catch (EjbcaException e) {
            errors.add("Could not submit the information for approval: "+e.getMessage());
            log.error("Approval request could not be added", e);
        }
    }
    
}



