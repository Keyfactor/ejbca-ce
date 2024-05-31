package org.ejbca.ui.web.admin.endentity;

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.rainterface.UserView;

@Named
@ViewScoped
public class EditEndEntityMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

     
    static final String ACTION = "action";
    static final String ACTION_EDITUSER = "edituser";
    static final String ACTION_CHANGEPROFILE = "changeprofile";

    static final String BUTTON_SAVE = "buttonedituser";
    static final String BUTTON_CLOSE = "buttonclose";

    static final String TEXTFIELD_NEWUSERNAME = "textfieldnewusername";
    static final String TEXTFIELD_PASSWORD = "textfieldpassword";
    static final String TEXTFIELD_CONFIRMPASSWORD = "textfieldconfirmpassword";
    static final String TEXTFIELD_SUBJECTDN = "textfieldsubjectdn";
    static final String TEXTFIELD_SUBJECTALTNAME = "textfieldsubjectaltname";
    static final String TEXTFIELD_SUBJECTDIRATTR = "textfieldsubjectdirattr";
    static final String TEXTFIELD_EMAIL = "textfieldemail";
    static final String TEXTFIELD_EMAILDOMAIN = "textfieldemaildomain";
    static final String TEXTFIELD_UPNNAME = "textfieldupnnamne";
    static final String TEXTFIELD_STARTTIME = "textfieldstarttime";
    static final String TEXTFIELD_ENDTIME = "textfieldendtime";
    static final String TEXTFIELD_CARDNUMBER = "textfieldcardnumber";
    static final String TEXTFIELD_MAXFAILEDLOGINS = "textfieldmaxfailedlogins";
    static final String TEXTFIELD_CERTSERIALNUMBER = "textfieldcertserialnumber";
    static final String TEXTFIELD_NCANAME = "psd2ncaname";
    static final String TEXTFIELD_NCAID = "psd2ncaid";
    static final String TEXTFIELD_CABFORGANIZATIONIDENTIFIER = "cabforgident";

    static final String TEXTAREA_EXTENSIONDATA = "textareaextensiondata";
    static final String TEXTAREA_NC_PERMITTED = "textarencpermitted"; // Name Constraints
    static final String TEXTAREA_NC_EXCLUDED = "textarencexcluded";

    static final String SELECT_ENDENTITYPROFILE = "selectendentityprofile";
    static final String SELECT_CERTIFICATEPROFILE = "selectcertificateprofile";
    static final String SELECT_TOKEN = "selecttoken";
    static final String SELECT_USERNAME = "selectusername";
    static final String SELECT_PASSWORD = "selectpassword";
    static final String SELECT_CONFIRMPASSWORD = "selectconfirmpassword";
    static final String SELECT_SUBJECTDN = "selectsubjectdn";
    static final String SELECT_SUBJECTALTNAME = "selectsubjectaltname";
    static final String SELECT_SUBJECTDIRATTR = "selectsubjectdirattr";
    static final String SELECT_EMAILDOMAIN = "selectemaildomain";
    static final String SELECT_CHANGE_STATUS = "selectchangestatus";
    static final String SELECT_CA = "selectca";
    static final String SELECT_ALLOWEDREQUESTS = "selectallowedrequests";
    static final String SELECT_ISSUANCEREVOCATIONREASON = "selectissuancerevocationreason";
    static final String SELECT_PSD2_PSPROLE = "selectpsd2psprole";

    static final String CHECKBOX_CLEARTEXTPASSWORD = "checkboxcleartextpassword";
    static final String CHECKBOX_SUBJECTDN = "checkboxsubjectdn";
    static final String CHECKBOX_SUBJECTALTNAME = "checkboxsubjectaltname";
    static final String CHECKBOX_SUBJECTDIRATTR = "checkboxsubjectdirattr";
    static final String CHECKBOX_KEYRECOVERABLE = "checkboxkeyrecoverable";
    static final String CHECKBOX_SENDNOTIFICATION = "checkboxsendnotification";
    static final String CHECKBOX_PRINT = "checkboxprint";

    static final String CHECKBOX_REGENERATEPASSWD = "checkboxregeneratepasswd";

    static final String CHECKBOX_REQUIRED_USERNAME = "checkboxrequiredusername";
    static final String CHECKBOX_REQUIRED_PASSWORD = "checkboxrequiredpassword";
    static final String CHECKBOX_REQUIRED_CARDNUMBER = "checkboxrequiredcardnumber";
    static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
    static final String CHECKBOX_REQUIRED_SUBJECTDN = "checkboxrequiredsubjectdn";
    static final String CHECKBOX_REQUIRED_SUBJECTALTNAME = "checkboxrequiredsubjectaltname";
    static final String CHECKBOX_REQUIRED_SUBJECTDIRATTR = "checkboxrequiredsubjectdirattr";
    static final String CHECKBOX_REQUIRED_EMAIL = "checkboxrequiredemail";
    static final String CHECKBOX_REQUIRED_KEYRECOVERABLE = "checkboxrequiredkeyrecoverable";
    static final String CHECKBOX_REQUIRED_STARTTIME = "checkboxrequiredstarttime";
    static final String CHECKBOX_REQUIRED_ENDTIME = "checkboxrequiredendtime";
    static final String CHECKBOX_REQUIRED_CERTSERIALNUMBER = "checkboxrequiredcertserialnumber";
    static final String CHECKBOX_REQUIRED_NC_PERMITTED = "checkboxrequiredncpermitted";
    static final String CHECKBOX_REQUIRED_NC_EXCLUDED = "checkboxrequiredncexcluded";
    static final String CHECKBOX_REQUIRED_EXTENSIONDATA = "checkboxrequiredextensiondata";

    static final String CHECKBOX_RESETLOGINATTEMPTS = "checkboxresetloginattempts";
    static final String CHECKBOX_UNLIMITEDLOGINATTEMPTS = "checkboxunlimitedloginattempts";

    static final String RADIO_MAXFAILEDLOGINS = "radiomaxfailedlogins";
    static final String RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED = "unlimited";
    static final String RADIO_MAXFAILEDLOGINS_VAL_SPECIFIED = "specified";

    static final String CHECKBOX_VALUE = "true";

    static final String USER_PARAMETER = "username";
    static final String SUBJECTDN_PARAMETER = "subjectdnparameter";

    static final String HIDDEN_USERNAME = "hiddenusername";
    static final String HIDDEN_PROFILE = "hiddenprofile";
    
    
    String THIS_FILENAME = "editendentity.jsp";
    String username = null;
    EndEntityProfile profile = null;
    UserView userdata = null;
    int profileid = EndEntityConstants.NO_END_ENTITY_PROFILE;
    int[] fielddata = null;

    boolean userchanged = false;
    boolean nouserparameter = true;
    boolean notauthorized = true;
    boolean endentitysaved = false;
    boolean usekeyrecovery = false;
    String[] profilenames = null;
    String approvalmessage = null;

    
 // Authentication check and audit log page access request
    @PostConstruct    
    public void initialize() throws Exception {
        
        if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR)) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
        
        final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();

        // Initialize environment.
        GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR,
        AccessRulesConstants.REGULAR_EDITENDENTITY);
        rabean.initialize(ejbcawebbean);

    }

    

    Map<Integer, String> caidtonamemap = ejbcawebbean.getCAIdToNameMap();

    RequestHelper.setDefaultCharacterEncoding(request);

    profilenames = (String[]) ejbcawebbean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.CREATE_END_ENTITY).keySet().toArray(new String[0]);
    
    
    if (request.getParameter(USER_PARAMETER) != null) {
        username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), "UTF-8");
        try {
            userdata = rabean.findUserForEdit(username);
            
            if (userdata != null) {
                notauthorized = false;
                
                if (ACTION_CHANGEPROFILE.equals(request.getParameter(ACTION))) {
                    profileid = Integer.parseInt(request.getParameter(SELECT_ENDENTITYPROFILE));
                    userdata.setEndEntityProfileId(profileid);
                } else if (ACTION_EDITUSER.equals(request.getParameter(ACTION))) {
                    profileid = Integer.parseInt(request.getParameter(HIDDEN_PROFILE));
                    userdata.setEndEntityProfileId(profileid);
                } else {
                    profileid = userdata.getEndEntityProfileId();
                }
                
                profile = rabean.getEndEntityProfile(profileid);
                if (request.getParameter(ACTION) != null) {
                    if (request.getParameter(ACTION).equals(ACTION_EDITUSER)) {
                        if (request.getParameter(BUTTON_SAVE) != null) {
                            UserView newuser = new UserView();
                            newuser.setEndEntityProfileId(profileid);
                            newuser.setUsername(username);
                            String value = request.getParameter(TEXTFIELD_PASSWORD);
                            if (value != null) {
                                value = value.trim();
                                if (!value.equals("")) {
                                    newuser.setPassword(value);
                                }
                            }
                            value = request.getParameter(CHECKBOX_REGENERATEPASSWD);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    newuser.setPassword("NEWPASSWORD");
                                } else {
                                    newuser.setPassword(null);
                                }
                            }
                            value = request.getParameter(SELECT_PASSWORD);
                            if (value != null) {
                                if (!value.equals("")) {
                                    newuser.setPassword(value);
                                }
                            }
                            value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    newuser.setClearTextPassword(true);
                                } else {
                                    newuser.setClearTextPassword(false);
                                }
                            }
                            // Start by filling all old ExtendedInformation from the existing user, if any
                            // Fields that can be edited are changed below, but we don't want to loose anything else
                            //
                            // Fields we handle explicitly (view and edit):
                            // MAXFAILEDLOGINATTEMPTS
                            // EXTENSIONDATA
                            // REMAININGLOGINATTEMPTS
                            // CUSTOM_REQUESTCOUNTER
                            // CUSTOM_REVOCATIONREASON
                            // CUSTOM_ENDTIME
                            // CERTIFICATESERIALNUMBER
                            // NAMECONSTRAINTS_PERMITTED
                            // NAMECONSTRAINTS_EXCLUDED
                            // 
                            // In addition we display information about:
                            // RAWSUBJECTDN
                            // KEYSTORE_ALGORITHM_TYPE
                            // KEYSTORE_ALGORITHM_SUBTYPE
                            // CERTIFICATE_REQUEST
                            ExtendedInformation ei = userdata.getExtendedInformation();
                            if (ei == null) {
                                ei = new ExtendedInformation();
                            }
                            editendentitybean.setExtendedInformation(ei);
                            value = request.getParameter(RADIO_MAXFAILEDLOGINS);
                            if (RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED.equals(value)) {
                                value = "-1";
                            } else {
                                value = request.getParameter(TEXTFIELD_MAXFAILEDLOGINS);
                            }
                            if (value != null) {
                                ei.setMaxLoginAttempts(Integer.parseInt(value));
                                newuser.setExtendedInformation(ei);
                            }
                            value = request.getParameter(TEXTAREA_EXTENSIONDATA);
                            if (value != null) {
                                // Save the new value if the profile allows it
                                if (profile.getUseExtensiondata()) {
                                    editendentitybean.setExtensionData(value);
                                }
                            }
                            value = request.getParameter(CHECKBOX_RESETLOGINATTEMPTS);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    ei.setRemainingLoginAttempts(ei.getMaxLoginAttempts());
                                    newuser.setExtendedInformation(ei);
                                }
                            }
                            value = request.getParameter(TEXTFIELD_EMAIL);
                            String emaildomain = request.getParameter(TEXTFIELD_EMAILDOMAIN);
                            if (value == null || value.trim().equals("")) {
                                if (emaildomain == null || emaildomain.trim().equals("")) {
                                    newuser.setEmail("");
                                } else {
                                    // TEXTFIELD_EMAIL empty but not TEXTFIELD_EMAILDOMAIN
                                    approvalmessage = ejbcawebbean.getText("EMAILINCOMPLETE");
                                }
                            } else {
                                value = value.trim();
                                if (emaildomain != null) {
                                    emaildomain = emaildomain.trim();
                                    if (!emaildomain.equals("")) {
                                        newuser.setEmail(value + "@" + emaildomain);
                                    } else {
                                        // TEXTFIELD_EMAILDOMAIN empty but not TEXTFIELD_EMAIL
                                        approvalmessage = ejbcawebbean.getText("EMAILINCOMPLETE");
                                    }
                                }
                                emaildomain = request.getParameter(SELECT_EMAILDOMAIN);
                                if (emaildomain != null) {
                                    emaildomain = emaildomain.trim();
                                    if (!emaildomain.equals("")) {
                                        newuser.setEmail(value + "@" + emaildomain);
                                    }
                                }
                            }
                            value = request.getParameter(TEXTFIELD_CARDNUMBER);
                            if (value != null) {
                                value = value.trim();
                                newuser.setCardNumber(value);
                            }
                            String subjectdn = "";
                            int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
                            for (int i = 0; i < numberofsubjectdnfields; i++) {
                                value = null;
                                fielddata = profile.getSubjectDNFieldsInOrder(i);
                                if (!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)){
                                    value = request.getParameter(TEXTFIELD_SUBJECTDN + i);
                                } else {
                                    if (request.getParameter(CHECKBOX_SUBJECTDN + i) != null) {
                                        if (request.getParameter(CHECKBOX_SUBJECTDN + i).equals(CHECKBOX_VALUE)) {
                                            value = newuser.getEmail();
                                        }
                                    }
                                }
                                if (value != null) {
                                    value = value.trim();
                                    final String field = DNFieldExtractor.getFieldComponent(
                                            DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                            DNFieldExtractor.TYPE_SUBJECTDN) + value;
                                    final String dnPart;
                                    if (field.charAt(field.length() - 1) != '=') {
                                        dnPart = org.ietf.ldap.LDAPDN.escapeRDN(field);
                                    } else {
                                        dnPart = field;
                                    }
                                    if (subjectdn.equals("")) {
                                        subjectdn = dnPart;
                                    } else {
                                        subjectdn += ", " + dnPart;
                                    }
                                }
                                value = request.getParameter(SELECT_SUBJECTDN + i);
                                if (value != null) {
                                    if (!value.equals("")) {
                                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                                DNFieldExtractor.TYPE_SUBJECTDN) + value);
                                        if (subjectdn.equals("")) {
                                            subjectdn = value;                                    
                                        } else {
                                            subjectdn += ", " + value;
                                        }
                                    }
                                }
                            }
        
                            newuser.setSubjectDN(subjectdn);
        
                            String subjectaltname = "";
                            int numberofsubjectaltnamefields = profile.getSubjectAltNameFieldOrderLength();
                            for (int i = 0; i < numberofsubjectaltnamefields; i++) {
                                fielddata = profile.getSubjectAltNameFieldsInOrder(i);
                                value = null;
                                if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
                                    if (request.getParameter(CHECKBOX_SUBJECTALTNAME + i) != null) {
                                        if (request.getParameter(CHECKBOX_SUBJECTALTNAME + i).equals(CHECKBOX_VALUE)) {
                                            value = newuser.getEmail();
                                        }
                                    } else {
                                        // If we are not using the email field, we have to gether together the email pieces
                                        String dom = request.getParameter(TEXTFIELD_SUBJECTALTNAME + i);
                                        String na = request.getParameter(TEXTFIELD_EMAIL + i);
                                        if ((na != null) && (!na.trim().equals("")) && (dom != null) && (!dom.trim().equals(""))) {
                                            value = na + "@" + dom;
                                        } else {
                                            value = dom;
                                        }
                                    }
                                } else {
                                    if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                                        if (request.getParameter(TEXTFIELD_SUBJECTALTNAME + i) != null
                                                && !request.getParameter(TEXTFIELD_SUBJECTALTNAME + i).equals("")
                                                && request.getParameter(TEXTFIELD_UPNNAME + i) != null
                                                && !request.getParameter(TEXTFIELD_UPNNAME + i).equals("")) {
                                            value = request.getParameter(TEXTFIELD_UPNNAME + i) + "@"
                                                    + request.getParameter(TEXTFIELD_SUBJECTALTNAME + i);
                                        }
                                    } else {
                                        value = request.getParameter(TEXTFIELD_SUBJECTALTNAME + i);
                                    }
                                }
                                if (value != null) {
                                    if (!value.equals("")) {
                                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                                DNFieldExtractor.TYPE_SUBJECTALTNAME) + value);
                                        if (subjectaltname.equals("")) {
                                            subjectaltname = value;
                                        } else {
                                            subjectaltname += ", " + value;
                                        }
                                    }
                                }
                                // We have to do almost the same again they may have select drop-downs instead of textfields
                                value = request.getParameter(SELECT_SUBJECTALTNAME + i);
                                if (value != null) {
                                    if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                                        if (request.getParameter(TEXTFIELD_UPNNAME + i) != null && !value.trim().equals("")) {
                                            value = request.getParameter(TEXTFIELD_UPNNAME + i) + "@" + value;
                                        }
                                    }
                                    if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
                                        String na = request.getParameter(TEXTFIELD_EMAIL + i);
                                        if ((na != null) && (!na.trim().equals("")) && !value.trim().equals("")) {
                                            value = na + "@" + value;
                                        }
                                    }
                                    if (!value.equals("")) {
                                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                                DNFieldExtractor.TYPE_SUBJECTALTNAME) + value);
                                        if (subjectaltname.equals("")) {
                                            subjectaltname = value;
                                        } else {
                                            subjectaltname += ", " + value;
                                        }
                                    }
                                }
                            }
        
                            newuser.setSubjectAltName(subjectaltname);
        
                            String subjectdirattr = "";
                            int numberofsubjectdirattrfields = profile.getSubjectDirAttrFieldOrderLength();
                            for (int i = 0; i < numberofsubjectdirattrfields; i++) {
                                fielddata = profile.getSubjectDirAttrFieldsInOrder(i);
                                value = request.getParameter(TEXTFIELD_SUBJECTDIRATTR + i);
                                if (value != null) {
                                    value = value.trim();
                                    if (!value.equals("")) {
                                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                                DNFieldExtractor.TYPE_SUBJECTDIRATTR) + value);
                                        if (subjectdirattr.equals("")) {
                                            subjectdirattr = value;
                                        } else {
                                            subjectdirattr += ", " + value;
                                        }
                                    }
                                }
                                value = request.getParameter(SELECT_SUBJECTDIRATTR + i);
                                if (value != null) {
                                    if (!value.equals("")) {
                                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                                DNFieldExtractor.TYPE_SUBJECTDIRATTR) + value);
                                        if (subjectdirattr.equals("")) {
                                            subjectdirattr = value;
                                        }  else {
                                            subjectdirattr += ", " + value;
                                        }
                                    }
                                }
                            }
                            newuser.setSubjectDirAttributes(subjectdirattr);
                            value = request.getParameter(SELECT_ALLOWEDREQUESTS);
                            if (value != null) {
                                ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, value);
                                newuser.setExtendedInformation(ei);
                            }
                            value = request.getParameter(CHECKBOX_KEYRECOVERABLE);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    newuser.setKeyRecoverable(true);
                                } else {
                                    newuser.setKeyRecoverable(false);
                                }
                            }
                            value = request.getParameter(CHECKBOX_SENDNOTIFICATION);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    newuser.setSendNotification(true);
                                } else {
                                    newuser.setSendNotification(false);
                                }
                            }
                            value = request.getParameter(CHECKBOX_PRINT);
                            if (value != null) {
                                if (value.equals(CHECKBOX_VALUE)) {
                                    newuser.setPrintUserData(true);
                                } else {
                                    newuser.setPrintUserData(false);
                                }
                            }
        
                            value = request.getParameter(SELECT_CERTIFICATEPROFILE);
                            newuser.setCertificateProfileId(Integer.parseInt(value));
                            value = request.getParameter(SELECT_CA);
                            newuser.setCAId(Integer.parseInt(value));
                            value = request.getParameter(SELECT_TOKEN);
                            int tokentype = Integer.parseInt(value);
                            newuser.setTokenType(Integer.parseInt(value));
                            
                            // Issuance revocation reason, what state a newly issued certificate will have
                            value = request.getParameter(SELECT_ISSUANCEREVOCATIONREASON);
                            // If it's not modifyable don't even try to modify it
                            if ((profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0))
                                    && (!profile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0))) {
                                value = profile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
                            }
                            if (value != null) {
                                ei.setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, value);
                                newuser.setExtendedInformation(ei);
                            }
                            value = request.getParameter(TEXTFIELD_STARTTIME);
                            if (value != null) {
                                value = value.trim();
                                if (value.length() > 0) {
                                    String storeValue = ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value);
                                    ei.setCustomData(EndEntityProfile.STARTTIME, storeValue);
                                    newuser.setExtendedInformation(ei);
                                }
                            }
                            value = request.getParameter(TEXTFIELD_ENDTIME);
                            if (value != null) {
                                value = value.trim();
                                if (value.length() > 0) {
                                    String storeValue = ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value);
                                    ei.setCustomData(EndEntityProfile.ENDTIME, storeValue);
                                    newuser.setExtendedInformation(ei);
                                }
                            }
                            value = request.getParameter(TEXTFIELD_CERTSERIALNUMBER);
                            if (value != null && value.length() > 0) {
                                ei.setCertificateSerialNumber(new BigInteger(value.trim(), 16));
                            } else {
                                ei.setCertificateSerialNumber(null);
                            }
                            value = request.getParameter(TEXTFIELD_NCANAME);
                            if (value != null && value.length() > 0) {
                                ei.setQCEtsiPSD2NcaName(value.trim());
                            } else {
                                ei.setQCEtsiPSD2NcaName(null);
                            }
                            value = request.getParameter(TEXTFIELD_NCAID);
                            if (value != null && value.length() > 0) {
                                ei.setQCEtsiPSD2NcaId(value.trim());
                            } else {
                                ei.setQCEtsiPSD2NcaId(null);
                            }
                            String[] pspRoleValues = request.getParameterValues(SELECT_PSD2_PSPROLE);
                            if (pspRoleValues != null && pspRoleValues.length > 0) {
                                final List<PSD2RoleOfPSPStatement> pspRoles = new ArrayList<>();
                                for (String role : pspRoleValues) {
                                    pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid(role), role));
                                }
                                ei.setQCEtsiPSD2RolesOfPSP(pspRoles);
                            } else {
                                ei.setQCEtsiPSD2RolesOfPSP(null);
                            }
                            value = StringUtils.trim(request.getParameter(TEXTFIELD_CABFORGANIZATIONIDENTIFIER));
                            if (profile.isCabfOrganizationIdentifierRequired() && StringUtils.isEmpty(value)) {
                                throw new ParameterException(ejbcawebbean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED"));
                            } else if (value != null && !value.matches(CabForumOrganizationIdentifier.VALIDATION_REGEX)) {
                                throw new ParameterException(ejbcawebbean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_BADFORMAT"));
                            }
                            ei.setCabfOrganizationIdentifier(value);
                            newuser.setExtendedInformation(ei);
                            value = request.getParameter(TEXTAREA_NC_PERMITTED);
                            if (value != null && !value.trim().isEmpty()) {
                                ei.setNameConstraintsPermitted(NameConstraint.parseNameConstraintsList(value));
                            } else {
                                ei.setNameConstraintsPermitted(null);
                            }
                            value = request.getParameter(TEXTAREA_NC_EXCLUDED);
                            if (value != null && !value.trim().isEmpty()) {
                                ei.setNameConstraintsExcluded(NameConstraint.parseNameConstraintsList(value));
                            } else {
                                ei.setNameConstraintsExcluded(null);
                            }
                            newuser.setExtendedInformation(ei);
        
                            if (request.getParameter(SELECT_CHANGE_STATUS) != null) {
                                int newstatus = Integer.parseInt(request.getParameter(SELECT_CHANGE_STATUS));
                                if (newstatus == EndEntityConstants.STATUS_NEW || newstatus == EndEntityConstants.STATUS_GENERATED
                                        || newstatus == EndEntityConstants.STATUS_HISTORICAL
                                        || newstatus == EndEntityConstants.STATUS_KEYRECOVERY)
                                    newuser.setStatus(newstatus);
                            }
                            String newUsername = request.getParameter(TEXTFIELD_NEWUSERNAME);
                            if (approvalmessage == null) {
                                try {
                                    // Send changes to database.
                                    rabean.changeUserData(newuser, newUsername);
                                    endentitysaved = true;
                                    username = newUsername;
                                } catch (org.cesecore.authorization.AuthorizationDeniedException e) {
                                    notauthorized = true;
                                } catch (org.ejbca.core.ejb.ra.NoSuchEndEntityException e) {
                                    approvalmessage = ejbcawebbean.getText("ENDENTITYDOESNTEXIST");
                                } catch (org.cesecore.certificates.ca.IllegalNameException e) {
                                    if (e.getMessage().equals("Username already taken")) {
                                        approvalmessage = ejbcawebbean.getText("ENDENTITYALREADYEXISTS");
                                    } else {
                                        throw e;
                                    }
                                } catch (org.ejbca.core.model.approval.ApprovalException e) {
                                    if (e.getErrorCode().equals(ErrorCode.VALIDATION_FAILED)){
                                        approvalmessage = ejbcawebbean.getText("DOMAINBLACKLISTVALIDATOR_VALIDATION_FAILED");
                                    }else{
                                        approvalmessage = ejbcawebbean.getText("THEREALREADYEXISTSAPPROVAL");
                                    }
                                } catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
                                    approvalmessage = ejbcawebbean.getText("REQHAVEBEENADDEDFORAPPR");
                                } catch (org.ejbca.core.EjbcaException e) {
                                    if (e.getErrorCode().equals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS)) {
                                        approvalmessage = ejbcawebbean.getText("SERIALNUMBERALREADYEXISTS");
                                    }
                                    if (e.getErrorCode().equals(ErrorCode.CA_NOT_EXISTS)) {
                                        approvalmessage = ejbcawebbean.getText("CADOESNTEXIST");
                                    }
                                    if (e.getErrorCode().equals(ErrorCode.FIELD_VALUE_NOT_VALID)) {
                                        approvalmessage = e.getMessage();
                                    }
                                    if (e.getErrorCode().equals(ErrorCode.NAMECONSTRAINT_VIOLATION)) {
                                        approvalmessage = e.getMessage();
                                    }
                                }
                                userdata = newuser;
                            }
                        }
                    }
                }
            }
        } catch (AuthorizationDeniedException e) {
        }
        nouserparameter = false;
    }

    String[] tokentexts = RAInterfaceBean.tokentexts;
    int[] tokenids = RAInterfaceBean.tokenids;
    String[] availabletokens = null;
    ArrayList<Integer>[] tokenissuers = null;

    if (userdata != null && profile != null) {
        availabletokens = profile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);
        usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && profile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);
    }

    Map<Integer, List<Integer>> availablecas = rabean.getCasAvailableToEndEntity(profileid);
    if (userdata!=null) {
        editendentitybean.setExtendedInformation(userdata.getExtendedInformation());
    }
    pageContext.setAttribute("profile", profile);

    int row = 0;
    int tabindex = 1;

    
}
    
}
