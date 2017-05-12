<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%
    response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
%>
<%@page  errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.ui.web.admin.rainterface.UserView,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, org.ejbca.ui.web.admin.rainterface.EndEntityProfileDataHandler, org.ejbca.core.model.ra.raadmin.EndEntityProfile, org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator, org.cesecore.certificates.endentity.EndEntityConstants,
                 javax.ejb.CreateException, java.io.Serializable, org.cesecore.authorization.AuthorizationDeniedException, org.cesecore.certificates.util.DNFieldExtractor, org.ejbca.core.model.ra.ExtendedInformationFields, org.cesecore.certificates.endentity.EndEntityInformation,
                 org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean, org.ejbca.core.model.hardtoken.HardTokenIssuer,org.ejbca.core.model.hardtoken.HardTokenIssuerInformation,java.math.BigInteger,org.ejbca.core.model.SecConst,org.cesecore.util.StringTools,
                 org.cesecore.certificates.util.DnComponents,org.apache.commons.lang.time.DateUtils,org.cesecore.certificates.endentity.ExtendedInformation,org.cesecore.certificates.crl.RevokedCertInfo,org.cesecore.ErrorCode,org.ejbca.core.model.authorization.AccessRulesConstants,
                 org.cesecore.certificates.certificate.certextensions.standard.NameConstraint, org.ejbca.util.HTMLTools, org.cesecore.util.CertTools" %>
<html> 
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="tokenbean" scope="session" class="org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean" />
<jsp:useBean id="editendentitybean" scope="page" class="org.ejbca.ui.web.admin.rainterface.EditEndEntityBean" />
<%!// Declarations

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
    static final String SELECT_HARDTOKENISSUER = "selecthardtokenissuer";
    static final String SELECT_CHANGE_STATUS = "selectchangestatus";
    static final String SELECT_CA = "selectca";
    static final String SELECT_ALLOWEDREQUESTS = "selectallowedrequests";
    static final String SELECT_ISSUANCEREVOCATIONREASON = "selectissuancerevocationreason";

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
    static final String HIDDEN_PROFILE = "hiddenprofile";%>
<%
    // Initialize environment.
    GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR,
    AccessRulesConstants.REGULAR_EDITENDENTITY);
    rabean.initialize(request, ejbcawebbean);
    if (globalconfiguration.getIssueHardwareTokens())
        tokenbean.initialize(request, ejbcawebbean);

    String THIS_FILENAME = globalconfiguration.getRaPath() + "/editendentity.jsp";
    String username = null;
    EndEntityProfile profile = null;
    UserView userdata = null;
    int profileid = EndEntityInformation.NO_ENDENTITYPROFILE;
    int[] fielddata = null;

    boolean userchanged = false;
    boolean nouserparameter = true;
    boolean notauthorized = true;
    boolean endentitysaved = false;
    boolean usehardtokenissuers = false;
    boolean usekeyrecovery = false;

    String approvalmessage = null;

    Map<Integer, String> caidtonamemap = ejbcawebbean.getInformationMemory().getCAIdToNameMap();

    RequestHelper.setDefaultCharacterEncoding(request);

    if (request.getParameter(USER_PARAMETER) != null) {
        username = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), "UTF-8");
        try {
    userdata = rabean.findUserForEdit(username);
    if (userdata != null) {
        notauthorized = false;
        profileid = userdata.getEndEntityProfileId();    
        profile = rabean.getEndEntityProfile(profileid);
        if (request.getParameter(ACTION) != null) {
            if (request.getParameter(ACTION).equals(ACTION_EDITUSER)) {
                if (request.getParameter(BUTTON_SAVE) != null) {
                    String newUsername = request.getParameter(TEXTFIELD_NEWUSERNAME);
                    if (!username.equals(newUsername)) {
                        // Rename the end entity
                        try {
                            if (!rabean.renameUser(username, newUsername)) {
                                approvalmessage = ejbcawebbean.getText("ENDENTITYDOESNTEXIST");
                            }
                        } catch (org.cesecore.authorization.AuthorizationDeniedException e) {
                        	notauthorized = true;
                        } catch (org.ejbca.core.ejb.ra.EndEntityExistsException e) {
                            approvalmessage = ejbcawebbean.getText("ENDENTITYALREADYEXISTS");
                        }
                        username = newUsername;
                    }
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
                    if (value == null || value.trim().equals("")) {
                        newuser.setEmail("");
                    } else {
                        value = value.trim();
                        if (!value.equals("")) {
                            String emaildomain = request.getParameter(TEXTFIELD_EMAILDOMAIN);
                            if (emaildomain != null) {
                                emaildomain = emaildomain.trim();
                                if (!emaildomain.equals("")) {
                                    newuser.setEmail(value + "@" + emaildomain);
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
                    int hardtokenissuer = SecConst.NO_HARDTOKENISSUER;
                    if (tokentype > SecConst.TOKEN_SOFT && request.getParameter(SELECT_HARDTOKENISSUER) != null) {
                        value = request.getParameter(SELECT_HARDTOKENISSUER);
                        hardtokenissuer = Integer.parseInt(value);
                    }
                    newuser.setHardTokenIssuerId(hardtokenissuer);
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
                    try {
                        // Send changes to database.
                        rabean.changeUserData(newuser);
                        endentitysaved = true;
                    } catch (org.ejbca.core.model.approval.ApprovalException e) {
                        approvalmessage = ejbcawebbean.getText("THEREALREADYEXISTSAPPROVAL");
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
        } catch (AuthorizationDeniedException e) {
        }
        nouserparameter = false;
    }

    String[] tokentexts = RAInterfaceBean.tokentexts;
    int[] tokenids = RAInterfaceBean.tokenids;
    String[] availabletokens = null;
    String[] availablehardtokenissuers = null;
    ArrayList<Integer>[] tokenissuers = null;

    if (userdata != null && profile != null) {
        if (globalconfiguration.getIssueHardwareTokens()) {
    TreeMap<String, Integer> hardtokenprofiles = ejbcawebbean.getInformationMemory().getHardTokenProfiles();

    tokentexts = new String[RAInterfaceBean.tokentexts.length + hardtokenprofiles.keySet().size()];
    tokenids = new int[tokentexts.length];
    for (int i = 0; i < RAInterfaceBean.tokentexts.length; i++) {
        tokentexts[i] = RAInterfaceBean.tokentexts[i];
        tokenids[i] = RAInterfaceBean.tokenids[i];
    }
    Iterator<String> iter = hardtokenprofiles.keySet().iterator();
    int index = 0;
    while (iter.hasNext()) {
        String name = (String) iter.next();
        tokentexts[index + RAInterfaceBean.tokentexts.length] = name;
        tokenids[index + RAInterfaceBean.tokentexts.length] = ((Integer) hardtokenprofiles.get(name)).intValue();
        index++;
    }
        }

        availabletokens = profile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);
        availablehardtokenissuers = profile.getValue(EndEntityProfile.AVAILTOKENISSUER, 0).split(EndEntityProfile.SPLITCHAR);

        usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && profile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);
        usehardtokenissuers = globalconfiguration.getIssueHardwareTokens() && profile.getUse(EndEntityProfile.AVAILTOKENISSUER, 0);
        if (usehardtokenissuers) {
    tokenissuers = new ArrayList[availabletokens.length];
    for (int i = 0; i < availabletokens.length; i++) {
        if (Integer.parseInt(availabletokens[i]) > SecConst.TOKEN_SOFT) {
            tokenissuers[i] = new ArrayList<Integer>();
            for (int j = 0; j < availablehardtokenissuers.length; j++) {
                HardTokenIssuerInformation issuerdata = tokenbean.getHardTokenIssuerInformation(Integer
                        .parseInt(availablehardtokenissuers[j]));
                if (issuerdata != null) {
                    Iterator<Integer> iter = issuerdata.getHardTokenIssuer().getAvailableHardTokenProfiles().iterator();
                    while (iter.hasNext()) {
                        if (Integer.parseInt(availabletokens[i]) == ((Integer) iter.next()).intValue())
                            tokenissuers[i].add(Integer.valueOf(availablehardtokenissuers[j]));
                    }
                }
            }
        }
    }
        }
    }

    Map<Integer, List<Integer>> availablecas = ejbcawebbean.getInformationMemory().getCasAvailableToEndEntity(profileid, AccessRulesConstants.EDIT_END_ENTITY);
    if (userdata!=null) {
        editendentitybean.setExtendedInformation(userdata.getExtendedInformation());
    }
    pageContext.setAttribute("profile", profile);

    int row = 0;
    int tabindex = 1;
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript">
   <!--

<% if(profile != null && userdata != null){ %>
      var TRUE  = "<%= EndEntityProfile.TRUE %>";
      var FALSE = "<%= EndEntityProfile.FALSE %>";


   <% if(usehardtokenissuers){ %>

       var TOKENID         = 0;
       var NUMBEROFISSUERS = 1;
       var ISSUERIDS       = 2;
       var ISSUERNAMES     = 3;

       var tokenissuers = new Array(<%=availabletokens.length%>);
       <% for(int i=0; i < availabletokens.length; i++){
            int numberofissuers = 0;
            if (Integer.parseInt(availabletokens[i]) > SecConst.TOKEN_SOFT) numberofissuers=tokenissuers[i].size();           
           %>
         tokenissuers[<%=i%>] = new Array(4);
         tokenissuers[<%=i%>][TOKENID] = <%= availabletokens[i] %>;
         tokenissuers[<%=i%>][NUMBEROFISSUERS] = <%= numberofissuers %>;
         tokenissuers[<%=i%>][ISSUERIDS] = new Array(<%= numberofissuers %>);
         tokenissuers[<%=i%>][ISSUERNAMES] = new Array(<%= numberofissuers %>);    
         <%  for(int j=0; j < numberofissuers; j++){ %>
         tokenissuers[<%=i%>][ISSUERIDS][<%=j%>]= <%= ((Integer) tokenissuers[i].get(j)).intValue() %>;
         tokenissuers[<%=i%>][ISSUERNAMES][<%=j%>]= "<%= tokenbean.getHardTokenIssuerAlias(((Integer) tokenissuers[i].get(j)).intValue())%>";
         <%  }
           } %>
       
function setAvailableHardTokenIssuers(){
    var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex;
    issuers   =  document.edituser.<%=SELECT_HARDTOKENISSUER%>;

    numofissuers = issuers.length;
    for( i=numofissuers-1; i >= 0; i-- ){
       issuers.options[i]=null;
    }    
    issuers.disabled=true;

    if( seltoken > -1){
      var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value;
      if(token > <%= SecConst.TOKEN_SOFT%>){
        issuers.disabled=false;
        var tokenindex = 0;  
        for( i=0; i < tokenissuers.length; i++){
          if(tokenissuers[i][TOKENID] == token)
            tokenindex = i;
        }
        for( i=0; i < tokenissuers[tokenindex][NUMBEROFISSUERS] ; i++){
          issuers.options[i]=new Option(tokenissuers[tokenindex][ISSUERNAMES][i],tokenissuers[tokenindex][ISSUERIDS][i]);
          if(tokenissuers[tokenindex][ISSUERIDS][i] == <%=userdata.getHardTokenIssuerId()%>)
            issuers.options.selectedIndex=i;
        }      
      }
    }
}

   <% }      
      if(usekeyrecovery){ %>
function isKeyRecoveryPossible(){
   var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex; 
   var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value;
   if(token == <%=SecConst.TOKEN_SOFT_BROWSERGEN %>){
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true;
   }else{
     <% if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0) && profile.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE) && userdata.getKeyRecoverable()){ %>
       document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true; 
     <% }else{ %>
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=false;
     <%} %>
     document.edituser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=<%= userdata.getKeyRecoverable() %>
     
   }
}

   <% } %>

  var certprofileids = new Array(<%= availablecas.keySet().size()%>);
  var CERTPROFID   = 0;
  var AVAILABLECAS = 1;

  var CANAME       = 0;
  var CAID         = 1;
<%
  Iterator<Integer> iter = availablecas.keySet().iterator();
  int x = 0;
  while(iter.hasNext()){ 
    Integer next = iter.next();
    List<Integer> nextcaset = availablecas.get(next);
  %>
    certprofileids[<%=x%>] = new Array(2);
    certprofileids[<%=x%>][CERTPROFID] = <%= next.intValue() %> ;
    certprofileids[<%=x%>][AVAILABLECAS] = new Array(<%= nextcaset.size() %>);
<% Iterator<Integer> iter2 = nextcaset.iterator();
   int y = 0;
   while(iter2.hasNext()){
     Integer nextca = iter2.next(); %>
    certprofileids[<%=x%>][AVAILABLECAS][<%=y%>] = new Array(2);
    certprofileids[<%=x%>][AVAILABLECAS][<%=y%>][CANAME] = "<%= HTMLTools.javascriptEscape(caidtonamemap.get(nextca)) %>";      
    certprofileids[<%=x%>][AVAILABLECAS][<%=y%>][CAID] = <%= nextca.intValue() %>;
  <% y++ ;
   }
   x++;
 } %>     

function fillCAField(){
   var selcertprof = document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex; 
   var certprofid = document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options[selcertprof].value; 
   var caselect   =  document.edituser.<%=SELECT_CA%>; 

   var numofcas = caselect.length;
   for( i=numofcas-1; i >= 0; i-- ){
       caselect.options[i]=null;
    }   

    if( selcertprof > -1){
      for( i=0; i < certprofileids.length; i ++){
        if(certprofileids[i][CERTPROFID] == certprofid){
          for( j=0; j < certprofileids[i][AVAILABLECAS].length; j++ ){
            caselect.options[j]=new Option(certprofileids[i][AVAILABLECAS][j][CANAME],
                                           certprofileids[i][AVAILABLECAS][j][CAID]);    
            if(certprofileids[i][AVAILABLECAS][j][CAID] == "<%= userdata.getCAId() %>")
              caselect.options.selectedIndex=j;
          }
        }
      }
    }
}


function checkallfields(){
    var illegalfields = 0;
 <%    
     for(int i=0; i < profile.getSubjectDNFieldOrderLength(); i++){
         fielddata = profile.getSubjectDNFieldsInOrder(i);
         if(!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
           if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_SUBJECTDN+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
    <%     if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){%>
    if((document.edituser.<%= TEXTFIELD_SUBJECTDN+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
      illegalfields++;
    } 
    <%     }
          }
         }        
         else{ %>
             if(document.edituser.<%= CHECKBOX_SUBJECTDN+i %>)
             {
                 document.edituser.<%= CHECKBOX_SUBJECTDN+i %>.disabled = false;          
             }
     <%  }
       }
       for(int i=0; i < profile.getSubjectAltNameFieldOrderLength(); i++){
         fielddata = profile.getSubjectAltNameFieldsInOrder(i);
         int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
         if (EndEntityProfile.isFieldImplemented(fieldtype)) {
           if(!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
             if(EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {%>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_UPNNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
    <%         if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>    
              if((document.edituser.<%= TEXTFIELD_UPNNAME+i %>.value == "")){ 
                alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
                illegalfields++;
              } 
        <%     }
             }  
             if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){
               if(EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.IPADDRESS)) { %>
    if(!checkfieldforipaddess("document.edituser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYNUMBERALSANDDOTS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
           <%  }else{ %>
    if(!checkfieldforlegaldnchars("document.edituser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
    <%    if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if((document.edituser.<%= TEXTFIELD_SUBJECTALTNAME+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
      illegalfields++;
    } 
    <%        }
             }
            }
           }else{ %>
             if(document.edituser.<%= CHECKBOX_SUBJECTALTNAME+i %>)
             {
                 document.edituser.<%= CHECKBOX_SUBJECTALTNAME+i %>.disabled = false;          
             }
     <%    }
         }                   
       }
       
       if(profile.getUse(EndEntityProfile.MAXFAILEDLOGINS,0)) { %>
  			if(document.edituser.<%=RADIO_MAXFAILEDLOGINS %>[0].checked == true) {
	  			var maxFailedLogins = document.edituser.<%=TEXTFIELD_MAXFAILEDLOGINS %>.value; 
	      		if(maxFailedLogins != parseInt(maxFailedLogins) || maxFailedLogins < -1) {
	      			alert("<%= ejbcawebbean.getText("REQUIREDMAXFAILEDLOGINS", true) %>");
	      			illegalfields++;
	      		}
	  		}
	<% }
       
       if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
    if(!checkfieldforlegalemailcharswithoutat("document.edituser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;

    <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.edituser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL", true) %>");
      illegalfields++;
    } 
    <%    }

          if(profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(!checkfieldforlegalemailcharswithoutat("document.edituser.<%=TEXTFIELD_EMAILDOMAIN%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;
          
      <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.edituser.<%= TEXTFIELD_EMAILDOMAIN %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL", true) %>");
      illegalfields++;
    } 
    <%    }
        }
      }
       
       if(profile.getUse(EndEntityProfile.CARDNUMBER,0) ){%>
       if(!checkfieldfordecimalnumbers("document.edituser.<%=TEXTFIELD_CARDNUMBER%>", "<%= ejbcawebbean.getText("CARDNUMBER_MUSTBE", true) %>"))       
         illegalfields++;
     <% }


       if(profile.getUse(EndEntityProfile.PASSWORD,0)){
         if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>  
    if(document.edituser.<%= TEXTFIELD_PASSWORD %>.value != document.edituser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH", true) %>");
      illegalfields++;
    } 
    <%   }else{ %>
    if(document.edituser.<%=SELECT_PASSWORD%>.options.selectedIndex != document.edituser.<%=SELECT_CONFIRMPASSWORD%>.options.selectedIndex ){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH", true) %>");
      illegalfields++; 
    }
<%        }   
     } %>
    if(document.edituser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATEPROFILEMUST", true) %>");
      illegalfields++;
    }
    if(document.edituser.<%=SELECT_CA%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CAMUST", true) %>");
      illegalfields++;
    }
    if(document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("TOKENMUST", true) %>");
      illegalfields++;
    }

    
    <%  if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0) && profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(document.edituser.<%=CHECKBOX_SENDNOTIFICATION %>.checked && (document.edituser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("NOTIFICATIONADDRESSMUSTBE", true) %>");
      illegalfields++;
    } 
    <% } %>

   var selstatus = document.edituser.<%=SELECT_CHANGE_STATUS%>.options.selectedIndex;
   var status = document.edituser.<%=SELECT_CHANGE_STATUS%>.options[selstatus].value;
   var seltoken = document.edituser.<%=SELECT_TOKEN%>.options.selectedIndex;
   var token = document.edituser.<%=SELECT_TOKEN%>.options[seltoken].value

  <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){ 
       if(profile.isModifyable(EndEntityProfile.PASSWORD,0)){%>  
   if((status == <%= EndEntityConstants.STATUS_NEW%> || status == <%= EndEntityConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= TEXTFIELD_PASSWORD %>.value == ""){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD", true) %>");
      illegalfields++;
   }

  <%   } else { %>
   if((status == <%= EndEntityConstants.STATUS_NEW%> || status == <%= EndEntityConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= TEXTFIELD_PASSWORD %>.options.selectedIndex == -1){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD", true) %>");
      illegalfields++;
   }
 <%   }
    }else{%>
   if((status == <%= EndEntityConstants.STATUS_NEW%> || status == <%= EndEntityConstants.STATUS_KEYRECOVERY%>) && status != <%= userdata.getStatus() %> && document.edituser.<%= CHECKBOX_REGENERATEPASSWD %>.checked == false && token <= <%= SecConst.TOKEN_SOFT%> ){
      alert("<%= ejbcawebbean.getText("PASSWORDMUSTBEREGEN", true) %>");
      illegalfields++;
   }
 <% } %>
   if(status != <%= EndEntityConstants.STATUS_NEW%> && status != <%= EndEntityConstants.STATUS_KEYRECOVERY%> && status != <%= EndEntityConstants.STATUS_GENERATED%> && status != <%= EndEntityConstants.STATUS_HISTORICAL%>){
      alert("<%= ejbcawebbean.getText("ONLYSTATUSCANBESELECTED", true) %>");
      illegalfields++;
    }
    if(illegalfields == 0){
      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
      document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){%> 
      document.edituser.<%= CHECKBOX_KEYRECOVERABLE %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){%> 
      document.edituser.<%= CHECKBOX_SENDNOTIFICATION %>.disabled = false;
      <% } if(profile.getUsePrinting()){%> 
      document.edituser.<%= CHECKBOX_PRINT %>.disabled = false;
      <% }%>
    }

     return illegalfields == 0;  
}
<% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
function checkUseInBatch(){
  var returnval = false;
  <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){  %>   
  if(document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked){
  <% if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ %>
    returnval = document.edituser.<%= SELECT_PASSWORD %>.options.selectedIndex == -1;
  <% }else { %>
    returnval = document.edituser.<%= TEXTFIELD_PASSWORD %>.value == "";
  <% } %> 

  }

  if(returnval){
    alert("<%= ejbcawebbean.getText("PASSWORDREQUIRED", true) %>");    
    document.edituser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.checked  = false;  
  }

  <% } %>

  return !returnval;
}
<% } 
  }
 %>

 function maxFailedLoginsUnlimited() {
	document.edituser.<%= TEXTFIELD_MAXFAILEDLOGINS %>.disabled = true;
 }

 function maxFailedLoginsSpecified() {
	document.edituser.<%= TEXTFIELD_MAXFAILEDLOGINS %>.disabled = false;
 }   

   -->
  </script>
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body class="popup" id="editendentity"
      onload='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                 if(usekeyrecovery) out.write(" isKeyRecoveryPossible(); ");%>
                 fillCAField();'>

  <h2><%= ejbcawebbean.getText("EDITENDENTITYTITLE") %></h2>

 <%if(nouserparameter){%>
  <div class="message alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYUSERNAME") %></div> 
  <% } 
     else{
       if(userdata == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("ENDENTITYDOESNTEXIST") %></div> 
    <% }
       else{
         if(notauthorized || profile == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOEDIT") %></div> 
    <%   }
         else{ 
             if(approvalmessage != null){ %>
        	    <div class="message alert"><c:out value="<%= approvalmessage %>"/></div>
        	 <% }         	 
           if(endentitysaved){%>
  <div class="message info"><%=ejbcawebbean.getText("ENDENTITYSAVED") %></div> 
    <%     } %>


  <form name="edituser" action="<%= THIS_FILENAME %>" method="post">   
    <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
	<input type="hidden" name="<%= ACTION %>" value="<%=ACTION_EDITUSER %>" />   
	<input type="hidden" name="<%= HIDDEN_PROFILE %>" value="<%=profileid %>" />    
	<input type="hidden" name="<%= USER_PARAMETER %>" value="<c:out value="<%= username %>"/>" />

	<table class="edit" border="0" cellpadding="0" cellspacing="2" width="100%">

	<tr id="Row<%=(row)%2%>">
	  <td align="right"><%= ejbcawebbean.getText("ENDENTITYPROFILE")%></td>  
	  <td><% if(rabean.getEndEntityProfileName(profileid)==null) {
				out.write(ejbcawebbean.getText("NOENDENTITYPROFILEDEFINED"));
			 } else {%>
			    <c:out value="<%= rabean.getEndEntityProfileName(profileid) %>"/>
		     <%}%>
		</td>
	  <td><%= ejbcawebbean.getText("REQUIRED") %></td>
	</tr>


    <!-- ---------- Status -------------------- -->

    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("STATUS") %>
      </td>
      <td > 
        <select name="<%=SELECT_CHANGE_STATUS %>" tabindex="<%=tabindex++%>" >
         <%if(userdata.getStatus()== EndEntityConstants.STATUS_KEYRECOVERY){ %>
           <option selected value='<%= EndEntityConstants.STATUS_KEYRECOVERY %>'><%= ejbcawebbean.getText("STATUSKEYRECOVERY") %></option>
         <% }else{ %>  
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_NEW) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_NEW %>'><%= ejbcawebbean.getText("STATUSNEW") %></option>
         <% } %>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_FAILED) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_FAILED %>'><%= ejbcawebbean.getText("STATUSFAILED") %></option>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_INITIALIZED) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_INITIALIZED %>'><%= ejbcawebbean.getText("STATUSINITIALIZED") %></option>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_INPROCESS) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_INPROCESS %>'><%= ejbcawebbean.getText("STATUSINPROCESS") %></option>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_GENERATED) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_GENERATED %>'><%= ejbcawebbean.getText("STATUSGENERATED") %></option>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_REVOKED) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_REVOKED %>'><%= ejbcawebbean.getText("STATUSREVOKED") %></option>
         <option <%if(userdata.getStatus()== EndEntityConstants.STATUS_HISTORICAL) out.write(" selected ");%> value='<%= EndEntityConstants.STATUS_HISTORICAL %>'><%= ejbcawebbean.getText("STATUSHISTORICAL") %></option>
        </select>
        &nbsp;&nbsp;&nbsp;
        <input style="font-weight:bold;" type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>" tabindex="<%=tabindex++%>" onClick='return checkallfields()' />
      </td>
      <td>&nbsp;</td>
    </tr>


    <!-- ---------- Main -------------------- -->

      <tr id="Row<%=(row++)%2%>" class="title">
	<td align="right"><strong><%= ejbcawebbean.getText("USERNAME") %></strong></td> 
	<td>
		<strong>
			<input type="text" name="<%= TEXTFIELD_NEWUSERNAME %>" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<c:out value="<%= userdata.getUsername() %>"/>'>
        </strong>
    </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_USERNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" CHECKED></td>
      </tr>

          <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){ %>
      <tr id="Row<%=(row)%2%>">
	<td align="right"><%= ejbcawebbean.getText("PASSWORDORENROLLMENTCODE") %></td>
        <td>   
             <%
               if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_PASSWORD %>" size="1" tabindex="<%=tabindex++%>">
               <% if( profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<c:out value="<%= profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>"/>' >
               <c:out value="<%= profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>"/> 
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" autocomplete="off" name="<%= TEXTFIELD_PASSWORD %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value=''>
           <% } %>
 
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.PASSWORD,0)) out.write(" CHECKED "); %>></td>
      </tr>
       <% }else{ %>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("PASSWORD") %></td>
        <td>              
         <input type="checkbox" name="<%= CHECKBOX_REGENERATEPASSWD %>" value="<%= CHECKBOX_VALUE %>"  tabindex="<%=tabindex++%>"
         id="<%=CHECKBOX_REGENERATEPASSWD%>">
         <label for="<%=CHECKBOX_REGENERATEPASSWD%>"><c:out value="<%= ejbcawebbean.getText(\"REGENERATENEWPASSWORD\") %>" /></label>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.PASSWORD,0)) out.write(" CHECKED "); %>></td>
      </tr>
      <% } %>
      <% if(profile.getUse(EndEntityProfile.PASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("CONFIRMPASSWORD") %></td>
        <td>
          <%   if(!profile.isModifyable(EndEntityProfile.PASSWORD,0)){ 
               %>
           <select name="<%= SELECT_CONFIRMPASSWORD %>" size="1" tabindex="<%=tabindex++%>">
               <% if( profile.getValue(EndEntityProfile.PASSWORD,0) != null){ %>
             <option value='<c:out value="<%= profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>"/>' >
               <c:out value="<%= profile.getValue(EndEntityProfile.PASSWORD,0).trim() %>"/> 
             </option>                
               <%   
                  }
                %>
           </select>
           <% }else{ %> 
             <input type="password" autocomplete="off" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value=''>
           <% } %>
        </td>
	<td>&nbsp;</td> 
      </tr>
      <% } %>

      <tr id="Row<%=(row)%2%>">
		<td align="right"><%= ejbcawebbean.getText("MAXFAILEDLOGINATTEMPTS") %></td>
       	<td>
       		<%
	   			int maxLoginAttempts = ExtendedInformation.DEFAULT_MAXLOGINATTEMPTS; // Default value in ExtendedInformation
   				ExtendedInformation maxei = userdata.getExtendedInformation();
   				if (maxei != null) {
   					maxLoginAttempts = maxei.getMaxLoginAttempts();
   				}
       		%>   
             <input type="radio" name="<%= RADIO_MAXFAILEDLOGINS %>" value="<%= RADIO_MAXFAILEDLOGINS_VAL_SPECIFIED %>" onclick="maxFailedLoginsSpecified()" <% if(maxLoginAttempts != -1) { out.write("checked"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write("readonly"); } %>>
             <input type="text" name="<%= TEXTFIELD_MAXFAILEDLOGINS %>" size="5" maxlength="255" tabindex="<%=tabindex++%>" value='<% if(maxLoginAttempts != -1) { out.write(""+maxLoginAttempts); } %>' <% if(maxLoginAttempts == -1) { out.write("disabled"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write(" readonly"); } %> title="<%= ejbcawebbean.getText("FORMAT_INTEGER") %>">
             
             <input type="radio" name="<%= RADIO_MAXFAILEDLOGINS %>" value="<%= RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED %>" onclick="maxFailedLoginsUnlimited()" <% if(maxLoginAttempts == -1) { out.write("checked"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write("readonly"); } %>
                 id="<%=RADIO_MAXFAILEDLOGINS%>unlimited">
             <label for="<%=RADIO_MAXFAILEDLOGINS%>unlimited"><%= ejbcawebbean.getText("UNLIMITED") %></label>
      	</td>
		<td>&nbsp;</td>
      </tr>
      <tr id="Row<%=(row++)%2%>">
		<td align="right"><%= ejbcawebbean.getText("REMAININGLOGINATTEMPTS") %></td>
       	<td>   
             <input type="text" name="_remainingloginattempts" size="5" maxlength="255" tabindex="<%=tabindex++%>" value='<% if((userdata.getExtendedInformation()!=null) && (userdata.getExtendedInformation().getRemainingLoginAttempts() != -1)) out.write(""+userdata.getExtendedInformation().getRemainingLoginAttempts()); %>' readonly>
             <input type="checkbox" name="<%= CHECKBOX_RESETLOGINATTEMPTS %>" value="<%= CHECKBOX_VALUE %>"
                 id="<%=CHECKBOX_RESETLOGINATTEMPTS%>">
             <label for="<%=CHECKBOX_RESETLOGINATTEMPTS%>"><%= ejbcawebbean.getText("RESETLOGINATTEMPTS") %></label>
      	</td>
		<td>&nbsp;</td>
      </tr>

      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><%= ejbcawebbean.getText("USEINBATCH") %></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>"  onchange='return checkUseInBatch()' tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0) || userdata.getClearTextPassword())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>
             id="<%=CHECKBOX_CLEARTEXTPASSWORD%>">
         <label for="<%=CHECKBOX_CLEARTEXTPASSWORD%>"><c:out value="<%= ejbcawebbean.getText(\"USE\") %>" /></label>
        </td>
	<td>&nbsp;</td> 
      </tr>
      <% } %>
      
      <% 
      	  if(profile.getUse(EndEntityProfile.EMAIL,0)){ 
           String emailname = "";
           String emaildomain = "";
           if(userdata.getEmail() != null && !userdata.getEmail().equals("")){
             emailname   = userdata.getEmail().substring(0,userdata.getEmail().indexOf('@'));
             emaildomain = userdata.getEmail().substring(userdata.getEmail().indexOf('@')+1);
           }
	  %>
       <tr id="Row<%=(row++)%2%>">	 
	 <td align="right"><%= ejbcawebbean.getText("EMAIL") %></td>
	 <td>      
           <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="15" maxlength="255" tabindex="<%=tabindex++%>" value="<c:out value="<%= emailname %>"/>" title="<%= ejbcawebbean.getText("FORMAT_DOMAINNAME") %>"> @
          <% if(!profile.isModifyable(EndEntityProfile.EMAIL,0)){ 
                 String[] options = profile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
               %>
              <% if( options == null ){ %>
                   <input type="hidden" name="<%= SELECT_EMAILDOMAIN %>" value="" />
                   &nbsp;
              <% }else{ %> 
                <% if( options.length == 1 ){ %>
                   <input type="hidden" name="<%= SELECT_EMAILDOMAIN %>" value="<c:out value="<%= options[0].trim() %>"/>" />
                   <strong><c:out value="<%= options[0].trim() %>"/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_EMAILDOMAIN %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int i=0;i < options.length;i++){ %>
                       <option value="<c:out value="<%= options[i].trim() %>"/>" <% if(emaildomain.equals(options[i])) out.write(" selected "); %>>
                          <c:out value="<%= options[i].trim() %>"/>
                       </option>                
                     <% } %>
                   </select>
                <% } %>
              <% } %>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_EMAILDOMAIN %>" size="20" maxlength="255" tabindex="<%=tabindex++%>"  value="<c:out value="<%= emaildomain %>"/>">
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.EMAIL,0)) out.write(" CHECKED "); %>></td>
       </tr>
       <% }%>


    <!-- ---------- Subject DN -------------------- -->

      <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right"><strong><%= ejbcawebbean.getText("CERT_SUBJECTDN") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
       <% int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
          for(int i=0; i < numberofsubjectdnfields; i++){
            fielddata = profile.getSubjectDNFieldsInOrder(i);  %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td>      
          <% 
             if( !EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)){  
                if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
               %>
              <% if( options == null ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDN + i %>" value="" />
                   &nbsp;
              <% }else{ %> 
                <% if( options.length == 1 ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDN + i %>" value="<c:out value="<%= options[0].trim() %>"/>" />
                   <strong class="attribute"><c:out value="<%= options[0].trim() %>"/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_SUBJECTDN + i %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int j=0;j < options.length;j++){ %>
                       <option value="<c:out value="<%= options[j].trim() %>"/>" <% if(userdata.getSubjectDNField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals(options[j].trim())) out.write(" selected "); %>> 
                         <c:out value="<%= options[j].trim() %>"/>
                       </option>                
                     <% } %>
                   </select>
                <% } %>
              <% } %>
           <% }else{
             final Map<String,Serializable> validation = profile.getValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
             final String regex = (validation != null ? (String)validation.get(RegexFieldValidator.class.getName()) : null);
             %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTDN + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>"
                    value="<c:out value="<%= userdata.getSubjectDNField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]) %>"/>"
                    <% if (regex != null) { %>pattern="<c:out value='<%=regex%>'/>" title="Must match format specified in profile. / Technical detail - the regex is <c:out value='<%=regex%>'/>"<% } %> />
           <% }
            }
            else{ %>
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTDN + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(!userdata.getSubjectDNField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals("") || profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
              id="<%=CHECKBOX_SUBJECTDN + i%>">
          <label for="<%=CHECKBOX_SUBJECTDN + i%>"><%= ejbcawebbean.getText("USESEMAILFIELDDATA") %></label>
         <% } %>  
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTDN + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <% } %>


    <!-- ---------- Other subject attributes -------------------- -->

     <% if (  profile.getSubjectAltNameFieldOrderLength() > 0
           || profile.getSubjectDirAttrFieldOrderLength() > 0
           ) {
      %> 
      <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right"><strong><%= ejbcawebbean.getText("OTHERSUBJECTATTR") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
     <% } %>

     <% int numberofsubjectaltnamefields = profile.getSubjectAltNameFieldOrderLength();
        if(numberofsubjectaltnamefields > 0 ){
      %> 
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><strong><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTALTNAME") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
      <% } %>
       <% 
         for(int i=0; i < numberofsubjectaltnamefields; i++){
            fielddata = profile.getSubjectAltNameFieldsInOrder(i);
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(EndEntityProfile.isFieldImplemented(fieldtype)) {%>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td>      
          <%
             // If we have checked the checkbox "Use entity e-mail field" in the end entity profile
             boolean rfc822useemailfield = EndEntityProfile.isFieldOfType(fieldtype, DnComponents.RFC822NAME) && profile.getUse(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER]);
             if( !rfc822useemailfield ){
               if ( (EndEntityProfile.isFieldOfType(fieldtype, DnComponents.UPN)) || (EndEntityProfile.isFieldOfType(fieldtype, DnComponents.RFC822NAME)) ) { 
                 String name = "";
                 String domain = "";            
                 String fullname = userdata.getSubjectAltNameField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]);
                 if(fullname != null && !fullname.equals("")){
                   // if we have an @ sign, we will assume it is name@domain, if we have no @ sign, 
                   // we will assume that the name has not been entered yet.
                   if (fullname.contains("@")) {
                     name   = fullname.substring(0,fullname.indexOf('@'));
                     domain = fullname.substring(fullname.indexOf('@')+1);
                   } else {
                	   domain = fullname;
                   }
                 } 
                 boolean modifyable = profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                 String profilevalue = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                 // if the field is not modifyable, and the options contains an @ sign, we assume that the complete field is actually locked down
                 // and we should not attempt to split it in name@domain parts
                 if (!(!modifyable && profilevalue.contains("@"))) {
                   if (EndEntityProfile.isFieldOfType(fieldtype, DnComponents.UPN)) { %> 
                   <input type="text" name="<%= TEXTFIELD_UPNNAME +i%>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value="<c:out value="<%= name %>"/>"> @
          <%       } else { %>       
                   <input type="text" name="<%= TEXTFIELD_EMAIL +i%>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value="<c:out value="<%= name %>"/>"> @
          <%       }
                 }
                 // Only display the domain part if we have not completely locked down the email address
                 if (!modifyable) { 
                     String[] options = profilevalue.split(EndEntityProfile.SPLITCHAR); %>
	              <% if( options == null || options.length <= 0 ){ %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="" />
	                   &nbsp;
	              <% }else{ %> 
	                <% if( options.length == 1 ){ %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="<c:out value="<%= options[0].trim() %>"/>" />
	                   <strong><c:out value="<%= options[0].trim() %>"/></strong>
	                <% }else{ %> 
	                   <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
	                    <% for(int j=0;j < options.length;j++){ %>
                           <option value="<c:out value="<%= options[j].trim() %>"/>" <%  if(fullname.equals(options[j].trim()) || domain.equals(options[j].trim())) out.write(" selected "); %>> 
                             <c:out value="<%= options[j].trim() %>"/>
                           </option>                
	                    <% } %>
	                   </select>
	                <% } %>
	              <% } %>
             <%  }else{ %> 
                 <input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value="<c:out value="<%= domain %>"/>" title="<%= ejbcawebbean.getText("FORMAT_DOMAINNAME") %>">
             <% }
              }else{    
               if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR); %>
	            <%  if( options == null || options.length <= 0 ) { %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="" />
	                   &nbsp;
	            <%  } else { %> 
	              <%  if( options.length == 1 ) { %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="<c:out value="<%= options[0].trim() %>"/>" />
	                   <strong><c:out value="<%= options[0].trim() %>"/></strong>
	              <%  } else { %> 
	                   <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
	                   <%  for(int j=0;j < options.length;j++) { %>
                           <option value="<c:out value="<%= options[j].trim() %>"/>" <%  if(userdata.getSubjectAltNameField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals(options[j].trim())) out.write(" selected "); %>> 
                              <c:out value="<%= options[j].trim() %>"/>
                           </option>                
	                   <%  } %>
	                   </select>
	              <%  } %>
	            <%  } %>
           <% }else{
             final Map<String,Serializable> validation = profile.getValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
             final String regex = (validation != null ? (String)validation.get(RegexFieldValidator.class.getName()) : null); %>
             <input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="40" maxlength="255" tabindex="<%=tabindex++%>"
                    value="<c:out value="<%= userdata.getSubjectAltNameField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]) %>"/>"
                    <% if (regex != null) { %>pattern="<c:out value='<%=regex%>'/>" title="Must match format specified in profile. / Technical detail - the regex is <c:out value='<%=regex%>'/>"<% } %> />
           <% }
            }
            }else{ %>
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTALTNAME + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" 
          <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" disabled='true' ");     
             if(!userdata.getSubjectAltNameField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals("") || profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>
              id="<%=CHECKBOX_SUBJECTALTNAME + i%>">
           <label for="<%=CHECKBOX_SUBJECTALTNAME + i%>"><%= ejbcawebbean.getText("USESEMAILFIELDDATA") %></label>
         <% } %>  
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%   }
        } %>

     <%
        int numberofsubjectdirattrfields = profile.getSubjectDirAttrFieldOrderLength();
        if(numberofsubjectdirattrfields > 0){
     %> 
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><strong><%= ejbcawebbean.getText("EXT_ABBR_SUBJECTDIRATTRS") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
       <% }
          for(int i=0; i < numberofsubjectdirattrfields; i++){
            fielddata = profile.getSubjectDirAttrFieldsInOrder(i);  
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
			{ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %></td>
	 <td>      
          <%
               if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
                %>
              <% if( options == null ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDIRATTR + i %>" value="" />
                   &nbsp;
              <% }else{ %> 
                <% if( options.length == 1 ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDIRATTR + i %>" value="<c:out value="<%= options[0].trim() %>"/>" />
                   <strong><c:out value="<%= options[0].trim() %>"/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_SUBJECTDIRATTR + i %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int j=0;j < options.length;j++){ %>
                       <option value="<c:out value="<%= options[j].trim() %>"/>" <%  if(userdata.getSubjectDirAttributeField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]).equals(options[j].trim())) out.write(" selected "); %>> 
                         <c:out value="<%= options[j].trim() %>"/>
                       </option>                
                     <% } %>
                   </select>
                <% } %>
              <% } %>
           <% }else{ %>
             <input type="text" name="<%= TEXTFIELD_SUBJECTDIRATTR + i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value="<c:out value="<%= userdata.getSubjectDirAttributeField(DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),fielddata[EndEntityProfile.NUMBER]) %>"/>">
           <% } 
           %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTDIRATTR + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%  } %>
	<%	} %>


    <!-- ---------- Main certificate data -------------------- -->

      <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right"><strong><%= ejbcawebbean.getText("MAINCERTIFICATEDATA") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>

       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("CERTIFICATEPROFILE") %></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATEPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange='fillCAField()'>
         <%
           String[] availablecertprofiles = profile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
           if( availablecertprofiles != null){
             for(int i =0; i< availablecertprofiles.length;i++){
         %>
         <option value='<c:out value="<%= availablecertprofiles[i] %>"/>' <% if(userdata.getCertificateProfileId() ==Integer.parseInt(availablecertprofiles[i])) out.write(" selected "); %> >
            <c:out value="<%= rabean.getCertificateProfileName(Integer.parseInt(availablecertprofiles[i])) %>"/>
         </option>
         <%
             }
           }
         %>
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="disabled" CHECKED></td>
       </tr>

       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("CA") %></td>
	 <td>
         <select name="<%= SELECT_CA %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="disabled" CHECKED></td>
       </tr>

       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("TOKEN") %></td>
	 <td>
         <select name="<%= SELECT_TOKEN %>" size="1" tabindex="<%=tabindex++%>" onchange='<% if(usehardtokenissuers) out.write("setAvailableHardTokenIssuers();");
                                                                                             if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>'>
         <%
           if( availabletokens != null){
             for(int i =0; i < availabletokens.length;i++){
         %>
         <option value='<%=availabletokens[i]%>' <% if(userdata.getTokenType() ==Integer.parseInt(availabletokens[i])) out.write(" selected "); %> >
            <% for(int j=0; j < tokentexts.length; j++){
                 if( tokenids[j] == Integer.parseInt(availabletokens[i])){ 
                   if( tokenids[j] > SecConst.TOKEN_SOFT)
                     out.write(tokentexts[j]);
                   else
                     out.write(ejbcawebbean.getText(tokentexts[j]));
                 }
               } %>
         </option>
         <%
             }
           }
         %>
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="disabled" CHECKED></td>
       </tr>

       <% if(usehardtokenissuers){ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><%= ejbcawebbean.getText("HARDTOKENISSUER") %></td>
	 <td>
         <select name="<%= SELECT_HARDTOKENISSUER %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td>&nbsp;</td>
       </tr>
       <% } %>


    <!-- ---------- Other certificate data -------------------- -->

	<%	if ( profile.getUse(EndEntityProfile.CERTSERIALNR, 0)
		  || profile.getUse(EndEntityProfile.STARTTIME, 0)
		  || profile.getUse(EndEntityProfile.ENDTIME, 0)
		  || profile.getUse(EndEntityProfile.CARDNUMBER, 0)
		  || profile.getUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0)
          || profile.getUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0)
		   ) { %>
      <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right"><strong><%= ejbcawebbean.getText("OTHERCERTIFICATEDATA") %></strong></td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
       </tr>
	<%	} %> 

	<% if( profile.getUse(EndEntityProfile.CERTSERIALNR, 0) ) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("CERT_SERIALNUMBER_HEXA") %>
				(<%= ejbcawebbean.getText("EXAMPLE").toLowerCase() %> : 1234567890ABCDEF)
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_CERTSERIALNUMBER %>" size="20" maxlength="40" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_HEXA") %>" class="hexa"
					<%	final ExtendedInformation ei = userdata.getExtendedInformation();
						final BigInteger oldNr = ei!=null ? ei.certificateSerialNumber() : null;
						final String certSerialNr = oldNr!=null ? oldNr.toString(16) : "";
						%>
					value="<c:out value="<%= certSerialNr %>"/>"
					/>
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_CERTSERIALNUMBER %>" value="<%= CHECKBOX_VALUE %>" disabled="disabled" />
				<%	if ( profile.isRequired(EndEntityProfile.CERTSERIALNR, 0) ) {
						out.write(" CHECKED ");
					} %>
			</td>
		</tr>
	<% } %> 

	<%	if( profile.getUse(EndEntityProfile.STARTTIME, 0) ) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("TIMEOFSTART") %>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_STARTTIME %>" size="25" maxlength="40" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_ISO8601") %> <%= ejbcawebbean.getText("OR") %> (<%= ejbcawebbean.getText("DAYS").toLowerCase() %>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)"
					<%	ExtendedInformation ei = userdata.getExtendedInformation();
						String startTime = null;
						if ( ei != null ) {
							startTime = ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
							if ( startTime == null ) {
								startTime = "";
							} 
							if ( !startTime.trim().equals("") ) {
								startTime = ejbcawebbean.getISO8601FromImpliedUTCOrRelative(startTime);
							}
						}
                    %>
					value="<%= startTime %>"
					<%	if ( !profile.isModifyable(EndEntityProfile.STARTTIME, 0) ) { %>
					readonly="true"
					<%	} %>
					/>
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_STARTTIME %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled"
				<%	if ( profile.isRequired(EndEntityProfile.STARTTIME, 0) ) {
						out.write(" CHECKED ");
					} %>
				/>
			</td>
		</tr>
	<%	} %>

	<%	if( profile.getUse(EndEntityProfile.ENDTIME, 0) ) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("TIMEOFEND") %>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_ENDTIME %>" size="25" maxlength="40" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_ISO8601") %> <%= ejbcawebbean.getText("OR") %> (<%= ejbcawebbean.getText("DAYS").toLowerCase() %>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)"
					<%	ExtendedInformation ei = userdata.getExtendedInformation();
						String endTime = null;
						if ( ei != null ) {
							endTime = ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
						}
						if ( endTime == null ) {
							endTime = "";
						} 
						if ( !endTime.trim().equals("") ) {
							endTime = ejbcawebbean.getISO8601FromImpliedUTCOrRelative(endTime);
		        		}
						%>
					value="<%= endTime %>"
					<%	if ( !profile.isModifyable(EndEntityProfile.ENDTIME, 0) ) { %>
					readonly="true"
					<%	} %>
					/>
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_ENDTIME %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled"
				<%	if ( profile.isRequired(EndEntityProfile.ENDTIME, 0) ) {
						out.write(" CHECKED ");
					} %>
				/>
			</td>
		</tr>
	<% } %>

	<% if( profile.getUse(EndEntityProfile.CARDNUMBER, 0) ) { %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("CARDNUMBER") %>
      </td>
      <td > 
        <input type="text" name="<%=TEXTFIELD_CARDNUMBER%>" size="20" maxlength="40" tabindex="<%=tabindex++%>" value="<c:out value="<%= userdata.getCardNumber() %>"/>" title="<%= ejbcawebbean.getText("FORMAT_STRING") %>">  
      </td>
	  <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_CARDNUMBER %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.CARDNUMBER,0)) out.write(" CHECKED "); %>></td>
    </tr>
     <% } %>
     
     <% if( profile.getUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0) ) {
        ExtendedInformation ei = userdata.getExtendedInformation(); %>
        <tr id="Row<%=(row)%2%>">
            <td align="right">
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED\") %>"/>
                <%= ejbcawebbean.getHelpReference("/userguide.html#Name%20Constraints") %>
                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED_HELP1\") %>"/><br />
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED_HELP2\") %>"/></p>
            </td>
            <td>
                <textarea name="<%=TEXTAREA_NC_PERMITTED%>" rows="4" cols="38" tabindex="<%=tabindex++%>"><c:out value="<%= NameConstraint.formatNameConstraintsList(ei.getNameConstraintsPermitted()) %>"/></textarea>
            </td>
            <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_NC_PERMITTED %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.NAMECONSTRAINTS_PERMITTED,0)) out.write(" CHECKED "); %>></td>
        </tr>
    <% } %>
    <% if( profile.getUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0) ) {
        ExtendedInformation ei = userdata.getExtendedInformation(); %>
        <tr id="Row<%=(row++)%2%>">
            <td align="right">
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_EXCLUDED\") %>"/>
                <%= ejbcawebbean.getHelpReference("/userguide.html#Name%20Constraints") %>
                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_EXCLUDED_HELP\") %>"/></p>
            </td>
            <td>
                <textarea name="<%=TEXTAREA_NC_EXCLUDED%>" rows="4" cols="38" tabindex="<%=tabindex++%>"><c:out value="<%= NameConstraint.formatNameConstraintsList(ei.getNameConstraintsExcluded()) %>"/></textarea>
            </td>
            <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_NC_EXCLUDED %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED,0)) out.write(" CHECKED "); %>></td>
        </tr>
    <%  } %>

     <%	if (profile.getUseExtensiondata()) { %>
            <tr  id="Row<%=(row++)%2%>"> 
                    <td align="right"> 
                            <c:out value="<%= ejbcawebbean.getText(\"CERT_EXTENSIONDATA\") %>"/><br/>
                    </td><td>
                            <textarea name="<%=TEXTAREA_EXTENSIONDATA%>" rows="4" cols="38"><c:if test="${!useradded}"><c:out value="${editendentitybean.extensionData}"/></c:if></textarea>
                    </td>
                    <td>
                            <input type="checkbox" name="<%= CHECKBOX_REQUIRED_EXTENSIONDATA %>" value="<%= CHECKBOX_VALUE %>" disabled="disabled"/>
                    </td>
            </tr>
    <%	} %> 

    <% if (userdata.getExtendedInformation() != null && userdata.getExtendedInformation().getRawSubjectDn() != null) { %>
        <tr id="Row<%=(row++)%2%>">
            <td align="right">
                <c:out value="<%= ejbcawebbean.getText(\"RAWSUBJECTDN\") %>"/>
                <%= ejbcawebbean.getHelpReference("/userguide.html#Certificate%20Profile%20Fields") %>
                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"RAWSUBJECTDN_HELP\") %>"/></p>
            </td>
			<td style="text-align: left"><c:out value="<%= userdata.getExtendedInformation().getRawSubjectDn() %>"/></td>
            <td>&nbsp;</td>
        </tr>
    <%  } %>

    <!-- ---------- Other data -------------------- -->

       <% if ( profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)
            || usekeyrecovery 
            || profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON,0)
            || profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)
            || profile.getUsePrinting()
             ) { %>
       <tr id="Row<%=(row++)%2%>" class="section">
	 <td align="right"><strong><%= ejbcawebbean.getText("OTHERDATA") %></strong></td>
	 <td>&nbsp;</td>
	 <td>&nbsp;</td>
       </tr>
       <% } %>

       <!--  Max number of allowed requests for a password -->
       <% if(profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)){ %>
       <% 
           String defaultnrofrequests = profile.getValue(EndEntityProfile.ALLOWEDREQUESTS,0);
           if (defaultnrofrequests == null) {
        	   defaultnrofrequests = "1";
           }
           ExtendedInformation ei = userdata.getExtendedInformation();
           String counter = ei!=null ? ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER) : null;
           if (counter == null) {
        	   counter = defaultnrofrequests;
           }
         %>
       <tr id="Row<%=(row++)%2%>">
  	   <td align="right"><%= ejbcawebbean.getText("ALLOWEDREQUESTS") %></td>
	   <td>
            <select name="<%=SELECT_ALLOWEDREQUESTS %>" size="1" >
	            <% for(int j=0;j< 6;j++){
	            %>
	            <option
	            <%     if(counter.equals(Integer.toString(j)))
	                       out.write(" selected "); 
	            %>
	            value='<%=j%>'><%=j%></option>
	            <% }%>
            </select>
         </td>
	   <td>&nbsp;</td>
       </tr>
      <%} %>

  	<% if(usekeyrecovery){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <c:out value="<%= ejbcawebbean.getText(\"KEYRECOVERABLE\") %>"/> 
        <%= ejbcawebbean.getHelpReference("/adminguide.html#Key%20recovery") %>
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0))
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if( userdata.getKeyRecoverable())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>
           id="<%=CHECKBOX_KEYRECOVERABLE%>">
        <label for="<%=CHECKBOX_KEYRECOVERABLE%>"><c:out value="<%= ejbcawebbean.getText(\"ACTIVATE\") %>" /></label> 
      </td>
      <td>&nbsp;</td>
    </tr>
    <% } %>
	
        <% int revstatus = RevokedCertInfo.NOT_REVOKED;

           ExtendedInformation revei = userdata.getExtendedInformation();
		   if ( revei != null ) {
 		       String value = revei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
	           if((value != null) && (((String) value).length() > 0)) {
	               revstatus = (Integer.valueOf(value).intValue());
	           }
		   }
        %>
	
		<% if( profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) ) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("ISSUANCEREVOCATIONREASON") %>
			</td><td> 
        <select name="<%= SELECT_ISSUANCEREVOCATIONREASON %>" size="1"
        	<%	if ( !profile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) ) { %>
			  disabled
		   <% } %>
        >
          <option value="<%= RevokedCertInfo.NOT_REVOKED %>" class="lightgreen" <%
                if(revstatus == RevokedCertInfo.NOT_REVOKED) out.write(" selected ");
          %>><%= ejbcawebbean.getText("ACTIVE") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD %>" class="lightyellow" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) out.write(" selected ");
          %>><%= ejbcawebbean.getText("SUSPENDED") %>: <%= ejbcawebbean.getText("REV_CERTIFICATEHOLD") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_UNSPECIFIED") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_KEYCOMPROMISE") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_CACOMPROMISE") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_AFFILIATIONCHANGED") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_SUPERSEDED %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_SUPERSEDED") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_CESSATIONOFOPERATION") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_PRIVILEGEWITHDRAWN") %></option>

          <option value="<%= RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE %>" class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE) out.write(" selected ");
          %>><%= ejbcawebbean.getText("REVOKED") %>: <%= ejbcawebbean.getText("REV_AACOMPROMISE") %></option>
					
        </select>
			</td>
	 <td>&nbsp;</td>
		</tr>
	<% } %> 

 	<% if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("SENDNOTIFICATION") %>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_SENDNOTIFICATION%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% 
                                                                                                               if(profile.isRequired(EndEntityProfile.SENDNOTIFICATION,0) && profile.getValue(EndEntityProfile.SENDNOTIFICATION,0).equals(EndEntityProfile.TRUE) && userdata.getSendNotification())
                                                                                                                 out.write(" disabled='true'"); 
                                                                                                               if( userdata.getSendNotification())
                                                                                                                 out.write(" CHECKED ");
                                                                                                             %>
            id="<%=CHECKBOX_SENDNOTIFICATION%>">
        <label for="<%=CHECKBOX_SENDNOTIFICATION%>"><c:out value="<%= ejbcawebbean.getText(\"ACTIVATE\") %>" /></label>
      </td>
      <td>&nbsp;</td>
    </tr>
     <% } %>

 	<% if(profile.getUsePrinting()){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <%= ejbcawebbean.getText("PRINTUSERDATA") %>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_PRINT%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getPrintingDefault())
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(userdata.getPrintUserData())
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
            id="<%=CHECKBOX_PRINT%>">
        <label for="<%=CHECKBOX_PRINT%>"><c:out value="<%= ejbcawebbean.getText(\"PRINT\") %>" /></label>
      </td>
      <td>&nbsp;</td>
    </tr>
    <% } %>

    <!-- ---------- CSR -------------------- -->
    <% if (  userdata.getExtendedInformation() != null
    	  && (userdata.getExtendedInformation().getCertificateRequest() != null || userdata.getExtendedInformation().getKeyStoreAlgorithmType() != null) 
    	  ) {
        %>

       <tr id="Row<%=(row++)%2%>" class="section">
	 <td align="right"><strong><%= ejbcawebbean.getText("CERTIFICATEREQUESTDATA") %></strong></td>
	 <td>&nbsp;</td>
       </tr>
	  <%{
		final ExtendedInformation ei = userdata.getExtendedInformation();
		final byte[] csr = userdata.getExtendedInformation().getCertificateRequest();
		if (csr != null) {
		    final String csrPem = new String(CertTools.getPEMFromCertificateRequest(csr));
		%>
			<tr id="Row<%=(row++)%2%>">
			<td align="right"><%= ejbcawebbean.getText("CSR") %></td>
			<td style="text-align: left"><pre><c:out value="<%= csrPem %>"/></pre></td>
			</tr> 
      <% }
        String ksAlgType = userdata.getExtendedInformation().getKeyStoreAlgorithmType();
        String ksAlgSubType = userdata.getExtendedInformation().getKeyStoreAlgorithmSubType(); // can be null but it's ok
		if (ksAlgType != null) {
		%>
			<tr id="Row<%=(row++)%2%>">
			<td align="right"><%= ejbcawebbean.getText("REQKSALGTYPE") %></td>
			<td style="text-align: left"><c:out value="<%= ksAlgType %>"/></td>
			</tr> 
			<tr id="Row<%=(row++)%2%>">
			<td align="right"><%= ejbcawebbean.getText("REQKSALGSUBTYPE") %></td>
			<td style="text-align: left"><c:out value="<%= ksAlgSubType %>"/></td>
			</tr> 
      <% }
         } %>
    <% } %>


    <!-- ---------- Form buttons -------------------- -->

	<tr id="Row<%=(row++)%2%>">
	  <td align="right">&nbsp;</td>
	  <td><input type="submit" name="<%= BUTTON_SAVE %>" value="<%= ejbcawebbean.getText("SAVE") %>" tabindex="<%=tabindex++%>" onClick='return checkallfields()'>
		  &nbsp;&nbsp;&nbsp;
		  <input type="button" name="<%= BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" tabindex="<%=tabindex++%>" onclick='self.close()'>
	  </td>
	  <td>&nbsp;</td>
	</tr> 

	</table> 

  </form>

  <%  }
    }    
   } %>
   
</body>
</html>
