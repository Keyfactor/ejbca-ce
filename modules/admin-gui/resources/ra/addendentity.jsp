<%@page import="org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier"%>
<%@page import="org.ejbca.ui.web.ParameterException"%>
<%@page import="org.apache.commons.lang.StringUtils"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<%
    response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
%>
<%@page  errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.jsf.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.ui.web.admin.rainterface.UserView,
    org.ejbca.ui.web.RequestHelper,org.ejbca.ui.web.admin.rainterface.RAInterfaceBean, org.ejbca.core.model.ra.raadmin.EndEntityProfile, org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator, org.cesecore.certificates.endentity.EndEntityConstants,
                 org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement, javax.ejb.CreateException, java.io.Serializable, org.cesecore.certificates.util.DNFieldExtractor, org.ejbca.core.model.ra.ExtendedInformationFields, org.cesecore.certificates.endentity.EndEntityInformation, 
                 org.ejbca.core.model.SecConst,org.cesecore.util.StringTools,org.cesecore.certificates.util.DnComponents,org.apache.commons.lang.time.DateUtils, org.apache.commons.lang.StringUtils,
                 org.cesecore.certificates.endentity.ExtendedInformation,org.cesecore.certificates.crl.RevokedCertInfo,org.cesecore.ErrorCode,org.ejbca.util.query.*,java.math.BigInteger,org.cesecore.authorization.AuthorizationDeniedException,org.ejbca.core.model.authorization.AccessRulesConstants,
                 org.cesecore.certificates.certificate.certextensions.standard.NameConstraint, org.cesecore.certificates.certificate.certextensions.standard.QcStatement, org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier, org.cesecore.certificates.certificate.certextensions.CertificateExtensionException, org.cesecore.certificates.ca.IllegalNameException, org.ejbca.util.HTMLTools" %>
<html> 
<jsp:useBean id="ejbcawebbean" scope="session" type="org.ejbca.ui.web.jsf.configuration.EjbcaWebBean" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl" />
<jsp:useBean id="rabean" scope="session" class="org.ejbca.ui.web.admin.rainterface.RAInterfaceBean" />
<jsp:useBean id="editendentitybean" scope="page" class="org.ejbca.ui.web.admin.rainterface.EditEndEntityBean" />
<%!// Declarations

    static final String ACTION = "action";
    static final String ACTION_ADDUSER = "adduser";
    static final String ACTION_CHANGEPROFILE = "changeprofile";

    static final String BUTTON_ADDUSER = "buttonadduser";
    static final String BUTTON_RESET = "buttonreset";
    static final String BUTTON_RELOAD = "buttonreload";

    static final String TEXTFIELD_USERNAME = "textfieldusername";
    static final String TEXTFIELD_PASSWORD = "textfieldpassword";
    static final String TEXTFIELD_CONFIRMPASSWORD = "textfieldconfirmpassword";
    static final String TEXTFIELD_SUBJECTDN = "textfieldsubjectdn";
    static final String TEXTFIELD_SUBJECTALTNAME = "textfieldsubjectaltname";
    static final String TEXTFIELD_SUBJECTDIRATTR = "textfieldsubjectdirattr";
    static final String TEXTFIELD_EMAIL = "textfieldemail";
    static final String TEXTFIELD_EMAILDOMAIN = "textfieldemaildomain";
    static final String TEXTFIELD_UPNNAME = "textfieldupnname";
    static final String TEXTFIELD_RFC822NAME = "textfieldrfc822name";
    static final String TEXTFIELD_STARTTIME = "textfieldstarttime";
    static final String TEXTFIELD_ENDTIME = "textfieldendtime";
    static final String TEXTFIELD_CERTSERIALNUMBER = "textfieldcertsn";
    static final String TEXTFIELD_CARDNUMBER = "textfieldcardnumber";
    static final String TEXTFIELD_MAXFAILEDLOGINS = "textfieldmaxfailedlogins";
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
    static final String SELECT_SUBJECTDIRATTR = "selectsubjectaldirattr";
    static final String SELECT_EMAILDOMAIN = "selectemaildomain";
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
    static final String CHECKBOX_CARDNUMBER = "checkboxcardnumber";
    static final String CHECKBOX_PRINT = "checkboxprint";
    static final String CHECKBOX_SUBJECTALTNAME_DNS = "checkboxsubjectaltnamedns";

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
    static final String CHECKBOX_REQUIRED_MAXFAILEDLOGINS = "checkboxrequiredmaxfailedlogins";
    static final String CHECKBOX_REQUIRED_CERTSERIALNUMBER = "checkboxrequiredcertserialnumber";
    static final String CHECKBOX_REQUIRED_NC_PERMITTED = "checkboxrequiredncpermitted";
    static final String CHECKBOX_REQUIRED_NC_EXCLUDED = "checkboxrequiredncexcluded";
    static final String CHECKBOX_REQUIRED_EXTENSIONDATA = "checkboxrequiredextensiondata";

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
    AccessRulesConstants.REGULAR_CREATEENDENTITY);
    rabean.initialize(ejbcawebbean);
    
    final String VIEWUSER_LINK = "viewendentity.jsp";
    final String EDITUSER_LINK = "editendentity.jsp";

    String THIS_FILENAME = "addendentity.jsp";
    EndEntityProfile profile = null;
    String[] profilenames = null;
    boolean noprofiles = false;
    int profileid = 0;
    String serialnumber = "";

    profilenames = (String[]) ejbcawebbean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.CREATE_END_ENTITY).keySet().toArray(new String[0]);

    if (profilenames == null || profilenames.length == 0)
        noprofiles = true;
    else
        profileid = rabean.getEndEntityProfileId(profilenames[0]);

    boolean chooselastprofile = false;
    if (ejbcawebbean.getLastEndEntityProfile() != 0 && rabean.getEndEntityProfileName(ejbcawebbean.getLastEndEntityProfile()) != null) {
        for (int i = 0; i < profilenames.length; i++) {
    if (rabean.getEndEntityProfileName(ejbcawebbean.getLastEndEntityProfile()).equals(profilenames[i]))
        chooselastprofile = true;
        }
    }

    if (!noprofiles) {
        if (!chooselastprofile)
    profileid = rabean.getEndEntityProfileId(profilenames[0]);
        else
    profileid = ejbcawebbean.getLastEndEntityProfile();
    }

    boolean userexists = false;
    boolean useradded = false;
    boolean useoldprofile = false;
    boolean usekeyrecovery = false;

    EndEntityProfile oldprofile = null;
    String addedusername = "";

    String approvalmessage = null;
    String oldemail = "";
    String oldcardnumber = "";
    String lastselectedusername = "";
    String lastselectedpassword = "";
    String lastselectedemaildomain = "";
    String lastselectedcertificateprofile = "";
    String lastselectedtoken = "";
    String lastselectedca = "";

    String[] lastselectedsubjectdns = null;
    String[] lastselectedsubjectaltnames = null;
    String[] lastselectedsubjectdirattrs = null;
    int[] fielddata = null;

    Map<Integer, String> caidtonamemap = ejbcawebbean.getCAIdToNameMap();

    RequestHelper.setDefaultCharacterEncoding(request);

    if (request.getParameter(ACTION) != null) {
        if (request.getParameter(ACTION).equals(ACTION_CHANGEPROFILE)) {
    profileid = Integer.parseInt(request.getParameter(SELECT_ENDENTITYPROFILE));
    ejbcawebbean.setLastEndEntityProfile(profileid);
        }
        if (request.getParameter(ACTION).equals(ACTION_ADDUSER)) {
    if (request.getParameter(BUTTON_ADDUSER) != null) {
        UserView newuser = new UserView();
        // Get previous chosen profile.
        String hiddenprofileid = request.getParameter(HIDDEN_PROFILE);
        int oldprofileid = Integer.parseInt(hiddenprofileid);
        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            // Check that adminsitrator is authorized to given profileid
            boolean authorizedtoprofile = false;
            for (int i = 0; i < profilenames.length; i++) {
                if (oldprofileid == rabean.getEndEntityProfileId(profilenames[i])) {
                    authorizedtoprofile = true;
                }
            }
            if (!authorizedtoprofile)
                throw new AuthorizationDeniedException("Error when trying to add user to non authorized profile");
        }

        oldprofile = rabean.getEndEntityProfile(oldprofileid);
        lastselectedsubjectdns = new String[oldprofile.getSubjectDNFieldOrderLength()];
        lastselectedsubjectaltnames = new String[oldprofile.getSubjectAltNameFieldOrderLength()];
        lastselectedsubjectdirattrs = new String[oldprofile.getSubjectDirAttrFieldOrderLength()];
        newuser.setEndEntityProfileId(oldprofileid);

        String value = request.getParameter(TEXTAREA_EXTENSIONDATA);
        if (value != null) {
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
                newuser.setExtendedInformation(ei);
            }
            editendentitybean.setExtendedInformation(ei);

            // Save the new value if the profile allows it
            if (oldprofile.getUseExtensiondata()) {
                editendentitybean.setExtensionData(value);
            }
        }

        value = request.getParameter(TEXTFIELD_USERNAME);
        if (value != null) {
            value = value.trim();
            if (!value.equals("")) {
                newuser.setUsername(value);
                oldprofile.setUsernameDefault(value);
                addedusername = value;
            }
        }

        value = request.getParameter(SELECT_USERNAME);
        if (value != null) {
            if (!value.equals("")) {
                newuser.setUsername(value);
                lastselectedusername = value;
                addedusername = value;
        	}
        }

        value = request.getParameter(TEXTFIELD_PASSWORD);
        if (value != null) {
            value = value.trim();
            if (!value.equals("")) {
                newuser.setPassword(value);
                oldprofile.setPredefinedPassword(value);
            }
        }

        value = request.getParameter(SELECT_PASSWORD);
        if (value != null) {
            if (!value.equals("")) {
                newuser.setPassword(value);
                lastselectedpassword = value;
            }
        }

        value = request.getParameter(CHECKBOX_CLEARTEXTPASSWORD);
        if (value != null) {
            if (value.equals(CHECKBOX_VALUE)) {
                newuser.setClearTextPassword(true);
                oldprofile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);
            } else {
                newuser.setClearTextPassword(false);
                oldprofile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.FALSE);
            }
        } else {
            //We end up here if the checkbox was non-modifiable. 
            newuser.setClearTextPassword(oldprofile.getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0).equals(EndEntityProfile.TRUE));
        }

        value = request.getParameter(RADIO_MAXFAILEDLOGINS);
        if (RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED.equals(value)) {
            value = "-1";
        } else {
            value = request.getParameter(TEXTFIELD_MAXFAILEDLOGINS);
        }
        if (value != null) {
            int maxFailedLogins = Integer.parseInt(value);
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            ei.setMaxLoginAttempts(maxFailedLogins);
            ei.setRemainingLoginAttempts(maxFailedLogins);
            newuser.setExtendedInformation(ei);
            oldprofile.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, String.valueOf(maxFailedLogins));
        }

        value = request.getParameter(TEXTFIELD_EMAIL);
        if (value != null) {
            value = value.trim();
            oldemail = value;
            String emaildomain = request.getParameter(TEXTFIELD_EMAILDOMAIN);
            if (!value.equals("")) {
                if (emaildomain != null) {
                    emaildomain = emaildomain.trim();
                    if (!emaildomain.equals("")) {
                        newuser.setEmail(value + "@" + emaildomain);
                        oldprofile.setValue(EndEntityProfile.EMAIL, 0, emaildomain);
                    } else {
                        // TEXTFIELD_EMAILDOMAIN empty but not TEXTFIELD_EMAIL
                        approvalmessage = ejbcawebbean.getText("EMAILINCOMPLETE");
                    }
                }

                emaildomain = request.getParameter(SELECT_EMAILDOMAIN);
                if (emaildomain != null) {
                    if (!emaildomain.equals("")) {
                        newuser.setEmail(value + "@" + emaildomain);
                        lastselectedemaildomain = emaildomain;
                    }
                }
            } else {
                if (emaildomain != null) {
                    emaildomain = emaildomain.trim();
                    if (!emaildomain.equals("")) {
                        // TEXTFIELD_EMAIL empty but not TEXTFIELD_EMAILDOMAIN
                        approvalmessage = ejbcawebbean.getText("EMAILINCOMPLETE");
                    }
                }
            }
        }

        value = request.getParameter(TEXTFIELD_CARDNUMBER);
        if (value != null) {
            value = value.trim();
            oldcardnumber = value;
            if (!value.equals("")) {
                newuser.setCardNumber(value);
            }
        }

        String subjectdn = "";
        int numberofsubjectdnfields = oldprofile.getSubjectDNFieldOrderLength();
        for (int i = 0; i < numberofsubjectdnfields; i++) {
            value = null;
            fielddata = oldprofile.getSubjectDNFieldsInOrder(i);

            if (!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
                value = request.getParameter(TEXTFIELD_SUBJECTDN + i);
            } else {
                if (oldprofile.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])
                        || (request.getParameter(CHECKBOX_SUBJECTDN + i) != null && request.getParameter(CHECKBOX_SUBJECTDN + i)
                                .equals(CHECKBOX_VALUE)))
                    value = newuser.getEmail();
            }
            if (value != null) {
                value = value.trim();
                if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNSERIALNUMBER)) {
                    serialnumber = value;
                }
                oldprofile.setValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER], value);
                final String field = DNFieldExtractor.getFieldComponent(
                        DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]), DNFieldExtractor.TYPE_SUBJECTDN)
                        + value;
                final String dnPart;
                if (field.charAt(field.length() - 1) != '=') {
                    dnPart = org.ietf.ldap.LDAPDN.escapeRDN(field);
                } else {
                    dnPart = field;
                }
                if (subjectdn.equals(""))
                    subjectdn = dnPart;
                else
                    subjectdn += ", " + dnPart;
            }

            value = request.getParameter(SELECT_SUBJECTDN + i);
            if (value != null) {
                value = value.trim();
                if (!value.equals("")) {
                    lastselectedsubjectdns[i] = value;
                    value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                            DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]), DNFieldExtractor.TYPE_SUBJECTDN)
                            + value);
                    if (subjectdn.equals(""))
                        subjectdn = value;
                    else
                        subjectdn += ", " + value;
                }
            }
        }
        newuser.setSubjectDN(subjectdn);

        String subjectaltname = "";
        int numberofsubjectaltnamefields = oldprofile.getSubjectAltNameFieldOrderLength();
        for (int i = 0; i < numberofsubjectaltnamefields; i++) {
            fielddata = oldprofile.getSubjectAltNameFieldsInOrder(i);
            value = null;
            if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
                if (oldprofile.getUse(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])) {
                    if (oldprofile.isRequired(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])
                            || (request.getParameter(CHECKBOX_SUBJECTALTNAME + i) != null && request.getParameter(
                                    CHECKBOX_SUBJECTALTNAME + i).equals(CHECKBOX_VALUE))) {
                        value = newuser.getEmail();
                    }
                } else {
                    if (request.getParameter(TEXTFIELD_SUBJECTALTNAME + i) != null
                            && !request.getParameter(TEXTFIELD_SUBJECTALTNAME + i).equals("")
                            && request.getParameter(TEXTFIELD_RFC822NAME + i) != null
                            && !request.getParameter(TEXTFIELD_RFC822NAME + i).equals("")) {
                        value = request.getParameter(TEXTFIELD_RFC822NAME + i) + "@"
                                + request.getParameter(TEXTFIELD_SUBJECTALTNAME + i);
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
                value = value.trim();
                if (!value.equals("")) {
                    oldprofile.setValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER], value);
                    value = org.ietf.ldap.LDAPDN
                            .escapeRDN(DNFieldExtractor.getFieldComponent(
                                    DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                    DNFieldExtractor.TYPE_SUBJECTALTNAME) + value);
                    if (subjectaltname.equals(""))
                        subjectaltname = value;
                    else
                        subjectaltname += ", " + value;

                }
            }
            value = request.getParameter(SELECT_SUBJECTALTNAME + i);
            if (value != null) {
                if (!value.equals("")) {
                    lastselectedsubjectaltnames[i] = value;
                    if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
                        if (!oldprofile.getUse(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER])) {
                            if (request.getParameter(SELECT_SUBJECTALTNAME + i) != null
                                    && !request.getParameter(SELECT_SUBJECTALTNAME + i).equals("")
                                    && request.getParameter(TEXTFIELD_RFC822NAME + i) != null
                                    && !request.getParameter(TEXTFIELD_RFC822NAME + i).equals("")) {
                                value = request.getParameter(TEXTFIELD_RFC822NAME + i) + "@" + value;
                            } else {
                                value = request.getParameter(SELECT_SUBJECTALTNAME + i); // A completely locked down value is only stored in the SELECT_SUBJECTALTNAME part 
                            }
                        }
                    }
                    if (EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                        if (request.getParameter(TEXTFIELD_UPNNAME + i) != null) {
                            value = request.getParameter(TEXTFIELD_UPNNAME + i) + "@" + value;
                        }
                    }
                    if (value != null) {
                        value = org.ietf.ldap.LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(
                                DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                DNFieldExtractor.TYPE_SUBJECTALTNAME) + value);
                        if (subjectaltname.equals(""))
                            subjectaltname = value;
                        else
                            subjectaltname += ", " + value;
                    }
                }
            }
        }
        newuser.setSubjectAltName(subjectaltname);

        String subjectdirattr = "";
        int numberofsubjectdirattrfields = oldprofile.getSubjectDirAttrFieldOrderLength();
        for (int i = 0; i < numberofsubjectdirattrfields; i++) {
            fielddata = oldprofile.getSubjectDirAttrFieldsInOrder(i);
            value = request.getParameter(TEXTFIELD_SUBJECTDIRATTR + i);
            if (value != null) {
                value = value.trim();
                if (!value.equals("")) {
                    oldprofile.setValue(fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER], value);
                    value = org.ietf.ldap.LDAPDN
                            .escapeRDN(DNFieldExtractor.getFieldComponent(
                                    DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                    DNFieldExtractor.TYPE_SUBJECTDIRATTR) + value);
                    if (subjectdirattr.equals(""))
                        subjectdirattr = value;
                    else
                        subjectdirattr += ", " + value;

                }
            }
            value = request.getParameter(SELECT_SUBJECTDIRATTR + i);
            if (value != null) {
                if (!value.equals("")) {
                    lastselectedsubjectdirattrs[i] = value;
                    value = org.ietf.ldap.LDAPDN
                            .escapeRDN(DNFieldExtractor.getFieldComponent(
                                    DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]),
                                    DNFieldExtractor.TYPE_SUBJECTDIRATTR) + value);
                    if (subjectdirattr.equals(""))
                        subjectdirattr = value;
                    else
                        subjectdirattr += ", " + value;

                }
            }
        }
        newuser.setSubjectDirAttributes(subjectdirattr);

        value = request.getParameter(SELECT_ALLOWEDREQUESTS);
        if (value != null) {
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, value);
            newuser.setExtendedInformation(ei);
        }
        value = request.getParameter(CHECKBOX_KEYRECOVERABLE);
        if (value != null) {
            if (value.equals(CHECKBOX_VALUE)) {
                newuser.setKeyRecoverable(true);
                oldprofile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
            } else {
                newuser.setKeyRecoverable(false);
                oldprofile.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.FALSE);
            }
        }

        value = request.getParameter(CHECKBOX_SENDNOTIFICATION);
        if (value != null) {
            if (value.equals(CHECKBOX_VALUE)) {
                newuser.setSendNotification(true);
                oldprofile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.TRUE);
            } else {
                newuser.setSendNotification(false);
                oldprofile.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.FALSE);
            }
        }
        value = request.getParameter(CHECKBOX_PRINT);
        if (value != null) {
            if (value.equals(CHECKBOX_VALUE)) {
                newuser.setPrintUserData(true);
                oldprofile.setPrintingDefault(true);
            } else {
                newuser.setPrintUserData(false);
                oldprofile.setPrintingDefault(false);
            }
        }

        // Issuance revocation reason, what state a newly issued certificate will have
        if (oldprofile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
            value = request.getParameter(SELECT_ISSUANCEREVOCATIONREASON);
            // If it's not modifyable don't even try to modify it
            if (!oldprofile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
                value = oldprofile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
            }
            if (value != null) {
                ExtendedInformation ei = newuser.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                ei.setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, value);
                newuser.setExtendedInformation(ei);
                oldprofile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, value);
            } else {
                oldprofile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);
            }
        }

        value = request.getParameter(SELECT_CERTIFICATEPROFILE);
        newuser.setCertificateProfileId(Integer.parseInt(value));
        oldprofile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, value);
        lastselectedcertificateprofile = value;

        value = request.getParameter(SELECT_CA);
        newuser.setCAId(Integer.parseInt(value));
        oldprofile.setValue(EndEntityProfile.DEFAULTCA, 0, value);
        lastselectedca = value;

        value = request.getParameter(SELECT_TOKEN);
        int tokentype = Integer.parseInt(value);
        newuser.setTokenType(tokentype);
        oldprofile.setValue(EndEntityProfile.DEFKEYSTORE, 0, value);
        lastselectedtoken = value;

        if (oldprofile.isValidityStartTimeUsed()) {
            value = request.getParameter(TEXTFIELD_STARTTIME);
            if (value != null) {
                value = value.trim();
                if (value.length() > 0) {
                    String storeValue = ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value);
                    ExtendedInformation ei = newuser.getExtendedInformation();
                    if (ei == null) {
                        ei = new ExtendedInformation();
                    }
                    ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, storeValue);
                    newuser.setExtendedInformation(ei);
                    oldprofile.setValidityStartTime(value);
                }
            }
        }
        if (oldprofile.isValidityEndTimeUsed()) {
            value = request.getParameter(TEXTFIELD_ENDTIME);
            if (value != null) {
                value = value.trim();
                if (value.length() > 0) {
                    String storeValue = ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value);
                    ExtendedInformation ei = newuser.getExtendedInformation();
                    if (ei == null) {
                        ei = new ExtendedInformation();
                    }
                    ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, storeValue);
                    newuser.setExtendedInformation(ei);
                    oldprofile.setValidityEndTime(value);
                }
            }
        }
        if (oldprofile.isCustomSerialNumberUsed()) {
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            value = request.getParameter(TEXTFIELD_CERTSERIALNUMBER);
            if (value != null && value.length() > 0) {
                ei.setCertificateSerialNumber(new BigInteger(value.trim(), 16));
            } else {
                ei.setCertificateSerialNumber(null);
            }
            newuser.setExtendedInformation(ei);
        }
        if (oldprofile.isPsd2QcStatementUsed()) {
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            value = request.getParameter(TEXTFIELD_NCANAME);
            if (value != null && value.length() > 0) {
                ei.setQCEtsiPSD2NcaName(value.trim());
            }
            value = request.getParameter(TEXTFIELD_NCAID);
            if (value != null && value.length() > 0) {
                ei.setQCEtsiPSD2NcaId(value.trim());
            }
            String[] pspRoleValues = request.getParameterValues(SELECT_PSD2_PSPROLE);
            if (pspRoleValues != null && pspRoleValues.length > 0) {
                final List<PSD2RoleOfPSPStatement> pspRoles = new ArrayList<>();
                for (String role : pspRoleValues) {
                    pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid(role), role));
                }
            	ei.setQCEtsiPSD2RolesOfPSP(pspRoles);
            }
            newuser.setExtendedInformation(ei);
        }
        if (oldprofile.isCabfOrganizationIdentifierUsed()) {
            ExtendedInformation ei = newuser.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            value = StringUtils.trim(request.getParameter(TEXTFIELD_CABFORGANIZATIONIDENTIFIER));
            if (oldprofile.isCabfOrganizationIdentifierRequired() && StringUtils.isEmpty(value)) {
            	throw new ParameterException(ejbcawebbean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED"));
            } else if (value != null && !value.matches(CabForumOrganizationIdentifier.VALIDATION_REGEX)) {
            	throw new ParameterException(ejbcawebbean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_BADFORMAT"));
            }
            ei.setCabfOrganizationIdentifier(value);
            newuser.setExtendedInformation(ei);
        }
        try {
            if (oldprofile.isNameConstraintsPermittedUsed()) {
                ExtendedInformation ei = newuser.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                value = request.getParameter(TEXTAREA_NC_PERMITTED);
                if (value != null && !value.trim().isEmpty()) {
                    ei.setNameConstraintsPermitted(NameConstraint.parseNameConstraintsList(value));
                } else {
                    ei.setNameConstraintsPermitted(null);
                }
                newuser.setExtendedInformation(ei);
            }
            if (oldprofile.isNameConstraintsExcludedUsed()) {
                ExtendedInformation ei = newuser.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                value = request.getParameter(TEXTAREA_NC_EXCLUDED);
                if (value != null && !value.trim().isEmpty()) {
                    ei.setNameConstraintsExcluded(NameConstraint.parseNameConstraintsList(value));
                } else {
                    ei.setNameConstraintsExcluded(null);
                }
                newuser.setExtendedInformation(ei);
            }
        } catch (CertificateExtensionException e) {
            approvalmessage = e.getMessage();
        }

        // See if user already exists
        if (rabean.userExist(newuser.getUsername())) {
            userexists = true;
            useoldprofile = true;
        } else {
            if (request.getParameter(BUTTON_RELOAD) != null) {
                useoldprofile = true;
            } else if (approvalmessage == null) {
                // No error. Go ahead an add user
                try {
                    EndEntityInformation endEntityInformation = rabean.addUser(newuser);
                    newuser.setUsername(endEntityInformation.getUsername());
                    oldprofile.setUsernameDefault(endEntityInformation.getUsername());
                    addedusername = endEntityInformation.getUsername();
                    useradded = true;
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
                } catch (org.cesecore.certificates.ca.IllegalNameException e) {
                    if (e.getErrorCode().equals(ErrorCode.NAMECONSTRAINT_VIOLATION)) {
                        approvalmessage = e.getMessage();
                    } else {
                        throw e;
                    }
                }

            }
        }
    }
        }
    }

    int numberofrows = ejbcawebbean.getEntriesPerPage();
    UserView[] addedusers = rabean.getAddedUsers(numberofrows);
    int row = 0;
    int tabindex = 0;

    if (!noprofiles) {
        if (!useoldprofile) {
    profile = rabean.getEndEntityProfile(profileid);
    oldemail = "";
    oldcardnumber = "";
        } else
    profile = oldprofile;
    } else
        profile = new EndEntityProfile();

    String[] tokentexts = RAInterfaceBean.tokentexts;
    int[] tokenids = RAInterfaceBean.tokenids;

    String[] availabletokens = profile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);

    ArrayList<Integer>[] tokenissuers = null;

    usekeyrecovery = globalconfiguration.getEnableKeyRecovery() && profile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);

    Map<Integer, List<Integer>> availablecas = rabean.getCasAvailableToEndEntity(profileid);
    
    Collection authcas = null;

    pageContext.setAttribute("useradded", useradded);
    pageContext.setAttribute("profile", profile);
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <link rel="stylesheet" type="text/css" href="<c:out value='<%= ejbcawebbean.getBaseUrl() + ejbcawebbean.getCssFile() %>' />" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getAdminWebBaseUrl() + ejbcawebbean.getImagePath("favicon.png")%>" type="image/png" />
  <script type="text/javascript">

  <% if(!noprofiles){ %>
   <!--
      var TRUE  = "<%= EndEntityProfile.TRUE %>";
      var FALSE = "<%= EndEntityProfile.FALSE %>"; 

      <%
      if(usekeyrecovery){ %>
function isKeyRecoveryPossible(){
   var seltoken = document.adduser.<%=SELECT_TOKEN%>.options.selectedIndex; 
   var token = document.adduser.<%=SELECT_TOKEN%>.options[seltoken].value;
   if(token == <%=SecConst.TOKEN_SOFT_BROWSERGEN %>){
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true;
   }else{
     <% if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0)){ %>
       document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=true; 
     <% }else{ %>
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.disabled=false;
     <%}
       if(profile.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE)){ %>
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=true;
   <% }else{ %>  
     document.adduser.<%=CHECKBOX_KEYRECOVERABLE%>.checked=false;
     <% } %>
   }
}

   <% } %>
   
  var certprofileids = new Array(<%= availablecas.keySet().size()%>);
  var CERTPROFID   = 0;
  var AVAILABLECAS = 1;

  var CANAME       = 0;
  var CAID         = 1;
<%
  Iterator iter = availablecas.keySet().iterator();
  int x = 0;
  while(iter.hasNext()){ 
    Integer next = (Integer) iter.next();
    Collection nextcaset = (Collection) availablecas.get(next);
  %>
    certprofileids[<%=x%>] = new Array(2);
    certprofileids[<%=x%>][CERTPROFID] = <%= next.intValue() %> ;
    certprofileids[<%=x%>][AVAILABLECAS] = new Array(<%= nextcaset.size() %>);
<%  Iterator iter2 = nextcaset.iterator();
    int y = 0;
    while(iter2.hasNext()){
        Integer nextca = (Integer) iter2.next(); %>
        certprofileids[<%=x%>][AVAILABLECAS][<%=y%>] = new Array(2);
        certprofileids[<%=x%>][AVAILABLECAS][<%=y%>][CANAME] = "<%= HTMLTools.javascriptEscape(caidtonamemap.get(nextca)) %>";      
        certprofileids[<%=x%>][AVAILABLECAS][<%=y%>][CAID] = <%= nextca.intValue() %>;
 <%     y++ ;
    }
    x++;
  } %>     

function fillCAField(){
   var selcertprof = document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex; 
   var certprofid = document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options[selcertprof].value; 
   var caselect   =  document.adduser.<%=SELECT_CA%>;

   var numofcas = caselect.length;
   for( i=numofcas-1; i >= 0; i-- ){
       caselect.options[i]=null;
    }   

    if( selcertprof > -1){
      for( i=0; i < certprofileids.length; i ++){
        if(certprofileids[i][CERTPROFID] == certprofid) {
            for (j = 0; j < certprofileids[i][AVAILABLECAS].length; j++) {
                caselect.options[j] = new Option(certprofileids[i][AVAILABLECAS][j][CANAME],
                    certprofileids[i][AVAILABLECAS][j][CAID]);

                if (certprofileids[i][AVAILABLECAS][j][CAID] == "<%= lastselectedca %>" ) {
                    caselect.options.selectedIndex = j;

                }else if (certprofileids[i][AVAILABLECAS][j][CAID] == "<%= profile.getDefaultCA() %>")
                    caselect.options.selectedIndex = j;
            }
        }
      }
    }
}

function checkallfields(){
    var illegalfields = 0;

    <% if (!profile.isAutoGeneratedUsername()) { %>
    if(!checkfieldforlegalchars("document.adduser.<%=TEXTFIELD_USERNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText("USERNAME") %>"))
      illegalfields++;
    <%  if (profile.isUsernameRequired()){%>
    if((document.adduser.<%= TEXTFIELD_USERNAME %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDUSERNAME", true) %>");
      illegalfields++;
    } 
    <%    }
        }
       if (!profile.useAutoGeneratedPasswd()){
         if (profile.isPasswordModifiable()){%>

    <%  if (profile.isPasswordRequired() && !profile.isPasswordPreDefined()) {%>
    if((document.adduser.<%= TEXTFIELD_PASSWORD %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDPASSWORD", true) %>");
      illegalfields++;
    } 
    <%    }
        }
       }
       for(int i=0; i < profile.getSubjectDNFieldOrderLength(); i++){
         fielddata = profile.getSubjectDNFieldsInOrder(i);
         if( !EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS) ){
           if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_SUBJECTDN+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
    <%     if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){%>
    if((document.adduser.<%= TEXTFIELD_SUBJECTDN+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
      illegalfields++;
    } 
    <%     }
          }
         }
         else{ %>
             if(document.adduser.<%= CHECKBOX_SUBJECTDN+i %>)
             {
                 document.adduser.<%= CHECKBOX_SUBJECTDN+i %>.disabled = false;          
             }
     <%  }
       }
       for(int i=0; i < profile.getSubjectAltNameFieldOrderLength(); i++){
         fielddata = profile.getSubjectAltNameFieldsInOrder(i);
         int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
         if(EndEntityProfile.isFieldImplemented(fieldtype)) {
           if(!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)){
             if(EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE],DnComponents.UPN)){%>
    if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_UPNNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
          <%   if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>            
              if((document.adduser.<%= TEXTFIELD_UPNNAME+i %>.value == "")){ 
                alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
                illegalfields++;
              }
           <%  }
             }   
             if(profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){
               if(EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.IPADDRESS)) { %>
    if(!checkfieldforipaddess("document.adduser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYNUMBERALSANDDOTS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
      illegalfields++;
           <%  }else{ %> 
           � if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_SUBJECTALTNAME+i%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"))
        	   ����� illegalfields++;
    
    <%    if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ %>
    if((document.adduser.<%= TEXTFIELD_SUBJECTALTNAME+i %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE]), true)%>");
      illegalfields++;
    } 
    <%      }
           }
          }
         }
         else{ %>
             if(document.adduser.<%= CHECKBOX_SUBJECTALTNAME+i %>)
             {
                 document.adduser.<%= CHECKBOX_SUBJECTALTNAME+i %>.disabled = false;          
             }
     <%    }
         } 
       }
       
       if(profile.isNameConstraintsPermittedRequired()) { %>
		 	if (document.adduser.<%= TEXTAREA_NC_PERMITTED %>.value == "") { 
		      alert("<%= ejbcawebbean.getText("REQUIREDNAMECONSTRAINTPERMITTED", true) + "" %>");
		      illegalfields++;
		    }
		<%}
		
		if(profile.isNameConstraintsExcludedRequired()) { %>
		    if (document.adduser.<%= TEXTAREA_NC_EXCLUDED %>.value == "") { 
		      alert("<%= ejbcawebbean.getText("REQUIREDNAMECONSTRAINTEXCLUDED", true) + "" %>");
		      illegalfields++;
		    }
		<%}

       
       for(int i=0; i<profile.getSubjectDirAttrFieldOrderLength(); i++){
            fielddata = profile.getSubjectDirAttrFieldsInOrder(i);
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(EndEntityProfile.isFieldImplemented(fieldtype)) {
                if(EndEntityProfile.isFieldOfType(fieldtype, DnComponents.COUNTRYOFCITIZENSHIP) || EndEntityProfile.isFieldOfType(fieldtype, DnComponents.COUNTRYOFRESIDENCE) || EndEntityProfile.isFieldOfType(fieldtype, DnComponents.PLACEOFBIRTH)) { %>
                    if(!checkfieldforlegaldnchars("document.adduser.<%=TEXTFIELD_SUBJECTDIRATTR+i%>", "<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype))%>"))
                        illegalfields++;
                  <%if(profile.isRequired(fieldtype, fielddata[EndEntityProfile.NUMBER])) { %>
                        if(document.adduser.<%= TEXTFIELD_SUBJECTDIRATTR+i%>.value=="") {
                            alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype), true) %>");
                            illegalfields++;
                        }
                 <%}
                } else if(EndEntityProfile.isFieldOfType(fieldtype, DnComponents.DATEOFBIRTH)){ %>
                    if(!checkFieldForDate("document.adduser.<%=TEXTFIELD_SUBJECTDIRATTR+i %>", "<%= ejbcawebbean.getText("ONLYDECNUMBERS") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype)) %>"))
                        illegalfields++;
                 <% if(profile.isRequired(fieldtype, fielddata[EndEntityProfile.NUMBER])) { %>
                        if(document.adduser.<%= TEXTFIELD_SUBJECTDIRATTR+i%>.value=="") {
                            alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype), true) %>");
                            illegalfields++;
                        }
              <%    }
                } else if(EndEntityProfile.isFieldOfType(fieldtype, DnComponents.GENDER)) { %>
                    if(!checkfieldforgender("document.adduser.<%= TEXTFIELD_SUBJECTDIRATTR+i %>", "<%= ejbcawebbean.getText("ONLYMORFINGENDERFIELD") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype)) %>"))
                        illegalfields++;
                <%  if(profile.isRequired(fieldtype, fielddata[EndEntityProfile.NUMBER])) { %>
                        if(document.adduser.<%= TEXTFIELD_SUBJECTDIRATTR+i %>.value=="") {
                            alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype), true) %>");
                            illegalfields++;
                        }
            <%      }
                } else { %>
                    if(!checkfieldforhexadecimalnumbers("document.adduser.<%= TEXTFIELD_CERTSERIALNUMBER %>", "<%= ejbcawebbean.getText("ONLYHEXINCERTSN") + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype)) %>"))
                        illegalfields++;
                <%  if(profile.isRequired(fieldtype, fielddata[EndEntityProfile.NUMBER])) { %>
                        if(document.adduser.<%= TEXTFIELD_CERTSERIALNUMBER %>.value=="") {
                            alert("<%= ejbcawebbean.getText("YOUAREREQUIRED", true) + " " + ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fieldtype), true) %>");
                            illegalfields++;
                        }
                <%  }
                }
            }
       }

       
       if(profile.getUse(EndEntityProfile.MAXFAILEDLOGINS,0)) { %>
       		if(document.adduser.<%=RADIO_MAXFAILEDLOGINS %>[0].checked == true) {
       			var maxFailedLogins = document.adduser.<%=TEXTFIELD_MAXFAILEDLOGINS %>.value; 
           		if(maxFailedLogins != parseInt(maxFailedLogins) || maxFailedLogins < -1) {
           			alert("<%= ejbcawebbean.getText("REQUIREDMAXFAILEDLOGINS", true) %>");
           			illegalfields++;
           		}
       		}
	<% }
        
       if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
    if(!checkfieldforlegalemailcharswithoutat("document.adduser.<%=TEXTFIELD_EMAIL%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;

    <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.adduser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL", true) %>");
      illegalfields++;
    } 
    <%    }

          if(profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(!checkfieldforlegalemailcharswithoutat("document.adduser.<%=TEXTFIELD_EMAILDOMAIN%>","<%= ejbcawebbean.getText("ONLYEMAILCHARSNOAT") %>"))
      illegalfields++;
          
      <%  if(profile.isRequired(EndEntityProfile.EMAIL,0)){%>
    if((document.adduser.<%= TEXTFIELD_EMAILDOMAIN %>.value == "")){
      alert("<%= ejbcawebbean.getText("REQUIREDEMAIL", true) %>");
      illegalfields++;
    } 
    <%    }
        }
      }
       
       if (profile.isCabfOrganizationIdentifierUsed() && profile.isCabfOrganizationIdentifierRequired()) { %>
         if((document.adduser.<%= TEXTFIELD_CABFORGANIZATIONIDENTIFIER %>.value == "")){
	        alert("<%= ejbcawebbean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED", true) %>");
	        illegalfields++;
	      }
     <% }
       
       if(profile.getUse(EndEntityProfile.CARDNUMBER,0)){ %>
      <%  if(profile.isRequired(EndEntityProfile.CARDNUMBER,0)){%>
       if((document.adduser.<%= TEXTFIELD_CARDNUMBER %>.value == "")){
         alert("<%= ejbcawebbean.getText("REQUIREDCARDNUMBER", true) %>");
         illegalfields++;
       } 
       <%    }
             if(profile.isModifyable(EndEntityProfile.CARDNUMBER,0)){%>
         <%  if(profile.isRequired(EndEntityProfile.CARDNUMBER,0)){%>
       if((document.adduser.<%= TEXTFIELD_CARDNUMBER %>.value == "")){
         alert("<%= ejbcawebbean.getText("REQUIREDCARDNUMBER", true) %>");
         illegalfields++;
       } 
       <%    }
           }
         }
 
       if (!profile.useAutoGeneratedPasswd()) {
         if (profile.isPasswordModifiable()) { %>
    if(document.adduser.<%= TEXTFIELD_PASSWORD %>.value != document.adduser.<%= TEXTFIELD_CONFIRMPASSWORD %>.value){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH", true) %>");
      illegalfields++;
    } 
    <%   }else{ %>
    if(document.adduser.<%=SELECT_PASSWORD%>.options.selectedIndex != document.adduser.<%=SELECT_CONFIRMPASSWORD%>.options.selectedIndex ){
      alert("<%= ejbcawebbean.getText("PASSWORDSDOESNTMATCH", true) %>");
      illegalfields++; 
    }
<%        }   
     } %>
    if(document.adduser.<%=SELECT_CERTIFICATEPROFILE%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CERTIFICATEPROFILEMUST", true) %>");
      illegalfields++;
    }
    if(document.adduser.<%=SELECT_CA%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("CAMUST", true) %>");
      illegalfields++;
    }
    if(document.adduser.<%=SELECT_TOKEN%>.options.selectedIndex == -1){
      alert("<%=  ejbcawebbean.getText("TOKENMUST", true) %>");
      illegalfields++;
    }

    <% if(profile.getUse(EndEntityProfile.CARDNUMBER,0) ){%>
    if(!checkfieldfordecimalnumbers("document.adduser.<%=TEXTFIELD_CARDNUMBER%>", "<%= ejbcawebbean.getText("CARDNUMBER_MUSTBE", true) %>"))       
      illegalfields++;
  <% } %>


    <%  if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0) && profile.isModifyable(EndEntityProfile.EMAIL,0)){%>
    if(document.adduser.<%=CHECKBOX_SENDNOTIFICATION %>.checked && (document.adduser.<%= TEXTFIELD_EMAIL %>.value == "")){
      alert("<%= ejbcawebbean.getText("NOTIFICATIONADDRESSMUSTBE", true) %>");
      illegalfields++;
    } 
    <% } %>

    if(illegalfields == 0){
      <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%> 
      document.adduser.<%= CHECKBOX_CLEARTEXTPASSWORD %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.KEYRECOVERABLE,0) && globalconfiguration.getEnableKeyRecovery()){%> 
      document.adduser.<%= CHECKBOX_KEYRECOVERABLE %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.CARDNUMBER,0)){%> 
      document.adduser.<%= TEXTFIELD_CARDNUMBER %>.disabled = false;
      <% } if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){%> 
      document.adduser.<%= CHECKBOX_SENDNOTIFICATION %>.disabled = false;
      <% } if(profile.getUsePrinting()){%> 
      document.adduser.<%= CHECKBOX_PRINT %>.disabled = false;
      <% }%>
    }

     return illegalfields == 0;  
}
  <% } %>

   function maxFailedLoginsUnlimited() {
		document.adduser.<%= TEXTFIELD_MAXFAILEDLOGINS %>.disabled = true;
   }

   function maxFailedLoginsSpecified() {
		document.adduser.<%= TEXTFIELD_MAXFAILEDLOGINS %>.disabled = false;
   }

   function toggleModifySubjectAltName(checkBox, textBoxName) {
       const textBox = document.getElementsByName(textBoxName)[0];
       if(checkBox.checked) {
           textBox.disabled = true;
           textBox.value = "";
       } else {
           textBox.disabled = false;
       }
   }
   
   -->
  </script>
  <script type="text/javascript" src="<%= ejbcawebbean.getAdminWebBaseUrl() %>ejbcajslib.js"></script>
</head>

<body onload='<% if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>
                 fillCAField();'>
  
  <jsp:include page="../adminmenu.jsp" />
  <div class="main-wrapper">
  <div class="container">
  <h1><c:out value="<%= ejbcawebbean.getText(\"ADDENDENTITY\") %>"/></h1>

  <% 
  String formAction = "listendentities.jsp";
  %>
  <% if(noprofiles){ %>
    <div class="message alert"><c:out value="<%=ejbcawebbean.getText(\"NOTAUTHORIZEDTOCREATEENDENTITY\") %>"/></div>
  <% }else{
       if(userexists){ %>
  <div class="message alert"><c:out value="<%=ejbcawebbean.getText(\"ENDENTITYALREADYEXISTS\") %>"/></div>
  <div class="message alert">
    <form action="<%=formAction%>" method="post">
      <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
      <input type="hidden" name="action" value="listusers"/>
      <input type="hidden" name="buttonfind" value="value"/>
      <input type="hidden" name="textfieldusername" value="<%=request.getParameter(TEXTFIELD_USERNAME)%>"/>
      <input type="submit" class="commandLink" value="See existing user">
    </form>  
  </div>
  <% } %>
    <% if(approvalmessage != null){ %>
      <div class="message alert"><c:out value="<%= approvalmessage%>"/></div>
  		<% if(approvalmessage.equals(ejbcawebbean.getText("SERIALNUMBERALREADYEXISTS"))){ %>
	  <div class="message alert">
	    <form action="<%=formAction%>" method="post">
	      <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
	      <input type="hidden" name="action" value="listusers"/>
	      <input type="hidden" name="buttonadvancedlist" value="value"/>
	      <input type="hidden" name="selectmatchwithrow1" value="<%=UserMatch.MATCH_WITH_DNSERIALNUMBER%>"/>
	      <input type="hidden" name="selectmatchtyperow1" value="<%=BasicMatch.MATCH_TYPE_EQUALS%>"/>
	      <input type="hidden" name="textfieldmatchvaluerow1" value="serialnumber%>"/>
	      <input type="submit" class="commandLink" value="See existing user">
	    </form>  
	  </div>
  		<% } %>
  <% } %>
  <% if(useradded){ %>
  <div class="message info"><c:out value="<%= ejbcawebbean.getText(\"ENDENTITY\")+ \" \" + addedusername + \" \" + ejbcawebbean.getText(\"ADDEDSUCCESSFULLY\") %>"/></div>
  <% } %>


     <table class="edit" id="addendentity" border="0" cellpadding="0" cellspacing="2">
       <form name="changeprofile" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
       <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHANGEPROFILE %>'>

     <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(\"ENDENTITYPROFILE\") %>"/></td>
	 <td><select name="<%=SELECT_ENDENTITYPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange="document.changeprofile.submit()">
                <% for(int i = 0; i < profilenames.length;i++){
                      int pid = rabean.getEndEntityProfileId(profilenames[i]);
                      %>                
	 	<option value='<c:out value="<%=pid %>"/>' <% if(pid == profileid)
                                             out.write("selected"); %>>
 
                         <c:out value="<%= profilenames[i] %>"/>
                </option>
                <% } %>
	     </select>
         </td>
	<td><c:out value="<%= ejbcawebbean.getText(\"REQUIRED\") %>"/></td>
      </tr>
      </form>

       <form name="adduser" action="<%= THIS_FILENAME %>" method="post">
         <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
         <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_ADDUSER %>'>   
         <input type="hidden" name='<%= HIDDEN_PROFILE %>' value='<c:out value="<%=profileid %>"/>'>    


    <!-- ---------- Main -------------------- -->

      <tr id="Row<%=(row++)%2%>">
	<td align="right"><strong><c:out value="<%= ejbcawebbean.getText(\"USERNAME\") %>"/></strong></td> 
	<td>
            <%if (profile.isAutoGeneratedUsername()){%>
            <input type="text" name="<%= TEXTFIELD_USERNAME %>" disabled="disabled" size="40" maxlength="255" tabindex="<%=tabindex++%>" value='<c:out value="<%= profile.getUsernameDefault() %>"/>' title="<%= ejbcawebbean.getText("USERNAMEWILLBEAUTOGENERATED") %>">	
            <%}else{ %>
            <input type="text" size="40" maxlength="255"
                   name="<%= TEXTFIELD_USERNAME %>" tabindex="<%=tabindex++%>"
                   value='<c:out value="<%= profile.getUsernameDefault() %>"/>'

                    <% if (profile.getUseValidationForUsername()) {
                        final String usernameRegex = profile.getUsernameDefaultValidation();
                    %>
                        pattern="<c:out value='<%=usernameRegex%>'/>"
                        title="Must match format specified in profile. / Technical detail - the regex is <c:out value='<%=usernameRegex%>'/>"
                   <% } else { %>
                        title="<%= ejbcawebbean.getText("FORMAT_ID_STR") %>"
                   <% } %> />
          	<% } %>
    </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_USERNAME %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if (profile.isUsernameRequired()) out.write(" CHECKED "); %>></td>
      </tr>

          <% if (!profile.useAutoGeneratedPasswd()){ %>
      <tr id="Row<%=(row)%2%>">
		<td align="right"><c:out value="<%= ejbcawebbean.getText(\"PASSWORDORENROLLMENTCODE\") %>"/></td>
        <td>   
        	<input type="password" autocomplete="off" name="<%= TEXTFIELD_PASSWORD %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value=''> 
        	<% if(profile.isPasswordPreDefined()){ %>
        		<i><c:out value="<%= ejbcawebbean.getText(\"PASSWORD_DEFINED_IN_PROFILE\") %>"/></i>
        	<% } %>
        </td>
		<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_PASSWORD %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if (profile.isPasswordRequired()) out.write(" CHECKED "); %>></td>
      </tr>
      <tr id="Row<%=(row++)%2%>">
	<td align="right"><c:out value="<%= ejbcawebbean.getText(\"CONFIRMPASSWORD\") %>"/></td>
        <td>        
        	<input type="password" autocomplete="off" name="<%= TEXTFIELD_CONFIRMPASSWORD %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value=''>
        </td>
		<td>&nbsp;</td> 
      </tr>
      <% } %>

      <% if(profile.getUse(EndEntityProfile.MAXFAILEDLOGINS,0)) { %>
      <tr id="Row<%=(row++)%2%>">
		<td align="right"><c:out value="<%= ejbcawebbean.getText(\"MAXFAILEDLOGINATTEMPTS\") %>"/></td>
        <td>
        	<%
       			int maxLoginAttempts = -1;
        		try {
        			maxLoginAttempts = Integer.parseInt(profile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0));
        		} catch(NumberFormatException ignored) {}
       		%>   
       		 <input type="radio" name="<%= RADIO_MAXFAILEDLOGINS %>" value="<%= RADIO_MAXFAILEDLOGINS_VAL_SPECIFIED %>" onclick="maxFailedLoginsSpecified()" <% if(maxLoginAttempts != -1) { out.write("checked"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write("readonly"); } %>>
             <input type="text" name="<%= TEXTFIELD_MAXFAILEDLOGINS %>" size="5" maxlength="255" tabindex="<%=tabindex++%>" value='<% if(maxLoginAttempts != -1) { out.write(""+maxLoginAttempts); } %>' <% if(maxLoginAttempts == -1) { out.write("disabled"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write(" readonly"); } %> title="<%= ejbcawebbean.getText("FORMAT_INTEGER") %>">
             
             <input type="radio" name="<%= RADIO_MAXFAILEDLOGINS %>" value="<%= RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED %>" onclick="maxFailedLoginsUnlimited()" <% if(maxLoginAttempts == -1) { out.write("checked"); } %> <% if(!profile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0)) { out.write(" readonly"); } %>
             id="<%=RADIO_MAXFAILEDLOGINS%>unlimited">
             <label for="<%=RADIO_MAXFAILEDLOGINS%>unlimited"><%= ejbcawebbean.getText("UNLIMITED") %></label>
        </td>
		<td>&nbsp;</td> 
      </tr>
      <% } %>

    <% if(profile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0)){%>
    <tr id="Row<%=(row++)%2%>">
	<td align="right"><c:out value="<%= ejbcawebbean.getText(\"USEINBATCH\") %>"/></td>
	<td><input type="checkbox" name="<%= CHECKBOX_CLEARTEXTPASSWORD %>" value="<%= CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
            id="<%=CHECKBOX_CLEARTEXTPASSWORD%>">
            <label for="<%=CHECKBOX_CLEARTEXTPASSWORD%>"><c:out value="<%= ejbcawebbean.getText(\"USE\") %>" /></label>
        </td>
	<td>&nbsp;</td> 
    </tr>
    <% } %>

    <%	if(profile.getUse(EndEntityProfile.EMAIL,0)){ %>
    <tr id="Row<%=(row++)%2%>">
	<td align="right"><c:out value="<%= ejbcawebbean.getText(\"EMAIL\") %>"/></td>
	<td>      
           <input type="text" name="<%= TEXTFIELD_EMAIL %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value='<c:out value="<%=oldemail%>"/>'> @
          <% if(!profile.isModifyable(EndEntityProfile.EMAIL,0)){ 
                 String[] options = profile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
               %>
              <% if( options == null ){ %>
                   <input type="hidden" name="<%= SELECT_EMAILDOMAIN %>" value="" />
                   &nbsp;
              <% }else{ %> 
                <% if( options.length == 1 ){ %>
                   <input type="hidden" name="<%= SELECT_EMAILDOMAIN %>" value="<c:out value='<%=options[0].trim()%>'/>" />
                   <strong><c:out value='<%=options[0].trim()%>'/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_EMAILDOMAIN %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int i=0;i < options.length;i++){ %>
                       <option value="<c:out value='<%=options[i].trim()%>'/>" <% if(lastselectedemaildomain.equals(options[i])) out.write(" selected "); %>>
                         <c:out value='<%=options[i].trim()%>'/>
                       </option>                
                     <% } %>
                   </select>
                <% } %>
              <% } %>
           <% }else{ %> 
             <input type="text" name="<%= TEXTFIELD_EMAILDOMAIN %>" size="15" maxlength="255" tabindex="<%=tabindex++%>"  value='<c:out value="<%= profile.getValue(EndEntityProfile.EMAIL,0) %>"/>' title="<%= ejbcawebbean.getText("FORMAT_DOMAINNAME") %>">
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_EMAIL %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(EndEntityProfile.EMAIL,0)) out.write(" CHECKED "); %>></td>
    </tr>
    <%	} %>


    <!-- ---------- Subject DN attributes -------------------- -->

    <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right">
	  <strong><c:out value="<%= ejbcawebbean.getText(\"CERT_SUBJECTDN_ATTRIBUTES\") %>"/></strong>
	</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
    </tr>

       <% int numberofsubjectdnfields = profile.getSubjectDNFieldOrderLength();
          for(int i=0; i < numberofsubjectdnfields; i++){
            fielddata = profile.getSubjectDNFieldsInOrder(i);  %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"/></td>
	 <td>      
          <% 
             if( !EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS) ){  
                if(!profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])){ 
                 String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
               %>
              <% if( options == null ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDN + i %>" value="" />
                   &nbsp;
              <% }else{ %> 
                <% if( options.length == 1 ){ %>
                   <input type="hidden" name="<%= SELECT_SUBJECTDN + i %>" value="<c:out value='<%=options[0].trim()%>'/>" />
                   <strong class="attribute"><c:out value='<%=options[0].trim()%>'/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_SUBJECTDN + i %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int j=0;j < options.length;j++){ %>
                       <option value="<c:out value='<%=options[j].trim()%>'/>" <% if( lastselectedsubjectdns != null && lastselectedsubjectdns[i] != null) 
                                                         if(lastselectedsubjectdns[i].equals(options[j])) out.write(" selected "); %>>
                         <c:out value='<%=options[j].trim()%>'/>
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
                    value="<c:out value="<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>"/>"
                    <% if (regex != null) { %>pattern="<c:out value='<%=regex%>'/>" title="Must match format specified in profile. / Technical detail - the regex is <c:out value='<%=regex%>'/>"<% } %> />
           <% }
            }
            else{ %>
        <input type="checkbox" name="<%=CHECKBOX_SUBJECTDN + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
            id="<%=CHECKBOX_SUBJECTDN + i%>">
            <label for="<%=CHECKBOX_SUBJECTDN + i%>"><c:out value="<%= ejbcawebbean.getText(\"USESEMAILFIELDDATA\") %>"/></label>
         <% } %>       
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTDN + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <% } %>


    <!-- ---------- Other subject attributes -------------------- -->

    <%  
        int numberofsubjectaltnamefields = profile.getSubjectAltNameFieldOrderLength();
		int numberofsubjectdirattrfields = profile.getSubjectDirAttrFieldOrderLength();
    %>
	<%	if ( numberofsubjectaltnamefields > 0
		  || numberofsubjectdirattrfields > 0
		   ) { %>
	    <tr id="Row<%=(row++)%2%>" class="section">
		<td align="right">
		  <strong><c:out value="<%= ejbcawebbean.getText(\"OTHERSUBJECTATTR\") %>"/></strong>
		</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
	    </tr>
	<%	} %>

    <%  
        if(numberofsubjectaltnamefields > 0){
    %> 
    <tr id="Row<%=(row++)%2%>">
	<td align="right">
      <strong><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_SUBJECTALTNAME\") %>"/></strong>
    </td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
    </tr>
       <% } %>

       <% for(int i=0; i < numberofsubjectaltnamefields; i++){
            fielddata = profile.getSubjectAltNameFieldsInOrder(i);  
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
            if(EndEntityProfile.isFieldImplemented(fieldtype)) { %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"/></td>
	 <td>      
		<%	if( EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME ) ) {
				// Handle RFC822NAME separately
            	if ( profile.getUse(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) ) { %>
					<input type="checkbox" name="<%=CHECKBOX_SUBJECTALTNAME + i%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>"
					<%	if ( profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) ) { %>
							CHECKED disabled="disabled"
					<%	} %> id="<%=CHECKBOX_SUBJECTALTNAME + i%>">
					<label for="<%=CHECKBOX_SUBJECTALTNAME + i%>"><c:out value="<%= ejbcawebbean.getText(\"USESEMAILFIELDDATA\") %>"/></label>
            <%	} else {
            		String rfc822NameString = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
            		String[] rfc822NameArray = new String[2];
            		if ( rfc822NameString.indexOf("@") != -1 ) {
            			rfc822NameArray = rfc822NameString.split("@");
            		} else {
	            		rfc822NameArray[0] = "";
            			rfc822NameArray[1] = rfc822NameString;
            		} 
            		boolean modifyable = profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
            		if (!(!modifyable && rfc822NameString.contains("@"))) {
            		%>
					<input type="text" name="<%= TEXTFIELD_RFC822NAME+i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>"
						value='<c:out value="<%= rfc822NameArray[0] %>"/>' /> @
				<%	}
            		if ( modifyable ) { %>
					<input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="15" maxlength="255" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_DOMAINNAME") %>"
						value='<c:out value="<%= rfc822NameArray[1] %>"/>' />
				<%	} else {
						String[] options = rfc822NameString.split(EndEntityProfile.SPLITCHAR); %>
		              <% if( options == null || options.length <= 0 ){ %>
		                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="" />
		                   &nbsp;
		              <% }else{ %> 
		                <% if( options.length == 1 ){ %>
		                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="<c:out value='<%=options[0].trim()%>'/>" />
		                   <strong><c:out value='<%=options[0].trim()%>'/></strong>
		                <% }else{ %> 
		                   <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
		                     <% for(int j=0;j < options.length;j++){ %>
		                       <option value="<c:out value='<%=options[j].trim()%>'/>"
		                       <% if ( lastselectedsubjectaltnames != null && lastselectedsubjectaltnames[i] != null &&
										lastselectedsubjectaltnames[i].equals(options[j]) ) out.write(" selected "); %>>
		                         <c:out value='<%=options[j].trim()%>'/>
		                       </option>                
		                     <% } %>
		                   </select>
		                <% } %>
		              <% } %>
	             <% } %>
			<%	}
		} else {
				// Handle all non-RFC822NAME-fields
				if ( !profile.isModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) ) {
					// Display fixed subject altname fields
					String[] options = profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
					if ( EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN) ) { %>
						<input type="text" name="<%= TEXTFIELD_UPNNAME+i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" /> @
				<%	} %>
	            <%  if( options == null || options.length <= 0 ) { %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="" />
	                   &nbsp;
	            <%  } else { %> 
	              <%  if( options.length == 1 ) { %>
	                   <input type="hidden" name="<%= SELECT_SUBJECTALTNAME + i %>" value="<c:out value='<%=options[0].trim()%>'/>" />
	                   <strong><c:out value='<%=options[0].trim()%>'/></strong>
	              <%  } else { %> 
	                   <select name="<%= SELECT_SUBJECTALTNAME + i %>" size="1" tabindex="<%=tabindex++%>">
	                   <%  for(int j=0;j < options.length;j++) { %>
	                       <option value="<c:out value='<%=options[j].trim()%>'/>"
							<%	if ( lastselectedsubjectaltnames != null &&  lastselectedsubjectaltnames[i] != null) {
									if ( lastselectedsubjectaltnames[i].equals(options[j])) {
										out.write(" selected ");
									}
								} %> >
	                         <c:out value='<%=options[j].trim()%>'/>
	                       </option>                
	                   <%  } %>
	                   </select>
	              <%  } %>
	            <%  } %>
			<%	} else {
					// Display modifyable subject altname fields
	               	if(EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) { %>
						<input type="text" name="<%= TEXTFIELD_UPNNAME+i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" > @
						<input type="text" name="<%= TEXTFIELD_SUBJECTALTNAME + i %>" size="15" maxlength="255" tabindex="<%=tabindex++%>" value='<c:out value="<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>"/>' title="<%= ejbcawebbean.getText("FORMAT_DOMAINNAME") %>">
				<%	} else {
                        String disabled = "";
	               	    if(profile.getCopy(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])
                                && EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNSNAME)) {
	               	        disabled = "hidden";
                            %>
                            <input
                                type="checkbox"
                                id="<%= CHECKBOX_SUBJECTALTNAME_DNS + i %>"
                                onchange="toggleModifySubjectAltName(this, '<%= TEXTFIELD_SUBJECTALTNAME + i %>')"
                                checked disabled>
                            <label for="<%= CHECKBOX_SUBJECTALTNAME_DNS + i %>">Use entity CN</label><br />
                        <% }
				        final Map<String,Serializable> validation = profile.getValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                        final String regex = (validation != null ? (String)validation.get(RegexFieldValidator.class.getName()) : null); %>
                        <input type="text"
                               name="<%= TEXTFIELD_SUBJECTALTNAME + i %>"
                               size="40"
                               maxlength="355"
                               tabindex="<%=tabindex++%>"
                               value="<c:out value="<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>"/>"
                               <%=disabled%>
                               <% if (regex != null) { %>pattern="<c:out value='<%=regex%>'/>" title="Must match format specified in profile. / Technical detail - the regex is <c:out value='<%=regex%>'/>"<% } %> />
				<%	} %>
			<%	} %>
		<%	} %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTALTNAME + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%  } %>
   <%  } %>

    <%  
        if(numberofsubjectdirattrfields > 0){
    %> 
    <tr id="Row<%=(row++)%2%>">
	<td align="right">
	   <strong><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_SUBJECTDIRATTRS\") %>"/></strong>
	</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
    </tr>
       <% } %>
       <% for(int i=0; i < numberofsubjectdirattrfields; i++){
            fielddata = profile.getSubjectDirAttrFieldsInOrder(i);  
            int fieldtype = fielddata[EndEntityProfile.FIELDTYPE];
			{ %>
       <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(DnComponents.getLanguageConstantFromProfileId(fielddata[EndEntityProfile.FIELDTYPE])) %>"/></td>
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
                   <input type="hidden" name="<%= SELECT_SUBJECTDIRATTR + i %>" value="<c:out value='<%=options[0].trim()%>'/>" />
                   <strong><c:out value='<%=options[0].trim()%>'/></strong>
                <% }else{ %> 
                   <select name="<%= SELECT_SUBJECTDIRATTR + i %>" size="1" tabindex="<%=tabindex++%>">
                     <% for(int j=0;j < options.length;j++){ %>
                       <option value="<c:out value='<%=options[j].trim()%>'/>"
                       		<% if( lastselectedsubjectdirattrs != null &&  lastselectedsubjectdirattrs[i] != null) 
                        			if(lastselectedsubjectdirattrs[i].equals(options[j])) out.write(" selected "); %>>
                         <c:out value='<%=options[j].trim()%>'/>
                       </option>                
                     <% } %>
                   </select>
                <% } %>
              <% } %>
           <% } else { %> 
             <input type="text" name="<%= TEXTFIELD_SUBJECTDIRATTR + i %>" size="20" maxlength="255" tabindex="<%=tabindex++%>" value='<c:out value="<%= profile.getValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]) %>"/>'>
           <% } %>
        </td>
	<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_SUBJECTDIRATTR + i %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if(profile.isRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER])) out.write(" CHECKED "); %>></td>
      </tr>
     <%  } %>
	<%	} %>


    <!-- ---------- Main certificate data -------------------- -->

    <tr id="Row<%=(row++)%2%>" class="section">
	<td align="right">
	  <strong><c:out value="<%= ejbcawebbean.getText(\"MAINCERTIFICATEDATA\") %>"/></strong>
	</td>
	<td>&nbsp;</td>
	<td>&nbsp;</td>
    </tr>

     <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(\"CERTIFICATEPROFILE\") %>"/></td>
	 <td>
         <select name="<%= SELECT_CERTIFICATEPROFILE %>" size="1" tabindex="<%=tabindex++%>" onchange='fillCAField()'>
         <%
           String[] availablecertprofiles = profile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
           if(lastselectedcertificateprofile.equals(""))
             lastselectedcertificateprofile= profile.getValue(EndEntityProfile.DEFAULTCERTPROFILE,0);

           if( availablecertprofiles != null){
             for(int i =0; i< availablecertprofiles.length;i++){
         %>
         <option value='<c:out value="<%=availablecertprofiles[i]%>"/>' <% if(lastselectedcertificateprofile.equals(availablecertprofiles[i])) out.write(" selected "); %> >
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
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(\"CA\") %>"/></td>
	 <td>
         <select name="<%= SELECT_CA %>" size="1" tabindex="<%=tabindex++%>">
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="disabled" CHECKED></td>
     </tr>

     <tr id="Row<%=(row++)%2%>">
	 <td align="right"><c:out value="<%= ejbcawebbean.getText(\"TOKEN\") %>"/></td>
	 <td>
         <select name="<%= SELECT_TOKEN %>" size="1" tabindex="<%=tabindex++%>" onchange='<% if(usekeyrecovery) out.write(" isKeyRecoveryPossible();");%>'>
         <%
           if(lastselectedtoken.equals(""))
             lastselectedtoken= profile.getValue(EndEntityProfile.DEFKEYSTORE,0);

           if( availabletokens != null){
             for(int i =0; i < availabletokens.length;i++){
         %>
         <option value='<c:out value="<%=availabletokens[i]%>"/>' <% if(lastselectedtoken.equals(availabletokens[i])) out.write(" selected "); %> >
            <% for(int j=0; j < tokentexts.length; j++){
                 if( tokenids[j] == Integer.parseInt(availabletokens[i])) {
                   if( tokenids[j] > SecConst.TOKEN_SOFT)
                     out.write(tokentexts[j]);
                   else
                     out.write(ejbcawebbean.getText(tokentexts[j]));
                 }
               }%>
         </option>
         <%
             }
           }
         %>
         </select>
         </td>
	 <td><input type="checkbox" name="checkbox" value="true"  disabled="disabled" CHECKED></td>
     </tr>

    <!-- ---------- Other certificate data -------------------- -->

	<%	if ( profile.isCustomSerialNumberUsed()
		  || profile.isValidityStartTimeUsed()
		  || profile.isValidityEndTimeUsed()
		  || profile.isCardNumberUsed()
		  || profile.isNameConstraintsPermittedUsed()
		  || profile.isNameConstraintsExcludedUsed()
		  || profile.isPsd2QcStatementUsed()
		  || profile.isCabfOrganizationIdentifierUsed()
		   ) { %>
	    <tr id="Row<%=(row++)%2%>" class="section">
		<td align="right">
		  <strong><c:out value="<%= ejbcawebbean.getText(\"OTHERCERTIFICATEDATA\") %>"/></strong>
		</td>
		<td>&nbsp;</td>
		<td>&nbsp;</td>
	    </tr>
	<%	} %>

	<%	if (profile.isCustomSerialNumberUsed()) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<c:out value="<%= ejbcawebbean.getText(\"CERT_SERIALNUMBER_HEXA\") %>"/>
				<p class="help">(<c:out value="<%= ejbcawebbean.getText(\"EXAMPLE\").toLowerCase() %>"/> : 1234567890ABCDEF)</p>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_CERTSERIALNUMBER %>" size="20" maxlength="40" tabindex="<%=tabindex++%>" value="" title="<%= ejbcawebbean.getText("FORMAT_HEXA") %>" class="hexa" />
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_CERTSERIALNUMBER %>" value="<%= CHECKBOX_VALUE %>" disabled="disabled" />
			</td>
		</tr>
	<%	} %> 

    <%	if (profile.isValidityStartTimeUsed()) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("TIMEOFSTART") %> <%= ejbcawebbean.getHelpReference("/End_Entity_Profiles.html#Certificate_Validity") %>
				<p class="help">(<%= ejbcawebbean.getText("DATE_HELP") %> <%= ejbcawebbean.getDateExample()
				%> <%= ejbcawebbean.getText("OR").toLowerCase() %> <%= ejbcawebbean.getText("DAYS").toLowerCase()
				%>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)</p>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_STARTTIME %>" size="25" maxlength="40" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_ISO8601") %> <%= ejbcawebbean.getText("OR") %> (<%= ejbcawebbean.getText("DAYS").toLowerCase() %>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)"
					<% String str = profile.getValidityStartTime();	
					String startTime = "";
					if (str != null && str.trim().length() > 0) {
						startTime = ejbcawebbean.getISO8601FromImpliedUTCOrRelative(str); 
					} %>
					value='<c:out value="<%= startTime %>"/>'
					<%	if (!profile.isValidityStartTimeModifiable()) { %>
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

    <%	if (profile.isValidityEndTimeUsed()) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<%= ejbcawebbean.getText("TIMEOFEND") %> <%= ejbcawebbean.getHelpReference("/End_Entity_Profiles.html#Certificate_Validity") %>
				<p class="help">(<%= ejbcawebbean.getText("DATE_HELP") %> <%= ejbcawebbean.getDateExample() 
				%> <%= ejbcawebbean.getText("OR").toLowerCase() %> <%= ejbcawebbean.getText("DAYS").toLowerCase()
				%>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)</p>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_ENDTIME %>" size="25" maxlength="40" tabindex="<%=tabindex++%>" title="<%= ejbcawebbean.getText("FORMAT_ISO8601") %> <%= ejbcawebbean.getText("OR") %> (<%= ejbcawebbean.getText("DAYS").toLowerCase() %>:<%= ejbcawebbean.getText("HOURS").toLowerCase() %>:<%= ejbcawebbean.getText("MINUTES").toLowerCase() %>)"
					<% String str = profile.getValidityEndTime();	
					String endTime = "";
					if (str != null && str.trim().length() > 0) {
						endTime = ejbcawebbean.getISO8601FromImpliedUTCOrRelative(str); 
					} %>
					value='<c:out value="<%= endTime %>"/>'
					<% if (!profile.isValidityEndTimeModifiable()) { %>
					readonly="true"
					<% } %>
					/>
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_ENDTIME %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled"
				<%	if (profile.isRequired(EndEntityProfile.ENDTIME, 0) ) {
						out.write(" CHECKED ");
					} %>
				/>
			</td>
		</tr>
	<%	} %>

	<%	if (profile.isCardNumberUsed()) { %>
		<tr id="Row<%=(row++)%2%>">
			<td align="right"><c:out value="<%= ejbcawebbean.getText(\"CARDNUMBER\") %>"/></td>
			<td>
				<input type="text" name="<%= TEXTFIELD_CARDNUMBER %>" size="20" maxlength="40" tabindex="<%=tabindex++%>" value='<c:out value="<%=oldcardnumber%>"/>' title="<%= ejbcawebbean.getText("FORMAT_STRING") %>">
			</td>
			<td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_CARDNUMBER %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if (profile.isCardNumberRequired()) out.write(" CHECKED "); %>></td>
		</tr>
	<%	} %>
	
	<% if (profile.isNameConstraintsPermittedUsed()) { %>
        <tr id="Row<%=(row)%2%>">
            <td align="right">
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED\") %>"/>
                <%= ejbcawebbean.getHelpReference("/CA_Fields.html#Name_Constraints") %>
                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED_HELP1\") %>"/><br />
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED_HELP2\") %>"/><br />
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_PERMITTED_HELP3\") %>"/></p>
            </td>
            <td>
                <textarea name="<%=TEXTAREA_NC_PERMITTED%>" rows="4" cols="38" tabindex="<%=tabindex++%>"></textarea>
            </td>
            <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_NC_PERMITTED %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if (profile.isNameConstraintsPermittedRequired()) out.write(" CHECKED "); %>></td>
        </tr>
    <% } %>
    <% if (profile.isNameConstraintsExcludedUsed()) { %>
        <tr id="Row<%=(row++)%2%>">
            <td align="right">
                <c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_EXCLUDED\") %>"/>
                <%= ejbcawebbean.getHelpReference("/CA_Fields.html#Name_Constraints") %>

                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_EXCLUDED_HELP1\") %>"/></p>
                <br/>
                <p class="help"><c:out value="<%= ejbcawebbean.getText(\"EXT_PKIX_NC_EXCLUDED_HELP2\") %>"/></p>
            </td>
            <td>
                <textarea name="<%=TEXTAREA_NC_EXCLUDED%>" rows="4" cols="38" tabindex="<%=tabindex++%>"></textarea>
            </td>
            <td><input type="checkbox" name="<%= CHECKBOX_REQUIRED_NC_EXCLUDED %>" value="<%= CHECKBOX_VALUE %>"  disabled="disabled" <% if (profile.isNameConstraintsExcludedRequired()) out.write(" CHECKED "); %>></td>
        </tr>
    <%  } %>

   	<% if (profile.getUseExtensiondata()) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<c:out value="<%= ejbcawebbean.getText(\"CERT_EXTENSIONDATA\") %>"/>
			</td><td> 
				<textarea name="<%=TEXTAREA_EXTENSIONDATA%>" rows="4" cols="38"><c:if test="${!useradded}"><c:out value="${editendentitybean.extensionData}"/></c:if></textarea>
			</td>
			<td>
				<input type="checkbox" name="<%= CHECKBOX_REQUIRED_EXTENSIONDATA %>" value="<%= CHECKBOX_VALUE %>" disabled="disabled"/>
			</td>
		</tr>
	<%	} %> 
	
	<% if (profile.isPsd2QcStatementUsed()) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<c:out value="<%= ejbcawebbean.getText(\"PSD2_NCANAME\") %>"/>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_NCANAME %>" size="30" maxlength="256" tabindex="<%=tabindex++%>" value="" />
			</td>
			<td>
				<input type="checkbox" value="<%= CHECKBOX_VALUE %>" disabled="disabled"/>
			</td>
		</tr>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<c:out value="<%= ejbcawebbean.getText(\"PSD2_NCAID\") %>"/>
			</td>
			<td> 
				<input type="text" name="<%= TEXTFIELD_NCAID %>" size="30" maxlength="256" tabindex="<%=tabindex++%>" value="" />
			</td>
			<td>
				<input type="checkbox" value="<%= CHECKBOX_VALUE %>" disabled="disabled"/>
			</td>
		</tr>
		
	  <tr  id="Row<%=row++%2%>"> 
      	<td align="right"> 
        	<c:out value="<%= ejbcawebbean.getText(\"PSD2_PSP_ROLES\") %>" />
      	</td>
      	<td width="50%"> 
        	<select class="select-list" name="<%=SELECT_PSD2_PSPROLE%>" size="4" multiple="multiple">
      		   <option value="PSP_AS"><c:out value="<%= ejbcawebbean.getText(\"PSD2_PSP_AS\") %>"/></option>
      		   <option value="PSP_PI"><c:out value="<%= ejbcawebbean.getText(\"PSD2_PSP_PI\") %>"/></option>
      		   <option value="PSP_AI"><c:out value="<%= ejbcawebbean.getText(\"PSD2_PSP_AI\") %>"/></option>
      		   <option value="PSP_IC"><c:out value="<%= ejbcawebbean.getText(\"PSD2_PSP_IC\") %>"/></option>
        	</select>
      	</td>
      	<td>
			<input type="checkbox" value="<%= CHECKBOX_VALUE %>" disabled="disabled"/>
		</td>
    </tr>
	<%	} %> 
	
	<% if (profile.isCabfOrganizationIdentifierUsed()) { %>
		<tr id="Row<%=(row++)%2%>">
			<td align="right">
				<c:out value="<%= ejbcawebbean.getText(\"EXT_CABF_ORGANIZATION_IDENTIFIER\") %>"/>
			</td>
			<td>
				<input type="text" name="<%= TEXTFIELD_CABFORGANIZATIONIDENTIFIER %>" size="30" maxlength="256" tabindex="<%=tabindex++%>"  value="<c:out value="<%=profile.getCabfOrganizationIdentifier()%>"/>"
					<% if (!profile.isCabfOrganizationIdentifierModifiable()) out.write(" readonly=\"true\" "); %>
					pattern="[A-Z0-9]{5,5}(\+[A-Z0-9]+)?-.+" title="<c:out value="<%= ejbcawebbean.getText(\"EXT_CABF_ORGANIZATION_IDENTIFIER_FORMAT\") %>"/>"/>
			</td>
			<td>
				<input type="checkbox" value="<%= CHECKBOX_VALUE %>" disabled="disabled"  <% if (profile.isCabfOrganizationIdentifierRequired()) out.write(" CHECKED "); %>/>
			</td>
		</tr>
	<%	} %>

    <!-- ---------- Other data -------------------- -->

	<%	if ( profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)
		  || usekeyrecovery
		  || profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON,0)
		  || profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)
		  || profile.getUsePrinting()
		   ) { %>
	    <tr id="Row<%=(row++)%2%>" class="section">
	 	<td align="right">
		   <strong><c:out value="<%= ejbcawebbean.getText(\"OTHERDATA\") %>"/></strong>
		 </td>
		 <td>&nbsp;</td>
		 <td>&nbsp;</td>
	    </tr>
	<%	} %>
       
       <!--  Max number of allowed requests for a password -->
       <% if(profile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0)){ %>
       <% 
           String defaultnrofrequests = profile.getValue(EndEntityProfile.ALLOWEDREQUESTS,0);
           if (defaultnrofrequests == null) {
        	   defaultnrofrequests = "1";
           }
       %>
       <tr id="Row<%=(row++)%2%>">
  	   <td align="right"><c:out value="<%= ejbcawebbean.getText(\"ALLOWEDREQUESTS\") %>"/></td>
	   <td>
            <select name="<%=SELECT_ALLOWEDREQUESTS %>" size="1" >
	            <% for(int j=0;j< 6;j++){
	            %>
	            <option
	            <%     if(defaultnrofrequests.equals(Integer.toString(j)))
	                       out.write(" selected "); 
	            %>
	            value='<%=j%>'><%=j%></option>
	            <% }%>
            </select>
       </td>
       <td>&nbsp;</td>
       </tr>
     <% } %>

     <% if(usekeyrecovery){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <c:out value="<%= ejbcawebbean.getText(\"KEYRECOVERABLE\") %>"/>
        <%= ejbcawebbean.getHelpReference("/Key_Recovery.html") %>
      </td>
      <td> 
        <input type="checkbox" name="<%=CHECKBOX_KEYRECOVERABLE%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>"<% if(profile.getValue(EndEntityProfile.KEYRECOVERABLE,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.KEYRECOVERABLE,0))
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
           id="<%=CHECKBOX_KEYRECOVERABLE%>">
           <label for="<%=CHECKBOX_KEYRECOVERABLE%>"><c:out value="<%= ejbcawebbean.getText(\"ACTIVATE\") %>" /></label> 
      </td>
      <td>&nbsp;</td>
    </tr>
     <% } %>

        <% int revstatus = RevokedCertInfo.NOT_REVOKED;
           String value = profile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON ,0);
           if((value != null) && (((String) value).length() > 0)) {
               revstatus = (Integer.valueOf(value).intValue());
           }
        %>
	<% if( profile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) ) { %>
		<tr  id="Row<%=(row++)%2%>"> 
			<td align="right"> 
				<c:out value="<%= ejbcawebbean.getText(\"ISSUANCEREVOCATIONREASON\") %>"/>
			</td>
			<td> 
        <select name="<%= SELECT_ISSUANCEREVOCATIONREASON %>" size="1" 
        	<%	if ( !profile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) ) { %>
			  disabled
		   <% } %>
        >
          <option value='<c:out value="<%= RevokedCertInfo.NOT_REVOKED %>"/>' class="lightgreen" <%
                if(revstatus == RevokedCertInfo.NOT_REVOKED) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"ACTIVE\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD %>"/>' class="lightyellow" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"SUSPENDED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_CERTIFICATEHOLD\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_UNSPECIFIED\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_KEYCOMPROMISE\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_CACOMPROMISE\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_AFFILIATIONCHANGED\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_SUPERSEDED %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_SUPERSEDED) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_SUPERSEDED\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_CESSATIONOFOPERATION\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_PRIVILEGEWITHDRAWN\") %>"/></option>

          <option value='<c:out value="<%= RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE %>"/>' class="lightred" <%
                if(revstatus == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE) out.write(" selected ");
          %>><c:out value="<%= ejbcawebbean.getText(\"REVOKED\") %>"/>: <c:out value="<%= ejbcawebbean.getText(\"REV_AACOMPROMISE\") %>"/></option>
					
        </select>
			</td>
			<td>&nbsp;</td>
		</tr>
	<% } %> 

     <% if(profile.getUse(EndEntityProfile.SENDNOTIFICATION,0)){ %>
    <tr  id="Row<%=(row++)%2%>"> 
      <td  align="right"> 
        <c:out value="<%= ejbcawebbean.getText(\"SENDNOTIFICATION\") %>"/>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_SENDNOTIFICATION%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getValue(EndEntityProfile.SENDNOTIFICATION,0).equals(EndEntityProfile.TRUE))
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.isRequired(EndEntityProfile.SENDNOTIFICATION,0))
                                                                                                                 out.write(" disabled='true' "); 
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
        <c:out value="<%= ejbcawebbean.getText(\"PRINTUSERDATA\") %>"/>
      </td>
      <td > 
        <input type="checkbox" name="<%=CHECKBOX_PRINT%>" value="<%=CHECKBOX_VALUE %>" tabindex="<%=tabindex++%>" <% if(profile.getPrintingDefault())
                                                                                                                 out.write(" CHECKED "); 
                                                                                                               if(profile.getPrintingRequired())
                                                                                                                 out.write(" disabled='true' "); 
                                                                                                             %>
           id="<%=CHECKBOX_PRINT%>">
           <label for="<%=CHECKBOX_PRINT%>"><c:out value="<%= ejbcawebbean.getText(\"PRINT\") %>" /></label>
      </td>
      <td>&nbsp;</td>
    </tr>
	<%	} %>


    <!-- ---------- Form buttons -------------------- -->

	<tr id="Row<%=(row++)%2%>">
	  <td align="right">
	  &nbsp;
	  </td>
	  <td class="padding-top"><input type="submit" name="<%= BUTTON_ADDUSER %>" value='<c:out value="<%= ejbcawebbean.getText(\"ADD\") %>"/>' tabindex="<%=tabindex++%>"
				onClick='return checkallfields()'>
		  &nbsp;&nbsp;&nbsp;
		  <input type="reset" name="<%= BUTTON_RESET %>" value='<c:out value="<%= ejbcawebbean.getText(\"RESET\") %>"/>' tabindex="<%=tabindex++%>"></td>
	  <td>&nbsp;</td>
	</tr>

	</table> 



    <!-- ---------- New end-entities added -------------------- -->

<script type="application/javascript" language="javascript">
<!--
function viewuser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = '<%= VIEWUSER_LINK %>' + encodeURI('?<%= USER_PARAMETER %>=' + username);
    win_popup = window.open(link, 'view_user','height=750,width=750,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function edituser(row){
    var hiddenusernamefield = eval("document.adduser.<%= HIDDEN_USERNAME %>" + row);
    var username = hiddenusernamefield.value;
    var link = '<%= EDITUSER_LINK %>' + encodeURI('?<%= USER_PARAMETER %>=' + username);
    win_popup = window.open(link, 'edit_user','height=750,width=900,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}
-->
</script>

 

  <% if(addedusers == null || addedusers.length == 0){     %>
  <!-- nothing to do -->
  <% } else{ %>
  <div class="message"><strong><c:out value="<%= ejbcawebbean.getText(\"PREVIOUSLYADDEDENDENTITIES\") %>"/></strong></div>
  <div>
    <input type="submit" name="<%=BUTTON_RELOAD %>" value='<c:out value="<%= ejbcawebbean.getText(\"RELOAD\") %>"/>'>
  </div>
  <table class="results" width="100%" border="0" cellspacing="1" cellpadding="0">
  <thead>
  <tr> 
    <th width="20%"><c:out value="<%= ejbcawebbean.getText(\"USERNAME_ABBR\") %>"/></th>
    <th width="20%"><c:out value="<%= ejbcawebbean.getText(\"DN_ABBR_COMMONNAME\") %>"/></th>
    <th width="20%"><c:out value="<%= ejbcawebbean.getText(\"DN_ABBR_ORGANIZATIONALUNIT\") %>"/></th>
    <th width="20%"><c:out value="<%= ejbcawebbean.getText(\"DN_ABBR_ORGANIZATION\") %>"/></th>
    <th width="20%"><c:out value="<%= ejbcawebbean.getText(\"ACTIONS\") %>"/></th>
  </tr>
  </thead>
  
  <tbody>
    <%   for(int i=0; i < addedusers.length; i++){
            if(addedusers[i] != null){ 
      %>
     
  <tr id="Row<%= i%2 %>"> 

    <td width="20%"><c:out value="<%= addedusers[i].getUsername() %>"/>
       <input type="hidden" name='<%= HIDDEN_USERNAME + i %>' value='<c:out value="<%=java.net.URLEncoder.encode(addedusers[i].getUsername(),\"UTF-8\")%>"/>'>
    </td>
    <td width="20%"><c:out value="<%= addedusers[i].getSubjectDNField(DNFieldExtractor.CN,0)  %>"/></td>
    <td width="20%"><c:out value="<%= addedusers[i].getSubjectDNField(DNFieldExtractor.OU,0) %>"/></td>
    <td width="20%"><c:out value="<%= addedusers[i].getSubjectDNField(DNFieldExtractor.O,0) %>"/></td>
    <td width="20%" style='white-space: nowrap;'><div class="button-group">
		<button type='button' onclick='viewuser(<%= i %>)' title='<%= ejbcawebbean.getText("VIEW_ENDENTITY_TITLE") %> <%= ejbcawebbean.getText("POPUP_WINDOW") %>'><c:out value='<%= ejbcawebbean.getText("VIEW") %>' /></button>
		<button type='button' onclick='edituser(<%= i %>)' title='<%= ejbcawebbean.getText("EDIT_ENDENTITY_TITLE") %> <%= ejbcawebbean.getText("POPUP_WINDOW") %>'><c:out value='<%= ejbcawebbean.getText("EDIT") %>' /></button>
    </div></td>

  </tr>
 <%        }
         }
 %>
  </tbody>
  </table>
 <%    }
     }%>
  </form>
  
  </div> <!-- container -->

  <%// Include Footer 
   String footurl =   globalconfiguration .getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />
</div> <!-- main-wrapper -->
<script>
    if (typeof document.addEventListener != 'undefined') {
    	// Standard way of doing it
    	document.addEventListener('load', fillCAField);
    } else if (typeof document.attachEvent != 'undefined') {
    	// IE 6-8
    	document.attachEvent('load', fillCAField);
    }
</script>
</body>
</html>
