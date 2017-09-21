<%@page import="org.ejbca.core.model.SecConst"%>

<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />

<%! // Declarations
static final String TEXTFIELD_EMAIL                       = "textfieldemail";
static final String TEXTFIELD_SUBJECTDN                   = "textfieldsubjectdn";
static final String TEXTFIELD_SUBJECTALTNAME              = "textfieldsubjectaltname";
static final String TEXTFIELD_SUBJECTDIRATTR              = "textfieldsubjectdirattr";

static final String CHECKBOX_USE_EMAIL                    = "checkboxuseemail";
static final String CHECKBOX_MODIFYABLE_EMAIL             = "checkboxmodifyableemail";
static final String CHECKBOX_REQUIRED_SUBJECTDN           = "checkboxrequiredsubjectdn";
static final String CHECKBOX_REQUIRED_SUBJECTALTNAME      = "checkboxrequiredsubjectaltname";
static final String CHECKBOX_REQUIRED_SUBJECTDIRATTR      = "checkboxrequiredsubjectdirattr";
static final String CHECKBOX_MODIFIABLE_SUBJECTDN         = "checkboxmodifyablesubjectdn";
static final String CHECKBOX_MODIFIABLE_SUBJECTALTNAME    = "checkboxmodifyablesubjectaltname";
static final String CHECKBOX_MODIFIABLE_SUBJECTDIRATTR    = "checkboxmodifyablesubjectdirattr";

static final String SELECT_DEFAULTCERTPROFILE             = "selectdefaultcertprofile";
static final String SELECT_AVAILABLECERTPROFILES          = "selectavailablecertprofiles";

static final String SELECT_DEFAULTCA                      = "selectdefaultca";
static final String SELECT_AVAILABLECAS                   = "selectavailablecas";
%>

<script type="text/javascript">
function checkNonModifiableEmptyEmail() {
    if (document.editprofile.<%= CHECKBOX_USE_EMAIL %>.checked
            && !document.editprofile.<%= CHECKBOX_MODIFYABLE_EMAIL %>.checked
            && document.editprofile.<%= TEXTFIELD_EMAIL %>.value == "") {
        alert("<%=ejbcawebbean.getText("EMAILEMPTYNONMODIFIABLE", true)%>");
        return 1;
    } else {
        return 0;
    }
}

function checkDefaultAmongAvailable() {
    var illegalfields = 0;
    var i;

    // Check that Default Certificate Profile is among Available Certificate Profiles
    var options = document.editprofile.<%=SELECT_AVAILABLECERTPROFILES%>.selectedOptions;
    var selInd = document.editprofile.<%=SELECT_DEFAULTCERTPROFILE%>.options.selectedIndex;
    var existsInAvailable = false;
    for (i = 0; i < options.length; i++) {
        if (options[i].value == document.editprofile.<%=SELECT_DEFAULTCERTPROFILE%>.options[selInd].value) {
            existsInAvailable = true;
        }
    }
    if (!existsInAvailable) {
        alert("<%=ejbcawebbean.getText("ADEFAULTCERTPROFILE", true)%>");
        illegalfields++;
    }

    // Check that Default CA is among Available CAs
    options = document.editprofile.<%=SELECT_AVAILABLECAS%>.selectedOptions;
    selInd = document.editprofile.<%=SELECT_DEFAULTCA%>.options.selectedIndex;
    existsInAvailable = false;
    for (i = 0; i < options.length; i++) {
        if (options[i].value == document.editprofile.<%=SELECT_DEFAULTCA%>.options[selInd].value
                || options[i].value == <%=SecConst.ALLCAS%>) {
            existsInAvailable = true;
        }
    }
    if (!existsInAvailable) {
        alert("<%=ejbcawebbean.getText("ADEFAULTCA", true)%>");
        illegalfields++;
    }

    return illegalfields;
}

function checkNonModifiableRequiredEmptyAttribute(index, textName, requiredName, modifiableName) {
    var text = new String(eval("document.editprofile." + textName + index).value);
    var required = eval("document.editprofile." + requiredName + index).checked;
    var modifiable = eval("document.editprofile." + modifiableName + index).checked;
    return required && !modifiable && text.length === 0;
}

function checkNonModifiableRequiredEmptyAttributes(dnFieldTypes, altNameFieldTypes, dirAttrFieldTypes) {
    var illegalFields = 0;
    // Check Subject DN Attributes
    for (var i = 0; i < dnFieldTypes.length; i++) {
        if (checkNonModifiableRequiredEmptyAttribute(i, "<%= TEXTFIELD_SUBJECTDN %>",
                "<%= CHECKBOX_REQUIRED_SUBJECTDN %>", "<%= CHECKBOX_MODIFIABLE_SUBJECTDN %>")) {
            illegalFields++;
        }
    }
    // Check Subject Alternative Names
    for (var i = 0; i < altNameFieldTypes.length; i++) {
        if (checkNonModifiableRequiredEmptyAttribute(i, "<%= TEXTFIELD_SUBJECTALTNAME %>",
                "<%= CHECKBOX_REQUIRED_SUBJECTALTNAME %>", "<%= CHECKBOX_MODIFIABLE_SUBJECTALTNAME %>")) {
            illegalFields++;
        }
    }
    // Check Subject Directory Attributes
    for (var i = 0; i < dirAttrFieldTypes.length; i++) {
        if (checkNonModifiableRequiredEmptyAttribute(i, "<%= TEXTFIELD_SUBJECTDIRATTR %>",
                "<%= CHECKBOX_REQUIRED_SUBJECTDIRATTR %>", "<%= CHECKBOX_MODIFIABLE_SUBJECTDIRATTR %>")) {
            illegalFields++;
        }
    }
    if (illegalFields > 0) {
        alert("<%= ejbcawebbean.getText("ILLEGALATTRIBUTE", true) %>");
    }
    return illegalFields;
}
</script>
