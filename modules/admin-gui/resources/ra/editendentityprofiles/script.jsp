<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />

<%! // Declarations
static final String SELECT_DEFAULTCERTPROFILE             = "selectdefaultcertprofile";
static final String SELECT_AVAILABLECERTPROFILES          = "selectavailablecertprofiles";

static final String SELECT_DEFAULTCA                      = "selectdefaultca";
static final String SELECT_AVAILABLECAS                   = "selectavailablecas";
%>

<script type="text/javascript">
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
        if (options[i].value == document.editprofile.<%=SELECT_DEFAULTCA%>.options[selInd].value) {
            existsInAvailable = true;
        }
    }
    if (!existsInAvailable) {
        alert("<%=ejbcawebbean.getText("ADEFAULTCA", true)%>");
        illegalfields++;
    }

    return illegalfields;
}
</script>
