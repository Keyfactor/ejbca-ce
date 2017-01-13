<%@page import="org.cesecore.authorization.control.StandardRules"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="
org.cesecore.authorization.AuthorizationDeniedException,
org.cesecore.certificates.ca.CAConstants,
org.cesecore.util.CertTools,
org.ejbca.config.GlobalConfiguration,
org.ejbca.core.model.authorization.AccessRulesConstants,
org.ejbca.ui.web.admin.configuration.EjbcaWebBean,
org.ejbca.ui.web.admin.cainterface.CAInfoView,
org.ejbca.ui.web.admin.cainterface.CAInterfaceBean,
java.security.cert.X509Certificate
"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="viewcainfohelper" scope="session" class="org.ejbca.ui.web.admin.cainterface.ViewCAInfoJSPHelper" />

<%
  // Initialize environment.
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource()); 
                                            cabean.initialize(ejbcawebbean);
  String THIS_FILENAME                    = globalconfiguration.getCaPath()  + "/viewcainfo.jsp";

  final String VIEWCERT_LINK            = ejbcawebbean.getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.jsp";

  viewcainfohelper.initialize(request, ejbcawebbean, cabean);
  viewcainfohelper.parseRequest(request);
  
  int row = 0; 
  int columnwidth = 200;
%>
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <script type="text/javascript" src="<%= globalconfiguration.getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body class="popup" id="viewcainfo">
    <h2><%= ejbcawebbean.getText("CAINFORMATION") %></h2>

    <% if (viewcainfohelper.generalerrormessage != null) { %>
    <div class="message alert"><%=ejbcawebbean.getText(viewcainfohelper.generalerrormessage) %></div> 
    <% } else { %>
    <form name="viewcainfo" action="<%= THIS_FILENAME %>" method="post">
        <input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue/>"/>
        <input type="hidden" name='<%= viewcainfohelper.CA_PARAMETER %>' value='<%=viewcainfohelper.caid %>'>
        <table class="view" border="0" cellpadding="0" cellspacing="2" width="100%">

	    <!-- ---------- Data ---------- -->

        <% for(int i=0; i < viewcainfohelper.cainfo.getCAInfoData().length; i++){ %>
         <tr id="Row<%=(row++)%2%>"<% if(i==0){ %> class="title"<% } %><% if(i==4||i==9||i==15){ %> class="section"<% } %>>
		   <td align="right" width="<%=columnwidth%>"><% if(i==0||i==1||i==4||i==9||i==15){ %><strong><% } %><%= viewcainfohelper.cainfo.getCAInfoDataText()[i] %><% if(i==0||i==1||i==4||i==9||i==15){ %></strong><% } %></td>
		        <td><% if(i==0||i==1){ %><strong><% } %><% 
		        String datatext = viewcainfohelper.cainfo.getCAInfoData()[i];
		        if (datatext == null) {
		            datatext = "";
		        }
			%><%=datatext%><% if(i==0||i==1){ %></strong><% } %></td>
      </tr>    
			<%-- CAInfoView will escape potentially dangerous fields for us
				we can't easily use c:out here, since empty fields will contain "&nbsp;"
				as set by CAInfoView, and I don't want to risk breaking other views by changing that 
				behavior too much... 
			--%>
        <% } %>

        <!-- ---------- Actions ---------- -->

            <tr id="Row<%=(row++)%2%>">
  	            <td align="right" width="<%=columnwidth%>"><%= ejbcawebbean.getText("INCLUDEINHEALTHCHECK") %></td>
        	    <td>
      	            <input type="checkbox" name="<%= viewcainfohelper.CHECKBOX_INCLUDEINHEALTHCHECK %>" value="<%=viewcainfohelper.CHECKBOX_VALUE %>" 
                    <%  if(viewcainfohelper.cainfo.getCAInfo().getIncludeInHealthCheck() ) { out.write(" CHECKED "); } %>
                    disabled >
                </td>
            </tr> 
            <tr id="Row<%=(row++)%2%>">
				<td width="<%=columnwidth%>">
					&nbsp;
				</td>
			    <td align="right" style="vertical-align: bottom;">
		             <input type="button" name="<%= viewcainfohelper.BUTTON_CLOSE %>" value="<%= ejbcawebbean.getText("CLOSE") %>" 
		                    onClick='self.close()'>
		        </td>
            </tr>
        </table> 
    </form>
    <% } %>
</body>
</html>
