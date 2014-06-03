<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page pageEncoding="UTF-8"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" %>
<%@page import="java.util.Map" %>
<%@page import="java.util.HashMap" %>
<%@page import="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" %>
<%@page import="org.ejbca.config.GlobalConfiguration" %>
<%@page import="org.ejbca.ui.web.RequestHelper" %>
<%@page import="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" %>
<%@page import="org.ejbca.core.model.authorization.AccessRulesConstants" %>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<html>
<%!
  static final String ACTION="action";
  static final String ACTION_IMPORT_EXPORT="importexportprofiles";
  static final String BUTTON_IMPORT_PROFILES="buttonimportprofiles";
  static final String BUTTON_EXPORT_PROFILES="buttonexportprofiles";
  static final String TEXTFIELD_EXPORT_DESTINATION	="textfieldexportdestination";
  static final String FILE_IMPORTFILE="fileimportfile";
%>
<%
  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.REGULAR_EDITCERTIFICATEPROFILES);
  cabean.initialize(ejbcawebbean);
  String THIS_FILENAME = globalconfiguration.getCaPath()+"/editcertificateprofiles/importexport.jsp";
%>
<head>
  <title><c:out value="<%=globalconfiguration.getEjbcaTitle()%>" /></title>
  <base href="<%=ejbcawebbean.getBaseUrl()%>"/>
  <link rel="stylesheet" type="text/css" href="<%=ejbcawebbean.getCssFile()%>"/>
  <script type="text/javascript" src="<%=globalconfiguration.getAdminWebPath()%>ejbcajslib.js"></script>
</head>
<body>
<%
  RequestHelper.setDefaultCharacterEncoding(request);
  Map<String,String> requestMap = new HashMap<String,String>();
  byte[] filebuffer = cabean.parseRequestParameters(request,requestMap);
  String action = requestMap.get(ACTION);
  if (action!=null) {
  	if (action.equals(ACTION_IMPORT_EXPORT)) {
  	  try {
  	    if (requestMap.get(BUTTON_IMPORT_PROFILES)!=null) { cabean.importProfilesFromZip(filebuffer); }
  	    if (requestMap.get(BUTTON_EXPORT_PROFILES)!=null) { cabean.exportProfiles(requestMap.get(TEXTFIELD_EXPORT_DESTINATION)); }
  	  } catch (Exception e) {
  		%><div style="color: #FF0000;"><c:out value="<%=e.getMessage()%>"/></div><%
  	  }
  	}
  }
%>
<%int row=0;%>
<form name="recievefile" action="<%=THIS_FILENAME%>" method="post" enctype='multipart/form-data' >
	<table class="action" width="70%" border="0" cellspacing="3" cellpadding="3">
		<form name="recievefile" action="<%=THIS_FILENAME%>" method="post" enctype='multipart/form-data' >
		<input type="hidden" name='<%=ACTION%>' value='<%=ACTION_IMPORT_EXPORT%>'>
		<tr id="Row<%=row++%2%>">
			<td width="25%" valign="top" align="right"><%=ejbcawebbean.getText("IMPORTPROFILESFROM")%></td>
			<td width="50%" valign="top">
					<input TYPE="FILE" NAME="<%=FILE_IMPORTFILE%>">
			</td>
			<td width="25%" valign="top">
					<input type="submit" name="<%=BUTTON_IMPORT_PROFILES%>" onClick='return check()' value="<%=ejbcawebbean.getText("IMPORT")%>">
			</td>
		</tr>
		<tr id="Row<%=row++%2%>">
		    <td width="25%" valign="top" align="right"><%=ejbcawebbean.getText("EXPORTROFILESTO")%></td>
			<td width="50%" valign="top">
				<input type="text" name="<%=TEXTFIELD_EXPORT_DESTINATION%>" size="35" maxlength="255" title="<%=ejbcawebbean.getText("FORMAT_ID_STR")%>">
			</td>
			<td width="25%" valign="top">
				<input type="submit" name="<%=BUTTON_EXPORT_PROFILES%>" onClick='return check()' value="<%=ejbcawebbean.getText("EXPORT")%>">
			</td>
		</tr>
	</table>
</form>

	<br/>
	<a href="<%=globalconfiguration.getAdminWebPath()%>ca/editcertificateprofiles/editcertificateprofiles.jsf"><%=ejbcawebbean.getText("BACK")%></a>

	<jsp:include page="<%=globalconfiguration.getFootBanner()%>"/>
</body>
</html>
