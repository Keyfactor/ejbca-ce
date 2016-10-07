<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%
   response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
   org.ejbca.ui.web.RequestHelper.setDefaultCharacterEncoding(request);
%>

<c:set var="hidemenu" value="${param['hidemenu'] == 'true' ? 'true' : 'false'}" />
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
    <title>Certificate/CRL Retrieval - <%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Public Web</title>
	<link rel="shortcut icon" href="../images/favicon.png" type="image/png" />
    <link rel="stylesheet" href="../styles.css" type="text/css" />
    <script type="text/javascript" src="../scripts/functions.js"></script>
    <script type="text/vbscript" src="../scripts/functions.vbs"></script>
  </head>

  <body>
    <div id="header">
		<div id="banner">
			<a href="../"><img src="../images/banner_ejbca-public.png" alt="EJBCA" /></a>
		</div>
    </div>
    <c:if test="${hidemenu != 'true'}">
    <div class="menucontainer">
      <div class="menu">
        <ul>
          <li><div class="menuheader">Enroll</div>
            <ul>
              <li>
                <a href="../enrol/browser.jsp">Create Browser Certificate</a>
              </li>
              <li>
                <a href="../enrol/server.jsp">Create Certificate from CSR</a>
              </li>
              <li>
                <a href="../enrol/keystore.jsp">Create Keystore</a>
              </li>
              <li>
                <a href="../enrol/cvcert.jsp">Create CV certificate</a>
              </li>
              <% if(org.ejbca.config.WebConfiguration.getRenewalEnabled()) { %>
              <li>
                <a href="../renew/">Renew Browser Certificate</a>
              </li>
              <% } %>
            </ul>
          </li>
          <li><div class="menuheader">Register</div>
            <ul>
              <li>
                <a href="../enrol/reg.jsp">Request Registration</a>
              </li>
            </ul>
          </li>
          <li><div class="menuheader">Retrieve</div>
            <ul>
              <li>
                <a href="ca_certs.jsp">Fetch CA Certificates</a>
              </li>
              <li>
                <a href="ca_crls.jsp">Fetch CA CRLs</a>
              </li>
              <li>
                <a href="list_certs.jsp">List  User's Certificates</a>
              </li>
              <li>
                <a href="latest_cert.jsp">Fetch User's Latest Certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Inspect</div>
            <ul>
              <li>
                <a href="../inspect/request.jsp">Inspect certificate/CSR</a>
              </li>
              <li>
                <a href="check_status.jsp">Check Certificate Status</a>
              </li>
            </ul>
          </li>
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
                <% java.net.URL adminURL = new java.net.URL("https",org.ejbca.util.HTMLTools.htmlescape(request.getServerName()),
                		org.ejbca.config.WebConfiguration.getExternalPrivateHttpsPort(),
                		"/"+org.ejbca.config.InternalConfiguration.getAppNameLower()+"/adminweb/");  %>
                <a href="<%=adminURL.toString() %>">Administration</a>
            </li>
              <% if (!"disabled".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) {
                  if ("internal".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) { %>
              <li>
                <a href="../doc/concepts.html" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
              </li>
              <%  } else { %>
              <li>
                <a href="<%= org.ejbca.config.WebConfiguration.getDocBaseUri() %>/concepts.html" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
              </li>
              <%  }
                 } %>
              <% if (org.ejbca.config.WebConfiguration.isProxiedAuthenticationEnabled()) { %>
              <li>
                <a href="/logout">Logout</a>
              </li>
              <% } %>
            </ul>
          </li>  
        </ul>
      </div>
    </div>
    <div class="main">
      <div class="content">
    </c:if>
    
    <c:if test="${hidemenu == 'true'}">
    <div class="main hidemenu">
      <div class="content hidemenu">
    </c:if>
