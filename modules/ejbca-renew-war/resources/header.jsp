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
    <title>Certificate renewal - <%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Public Web</title>
    <link rel="shortcut icon" href="images/favicon.png" type="image/png" />
    <link rel="stylesheet" href="styles.css" type="text/css" />
  </head>

  <body>
    <div id="header">
		<div id="banner">
			<a href="../"><img src="images/keyfactor-ejbca-logo.png" alt="EJBCA PKI by PrimeKey" /></a>
		</div>
    </div>
    <c:if test="${hidemenu != 'true'}">
    <div class="menucontainer">
      <div class="menu">
        <ul>
          <li><div class="menuheader">Enroll</div>
            <ul>
              <li>
                <a href=".">Renew Browser Certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
                <a href="../">Public Web home</a>
              </li>
              <li>
                <a href="../adminweb/">Administration</a>
              </li>
              <% if (!"disabled".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) {
                  if ("internal".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) { %>
              <li>
                <a href="../doc/concepts.html" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>" rel="noopener noreferer">Documentation</a>
              </li>
              <%  } else { %>
              <li>
                <a href="<%= org.ejbca.config.WebConfiguration.getDocBaseUri() %>/concepts.html" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>" rel="noopener noreferer">Documentation</a>
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
