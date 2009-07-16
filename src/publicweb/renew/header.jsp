<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page pageEncoding="ISO-8859-1"%>
<%@ page contentType="text/html; charset=@page.encoding@" %>

<%
  org.ejbca.ui.web.RequestHelper.setDefaultCharacterEncoding(request);
%>

<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.ui.web.RequestHelper.getDefaultContentEncoding() %>" />
    <title>@EJBCA@ Certification Authority</title>
    <link rel="stylesheet" href="styles.css" type="text/css" />
  </head>
  <body>
    <div class="logobar">
      <a href="index.jsp"><img src="images/logotype.png" alt="EJBCA-pki logotype" border="0"/></a>
    </div>
    <div class="menucontainer">
      <div class="menu">
        <ul>
          <li><div class="menuheader">Enroll</div>
            <ul>
              <li>
                <a href="index.jsp">Request Browser Certificate Renewal</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
                <a href="../">Public Web</a>
              </li>
              <li>
                <a href="../adminweb/index.jsp">Administration</a>
              </li>
              <% if (!"disabled".equalsIgnoreCase("@web.docbaseuri@")) {
                  if ("internal".equalsIgnoreCase("@web.docbaseuri@")) { %>
              <li>
                <a href="../doc/manual.html" target="<%= org.ejbca.core.model.ra.raadmin.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
              </li>
              <%  } else { %>
              <li>
                <a href="@web.docbaseuri@/manual.html" target="<%= org.ejbca.core.model.ra.raadmin.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
              </li>
              <%  }
                 } %>
            </ul>
          </li>  
        </ul>
      </div>
    </div>
    <div class="main">
      <div class="content">
