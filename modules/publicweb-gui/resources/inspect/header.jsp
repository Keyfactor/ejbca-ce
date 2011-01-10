<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ page pageEncoding="ISO-8859-1"%>
<%
   response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
   org.ejbca.ui.web.RequestHelper.setDefaultCharacterEncoding(request);
%>

<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=<%= org.ejbca.config.WebConfiguration.getWebContentEncoding() %>" />
    <title><%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Certificate/CRL Retrieval</title>
    <link rel="stylesheet" href="../styles.css" type="text/css" />
    <script type="text/javascript" src="scripts/functions.js"></script>
    <script type="text/vbscript" src="scripts/functions.vbs"></script>
  </head>

  <body>
    <div class="logobar">
      <a href="../index.jsp"><img src="../images/logotype.png" alt="EJBCA" border="0"/></a>
    </div>
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
                <a href="../renew/index.jsp">Request Browser Certificate Renewal</a>
              </li>
              <% } %>
            </ul>
          </li>  
          <li><div class="menuheader">Retrieve</div>
            <ul>
              <li>
                <a href="../retrieve/ca_certs.jsp">Fetch CA &amp; OCSP Certificates</a>
              </li>
              <li>
                <a href="../retrieve/ca_crls.jsp">Fetch CA CRLs</a>
              </li>
              <li>
                <a href="../retrieve/latest_cert.jsp">Fetch User's Latest Certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Inspect</div>
            <ul>
              <li>
                <a href="../inspect/request.jsp">Inspect certificate/CSR</a>
              </li>
            </ul>
          </li>
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
                <a href="../retrieve/list_certs.jsp">List  User's Certificates</a>
              </li>
              <li>
                <a href="../retrieve/check_status.jsp">Check Certificate Status</a>
              </li>
              <li>
                <% java.net.URL adminURL = new java.net.URL("https",request.getServerName(),
                		org.ejbca.config.WebConfiguration.getExternalPrivateHttpsPort(),
                		"/"+org.ejbca.config.InternalConfiguration.getAppNameLower()+"/adminweb/index.jsp");  %>
                <a href="<%=adminURL.toString() %>">Administration</a>
            </li>
              <% if (!"disabled".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) {
                  if ("internal".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) { %>
              <li>
                <a href="../doc/concepts.html" target="<%= org.ejbca.core.model.ra.raadmin.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
              </li>
              <%  } else { %>
              <li>
                <a href="<%= org.ejbca.config.WebConfiguration.getDocBaseUri() %>/concepts.html" target="<%= org.ejbca.core.model.ra.raadmin.GlobalConfiguration.DOCWINDOW %>">Documentation</a>
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
