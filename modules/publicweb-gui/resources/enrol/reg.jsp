<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<c:set var="THIS_TITLE" value="Request Registration" />
<%@ include file="header.jsp" %>
<h1 class="title">Request Registration</h1>


<% if (!org.ejbca.config.WebConfiguration.getSelfRegistrationEnabled()) { %>
  <p>Self-registration is disabled.
  
  <% if (!"disabled".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) { %>
      For administrators: See the
      <% if ("internal".equalsIgnoreCase(org.ejbca.config.WebConfiguration.getDocBaseUri())) { %>
          <a href="../doc/adminguide.html#Self%20Registration" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>">admin guide</a>
      <% } else { %>
          <a href="<%= org.ejbca.config.WebConfiguration.getDocBaseUri() %>/adminguide.html#Self%20Registration" target="<%= org.ejbca.config.GlobalConfiguration.DOCWINDOW %>">admin guide</a>
      <% } %>
      for instructions on how to configure self-registration.
  <% } %>
  
  </p>
<% } else { %>
    <p>Please enter your information below. A request for approval will be sent to your administrator.</p>
    
    <jsp:useBean id="reg" class="org.ejbca.ui.web.pub.RegisterReqBean" scope="request" />
    <%
    reg.checkConfig();
    %>
    
    <c:forEach var="error" items="${reg.errors}">
        <p><c:out value="${error}" /></p>
    </c:forEach>
    
    <c:if test="${empty reg.errors}">

    <form action="reg_details.jsp" method="post">
      <fieldset>
        <legend>Registration request - Step 1 of 2</legend>
        
        <input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" />
        
        <label for="certType">Certificate type</label>
        <select name="certType" id="certType" accesskey="t">
          <c:forEach var="certtype" items="${reg.certificateTypes}">
            <option value="<c:out value="${certtype.key}" />"${reg.defaultCertType == certtype.key ? " selected=\"selected\"" : ""}><c:out value="${certtype.value}" /></option>
          </c:forEach>
        </select>
        <br />
        <br />
        <label for="ok"></label>
        <input type="submit" id="ok" value="Continue" <% if(reg.getCertificateTypes().size() == 0) out.write(" disabled=\"disabled\" "); %>  />
      </fieldset>
    </form>

    </c:if>
<% } %>


<%@ include file="footer.inc" %>

