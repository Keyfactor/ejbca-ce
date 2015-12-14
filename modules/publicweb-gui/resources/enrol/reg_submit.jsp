<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:set var="THIS_TITLE" value="Request Registration" />
<%@ include file="header.jsp" %>
<h1 class="title">Request Registration</h1>


<% if (!org.ejbca.config.WebConfiguration.getSelfRegistrationEnabled()) { %>
  <p>Internal error: Self-registration is disabled in the configuration.</p>
<% } else { %>

<jsp:useBean id="reg" class="org.ejbca.ui.web.pub.RegisterReqBean" scope="request" />

<%

reg.initialize(request);
if (reg.isInitialized()) {
  reg.submit();
}

%>

<c:forEach var="error" items="${reg.errors}">
    <p><strong>ERROR:</strong> <c:out value="${error}" /></p>
</c:forEach>

<c:if test="${empty reg.errors}">
    <p>The registration request has been successfully submitted for approval by an administrator.</p>
</c:if>


<% } %>

<%@ include file="footer.inc" %>

