<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:set var="THIS_TITLE" value="Request Registration" />
<%@ include file="header.jsp" %>
<h1 class="title">Request Registration</h1>


<% if (!org.ejbca.config.WebConfiguration.getSelfRegistrationEnabled()) { %>
  <p>Self-registration is disbled. For administrators: You can enable this page
     with the <code>web.selfregenabled</code> setting in <code>web.properties</code>.</p>
<% } else { %>
    <p>Please enter your information below. A request for approval will be sent to your administrator.</p>

    <form action="reg_details.jsp" method="post">
      <fieldset>
        <legend>Registration request - Step 1 of 2</legend>
        
        <label for="certType">Certificate type</label>
        <select name="certType" id="certType" accesskey="t">
          <jsp:useBean id="reg" class="org.ejbca.ui.web.pub.RegisterReqBean" scope="request" />
          <c:forEach var="certtype" items="${reg.certificateTypes}">
            <option value="${certtype.key}"${reg.defaultCertType == certtype.key ? " selected=\"selected\"" : ""}>${certtype.value}</option>
          </c:forEach>
        </select>
        <br />
        <br />
        
        <label for="ok"></label>
        <input type="submit" id="ok" value="Continue" />
      </fieldset>
    </form>

<% } %>


<%@ include file="footer.inc" %>

