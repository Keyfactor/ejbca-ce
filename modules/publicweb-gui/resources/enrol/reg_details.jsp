<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:set var="THIS_TITLE" value="Request Registration" />
<%@ include file="header.jsp" %>
<h1 class="title">Request Registration</h1>


<% if (!org.ejbca.config.WebConfiguration.getSelfRegistrationEnabled()) { %>
  <p>Internal error: Self-registration is disabled in the configuration.</p>
<% } else { %>


    <jsp:useBean id="countrycodes" class="org.ejbca.util.CountryCodes" scope="page" />
    <jsp:useBean id="reg" class="org.ejbca.ui.web.pub.RegisterReqBean" scope="request" />
    <%
    reg.initialize(request);
    %>

    <p>Please enter your information below. A request for approval will be sent to your administrator.</p>

    <form action="reg_submit.jsp" method="post">
      <fieldset>
        <legend>Registration request - Step 2 of 2</legend>
        
        <b>Certificate type: <c:out value="${reg.certTypeDescription}" /></b>
        <input type="hidden" name="certType" value="${reg.certType}"  />
        <br />
        
        <c:forEach var="field" items="${reg.modifiableCertFields}">
            <c:set var="name" value="field_${field.name}" />
            
            <label for="${name}" title="${field.description}"><c:out value="${field.humanReadableName}" /></label>
            <c:choose>
                <c:when test='${field.name == "c"}'>
                    <select name="${name}" id="${name}" title="${field.description}">
                      <c:forEach var="country" items="${countrycodes.countriesFromBean}">
                        <option value="${country.code}"<c:if test="${field.defaultValue == country.code}"> selected="selected"</c:if>>${country.name}</option>
                      </c:forEach>
                    </select>
                </c:when>
                <c:otherwise>
                    <input name="${name}" id="${name}" type="text" size="25" title="${field.description}" value="${field.defaultValue}" />
                </c:otherwise>
            </c:choose>
            <br />
        </c:forEach>
        
        <br />
        
        <label for="username">Username</label>
        <input name="username" id="username" type="text" size="20" accesskey="u" />
        <br />
        <label for="email">E-mail</label>
        <input name="email" id="email" type="text" size="25" accesskey="e" />
        <br />
        <br />
        
        <b>Prevention of automatic registration (CAPTCHA)</b><br />
        <label for="code" style="font-size: 85%">Last character in username</label>
        <input name="code" id="code" type="text" size="3" accesskey="t" />
        <br />
        
        <label for="ok"></label>
        <input type="submit" id="ok" value="Request registration" />
      </fieldset>
    </form>

<% } %>


<%@ include file="footer.inc" %>

