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
    
    <c:forEach var="error" items="${reg.errors}">
        <p><c:out value="${error}" /></p>
    </c:forEach>
    
    <c:if test="${empty reg.errors}">
    
    
    <p>Please enter your information below. A request for approval will be sent to your administrator.</p>

    <form action="reg_submit.jsp" method="post">
      <fieldset>
        <legend>Registration request - Step 2 of 2</legend>
        
        <b>Certificate type: <c:out value="${reg.certTypeDescription}" /></b>
        <input type="hidden" name="certType" value="<c:out value="${reg.certType}" />"  />
        <br />
        
        <!-- Subject DN fields -->
        <c:forEach var="field" items="${reg.dnFields}">
            <c:set var="id" value="dnfield_${field.id}" />
            
            <label for="<c:out value="${id}" />" title="<c:out value="${field.description}" />"><c:out value="${field.humanReadableName}" /></label>
            <c:choose>
                <c:when test='${field.name == "c"}'>
                    <!-- Country field -->
                    <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                      <c:forEach var="country" items="${countrycodes.countriesFromBean}">
                        <c:if test="${field.modifiable || field.allowedValuesMap[country.code] != null}">
                          <option value="<c:out value="${country.code}" />"<c:if test="${field.defaultValue == country.code}"> selected="selected"</c:if>><c:out value="${country.name}" /></option>
                        </c:if>
                      </c:forEach>
                    </select>
                </c:when>
                <c:otherwise>
                    <!-- Other field -->
                    <c:if test="${field.modifiable}">
                        <input name="<c:out value="${id}" />" id="<c:out value="${id}" />" type="text" size="25" title="<c:out value="${field.description}" />" value="<c:out value="${field.defaultValue}" />" />
                    </c:if>
                    <c:if test="${!field.modifiable}">
                        <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                          <c:forEach var="value" items="${field.allowedValuesList}">
                            <option value="<c:out value="${value}" />"><c:out value="${value}" /></option>
                          </c:forEach>
                        </select>
                    </c:if>
                </c:otherwise>
            </c:choose>
            <br />
        </c:forEach>
        
        <!-- Subject alt name fields -->
        <c:forEach var="field" items="${reg.altNameFields}">
            <c:set var="id" value="altnamefield_${field.id}" />
            
            <label for="<c:out value="${id}" />" title="<c:out value="${field.description}" />"><c:out value="${field.humanReadableName}" /></label>
            <input name="<c:out value="${id}" />" id="<c:out value="${id}" />" type="text" size="25" title="<c:out value="${field.description}" />" value="<c:out value="${field.defaultValue}" />" />
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


    </c:if>
<% } %>


<%@ include file="footer.inc" %>

