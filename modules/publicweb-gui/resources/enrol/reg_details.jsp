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
        
        <input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" />
        
        <b>Certificate type: <c:out value="${reg.certTypeDescription}" /></b>
        <input type="hidden" name="certType" value="<c:out value="${reg.certType}" />"  />
        <br />
        
        <!-- Subject DN fields -->
        <c:forEach var="field" items="${reg.dnFields}">
            <c:set var="id" value="dnfield_${field.id}" />
            
            <label for="<c:out value="${id}" />" title="<c:out value="${field.description}" />"><c:out value="${field.humanReadableName}" /><c:out value="${field.requiredMarker}" /></label>
            <c:choose>
                <c:when test='${field.name == "c"}'>
                    <!-- Country field -->
                    <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                      <c:if test="${!field.required}">
                        <option value=""></option>
                      </c:if>
                      <c:forEach var="country" items="${countrycodes.countriesFromBean}">
                        <c:if test="${field.modifiable || field.allowedValuesMap[country.code] != null}">
                          <option value="<c:out value="${country.code}" />"<c:if test="${field.defaultValue == country.code}"> selected="selected"</c:if>><c:out value="${country.name}" /></option>
                        </c:if>
                      </c:forEach>
                    </select>
                </c:when>
                <c:when test='${field.name == "e"}'>
                    <!-- E-mail -->
                    <c:if test="${!field.required}">
                        <input type="checkbox" name="emailindn" value="1" />
                    </c:if>
                    <c:if test="${field.required}">
                        <input type="checkbox" checked="checked" disabled="disabled" />
                        <input type="hidden" name="emailindn" value="1" />
                    </c:if>
                    Include e-mail in certificate
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
        <br />
        
        <!-- Subject alt name fields -->
        <c:if test="${!empty reg.altNameFields}">Subject alternative names<br /></c:if>
        <c:forEach var="field" items="${reg.altNameFields}">
            <c:set var="id" value="altnamefield_${field.id}" />
            
            <label for="<c:out value="${id}" />" title="<c:out value="${field.description}" />"><c:out value="${field.humanReadableName}" /><c:out value="${field.requiredMarker}" /></label>
            
            <c:choose>
                <c:when test='${field.name == "rfc822name" && field.use}'>
                    <!-- rfc822name (e-mail) with "use email field" checkbox -->
                    <c:if test="${!field.required}">
                        <input type="checkbox" name="emailinaltname" value="<c:out value="${field.id}" />" />
                    </c:if>
                    <c:if test="${field.required}">
                        <input type="checkbox" checked="checked" disabled="disabled" />
                        <input type="hidden" name="emailinaltname" value="<c:out value="${field.id}" />" />
                    </c:if>
                    Include e-mail in certificate altname
                </c:when>
                <c:when test="${field.modifiable}">
                    <!-- Free text -->
                    <input name="<c:out value="${id}" />" id="<c:out value="${id}" />" type="text" size="25" title="<c:out value="${field.description}" />" value="<c:out value="${field.defaultValue}" />" />
                </c:when>
                <c:otherwise>
                    <!-- Select box -->
                    <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                      <c:forEach var="value" items="${field.allowedValuesList}">
                        <option value="<c:out value="${value}" />"><c:out value="${value}" /></option>
                      </c:forEach>
                    </select>
                </c:otherwise>
            </c:choose>
            <br />
        </c:forEach>
        <br />
        
        <!-- Subject directory attributes -->
        <c:if test="${!empty reg.dirAttrFields}">Subject directory attributes<br /></c:if>
        <c:forEach var="field" items="${reg.dirAttrFields}">
            <c:set var="id" value="dirattrfield_${field.id}" />
            
            <label for="<c:out value="${id}" />" title="<c:out value="${field.description}" />"><c:out value="${field.humanReadableName}" /><c:out value="${field.requiredMarker}" /></label>
            
            <c:choose>
                <c:when test='${field.name == "countryofcitizenship" || field.name == "countryofresidence"}'>
                    <!-- Country field -->
                    <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                      <c:if test="${!field.required}">
                        <option value=""></option>
                      </c:if>
                      <c:forEach var="country" items="${countrycodes.countriesFromBean}">
                        <c:if test="${field.modifiable || field.allowedValuesMap[country.code] != null}">
                          <option value="<c:out value="${country.code}" />"<c:if test="${field.defaultValue == country.code}"> selected="selected"</c:if>><c:out value="${country.name}" /></option>
                        </c:if>
                      </c:forEach>
                    </select>
                </c:when>
                <c:when test="${field.modifiable}">
                    <!-- Free text -->
                    <input name="<c:out value="${id}" />" id="<c:out value="${id}" />" type="text" size="25" title="<c:out value="${field.description}" />" value="<c:out value="${field.defaultValue}" />" />
                </c:when>
                <c:otherwise>
                    <!-- Select box -->
                    <select name="<c:out value="${id}" />" id="<c:out value="${id}" />" title="<c:out value="${field.description}" />">
                      <c:forEach var="value" items="${field.allowedValuesList}">
                        <option value="<c:out value="${value}" />"><c:out value="${value}" /></option>
                      </c:forEach>
                    </select>
                </c:otherwise>
            </c:choose>
            <br />
        </c:forEach>
        <c:if test="${!empty reg.dirAttrFields}"><br /></c:if>
        
        <!-- Username -->
        <br />
        <b>Certificate enrollment</b><br />
        <c:if test="${reg.usernameVisible}">
            <label for="username">Username *</label>
            <input name="username" id="username" type="text" size="20" accesskey="u" />
            <br />
        </c:if>
        
        <!-- E-mail -->
        <label for="email">E-mail *</label>
        <input name="email" id="email" type="text" size="25" accesskey="e" />
        <c:choose>
            <c:when test='${reg.emailDomainFrozen}'>
                <b>@ <c:out value="${reg.selectableEmailDomains[0]}" /></b>
                <input name="emaildomain" id="emaildomain" type="hidden" value="<c:out value="${reg.selectableEmailDomains[0]}" />" />
            </c:when>
            <c:when test='${reg.emailDomainSelectable}'>
                <b>@</b>
                <select name="emaildomain">
                    <c:forEach var="domain" items="${reg.selectableEmailDomains}">
                        <option value="<c:out value="${domain}" />"><c:out value="${domain}" /></option>
                    </c:forEach>
                </select>
            </c:when>
        </c:choose>
        <br />
        <small style="width: 50%">An auto-generated password will be sent to this e-mail address once the request has been approved.</small>
        <br />
        
        <!-- Token type -->
        <c:if test="${reg.tokenTypeVisible}">
            <label for="tokenType">Token type</label>
            <select name="tokenType" id="tokenType">
                <c:forEach var="item" items="${reg.selectableTokenTypeItems}">
                    <option value="<c:out value="${item.key}" />"<c:if test="${reg.defaultTokenType == item.key}"> selected="selected"</c:if>><c:out value="${item.text}" /></option>
                </c:forEach>
            </select>
            <br />
        </c:if>
        
        <br />
        
        <!-- CAPTCHA -->
        <b>Prevention of automatic registration (CAPTCHA)</b><br />
        <label for="code" style="font-size: 85%">Last character in
            <c:if test="${reg.usernameVisible}">username</c:if>
            <c:if test="${!reg.usernameVisible}">e-mail</c:if>
            *</label>
        <input name="code" id="code" type="text" size="3" accesskey="t" />
        <br />
        
        <p><small>* = Required field.</small></p>
        
        <label for="ok"></label>
        <input type="submit" id="ok" value="Request registration" />
      </fieldset>
    </form>


    </c:if>
<% } %>


<%@ include file="footer.inc" %>

