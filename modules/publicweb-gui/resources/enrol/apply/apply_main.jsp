<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<c:set var="ACTION" value="action" />
<c:set var="ACTION_GENERATETOKEN" value="generatetoken" />

<c:set var="TOKEN_SOFT_BROWSERGEN" value="1" />

<c:set var="BUTTON_SUBMIT_USERNAME" value="buttonsubmitusername" /> 
<c:set var="TEXTFIELD_USERNAME" value="textfieldusername" />
<c:set var="TEXTFIELD_PASSWORD" value="textfieldpassword" />

<c:set var="FORCE_BROWSER" value="forcebrowser" />

<c:set var="BROWSER_NETSCAPE" value="netscape" />
<c:set var="BROWSER_EXPLORER" value="explorer" />
<c:set var="BROWSER_UNKNOWN" value="browserunknown" />

<c:set var="username" value="${param[TEXTFIELD_USERNAME]}" />
<c:set var="password" value="${param[TEXTFIELD_PASSWORD]}" />
<c:set var="forcedBrowser" value="${param[FORCE_BROWSER]}" />
<c:set var="action" value="${param[ACTION]}" />

<jsp:useBean id="applybean" class="org.ejbca.ui.web.pub.ApplyBean" scope="page" />
<jsp:useBean id="username" class="java.lang.String" />
<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
<%
  applybean.initialize(request);
  applybean.setDefaultUsername(username);
%>

<c:set var="browser" value="${applybean.browser}" />

<c:set var="includefile" value="apply_auth.jspf" />
<c:if test="${action != null && action == ACTION_GENERATETOKEN}">
	<c:if test="${forcedBrowser != null}">
		<c:set var="browser" value="${forcedBrowser}" />
	</c:if>
	<c:if test="${username != null && password != null && browser != null}">
		<c:set var="tokentype" value="${applybean.tokenType}" />
		<c:set var="availablekeylengths" value="${applybean.availableBitLengths}" />
		<c:set var="minKeyLength" value="${applybean.minimumAvailableKeyLength}" />
		<c:set var="availableCertProfiles" value="${applybean.availableCertificateProfiles}" />
		<c:set var="userCertProfile" value="${applybean.userCertificateProfile}" />
		<c:set var="caid" value="${applybean.CAId}" />
		<jsp:useBean id="caid" type="java.lang.Integer" />
		<% finder.setCurrentCA(caid); %>

		<c:choose>
	        <c:when test="${tokentype == 0}">
				<%	
					// The user doesn't exist. Redirect to error page.
		            request.setAttribute("ErrorMessage","Wrong username or password");
		            request.getRequestDispatcher("error.jsp").forward(request, response);
		        %>
	        </c:when> 
	        <c:when test="${tokentype == TOKEN_SOFT_BROWSERGEN}">
				<c:choose>
			        <c:when test="${browser == BROWSER_NETSCAPE}">
			        	<c:set var="includefile" value="apply_nav.jspf" />
			        </c:when> 
			        <c:when test="${browser == BROWSER_EXPLORER}">
			        	<c:set var="includefile" value="apply_exp.jspf" />
			        </c:when> 
			        <c:otherwise> 
			        	<c:set var="includefile" value="apply_unknown.jspf" />
					</c:otherwise>
				</c:choose>
	        </c:when> 
	        <c:otherwise> 
	        	<c:set var="includefile" value="apply_token.jspf" />
			</c:otherwise>
		</c:choose>
	</c:if>
</c:if>

<c:if test="${availablekeylengths == null || fn:length(availablekeylengths) == 0}">
	<c:set var="browser" value="${applyBean.defaultBitLengths}" />
</c:if>

<c:choose>
    <c:when test="${includefile == 'apply_auth.jspf'}">
		<%@ include file="apply_auth.jspf" %>
    </c:when> 
    <c:when test="${includefile == 'apply_token.jspf'}">
		<%@ include file="apply_token.jspf" %>
    </c:when> 
    <c:when test="${includefile == 'apply_nav.jspf'}">
		<%@ include file="apply_nav.jspf" %>
    </c:when> 
    <c:when test="${includefile == 'apply_exp.jspf'}">
		<%@ include file="apply_exp.jspf" %>
    </c:when> 
    <c:when test="${includefile == 'apply_unknown.jspf'}">
		<%@ include file="apply_unknown.jspf" %>
    </c:when> 
    <c:otherwise> 
	    <h1><c:out value="NO MATCH! Error in apply_main.jsp. includefile == &quot;${includefile}&quot;" /></h1>
	</c:otherwise>
</c:choose>
