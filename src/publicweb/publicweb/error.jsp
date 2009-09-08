<%@ include file="header.jsp" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

    <c:set var="isException" value="${param.Exception}" />
    <c:set var="errMsg" value="${ErrorMessage}" />
    
    <h1 class="title"><%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Certificate Enrollment Error</h1>
    
    <c:if test="${isException != null && isException == 'true'}">
        <h2>An Exception occurred!</h2>
    </c:if>
    <c:choose> 
        <c:when test="${errMsg == null}"> 
            <h2>Unknown error, or you came to this page directly without being redirected.</h2> 
        </c:when>
        <c:otherwise> 
            <p>
            <pre><c:out value="${errMsg}" /></pre>
            </p>
        </c:otherwise> 
    </c:choose> 

    <p><a href="javascript:history.back()">Go back</a></p>
    
<%@ include file="footer.inc" %>
