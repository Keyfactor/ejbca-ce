<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:set var="THIS_TITLE" value="Certificate Enrollment" />
<%@ include file="header.jsp" %>

<jsp:useBean id="internalConfiguration" class="org.ejbca.config.InternalConfiguration" scope="request" />

<c:set var="THIS_FILENAME" value="/${internalConfiguration.appNameLowerDynamic}/enrol/browser.jsp" />
<c:set var="PASSWORD_TERMINOLOGY" value="enrollment_code" />
<%@ include file="apply/apply_main.jsp" %>

<%@ include file="footer.inc" %>
