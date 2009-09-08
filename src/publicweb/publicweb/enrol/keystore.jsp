<%@ include file="header.jsp" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:set var="THIS_FILENAME" value="/<%= org.ejbca.config.InternalConfiguration.getAppNameLower() %>/enrol/keystore.jsp" />
<%@ include file="apply/apply_main.jsp" %>

<%@ include file="footer.inc" %>
