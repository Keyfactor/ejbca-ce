<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
<%
finder.initialize(request.getRemoteAddr());
finder.lookupCertificateInfo(request.getParameter("issuer"), request.getParameter("serno"));

%>
<c:set var="THIS_TITLE" value="Certificate Created" />
<c:url var="header_redirect_url" value="../publicweb/webdist/certdist" >
    <c:param name="cmd" value="lastcert" />
    <c:param name="installtobrowser" value="netscape" />
    <c:param name="subject" value="${finder.subjectDN}" />
    <c:param name="hidemenu" value="${param.hidemenu}" />
</c:url>
<%@ include file="header.jsp" %>

<h1 class="title">Certificate Created</h1>

<table>
<tr><td>Subject DN: </td><td><strong><c:out value="${finder.subjectDN}" /></strong><br /></td></tr>
<tr><td>Issuer DN: </td><td><strong><c:out value="${finder.issuerDN}" /></strong><br /></td></tr>
<tr><td>Serial Number: </td><td><strong><c:out value="${finder.serialNumber}" /></strong><br /></td></tr>
</table>

<p>
If your certificate is not installed automatically, please click here to install it:<br />
<a id="installToBrowserLink" href="<c:out value="${header_redirect_url}" />">Install certificate</a>
</p>

<%@ include file="footer.inc" %>

