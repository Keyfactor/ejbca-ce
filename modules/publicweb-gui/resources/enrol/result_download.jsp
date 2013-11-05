<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
<%
org.ejbca.ui.web.RequestHelper.setDefaultCharacterEncoding(request);
finder.initialize(request.getRemoteAddr());
finder.lookupCertificateInfo(request.getParameter("issuer"), request.getParameter("serno"));
%>
<c:set var="THIS_TITLE" value="Certificate Created" />
<c:set var="header_redirect_url" value="../publicweb/webdist/certdist?cmd=lastcert&installtobrowser=netscape&subject=${finder.subjectDNEncoded}&hidemenu=${param.hidemenu}"/>
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

