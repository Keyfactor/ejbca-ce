<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:set var="THIS_TITLE" value="Certificate Created" />
<%@ include file="header.jsp" %>

<h1 class="title">Certificate Created</h1>

<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
<%
finder.initialize(request.getRemoteAddr());
finder.lookupCertificateInfo(request.getParameter("issuer"), request.getParameter("serno"));
%>

<table>
<tr><td>Subject DN: </td><td><strong><c:out value="${finder.subjectDN}" /></strong><br /></td></tr>
<tr><td>Issuer DN: </td><td><strong><c:out value="${finder.issuerDN}" /></strong><br /></td></tr>
<tr><td>Serial Number: </td><td><strong><c:out value="${finder.serialNumber}" /></strong><br /></td></tr>
</table>

<p>
If your certificate is not installed automatically, please click here to install it:<br />
<a id="installToBrowserLink" href="../publicweb/webdist/certdist?hidemenu=${hidemenu}&cmd=lastcert&installtobrowser=netscape&subject=<c:out value="${finder.subjectDN}" />">Install certificate</a>
</p>

<script type="text/javascript">
<!--
if (document.getElementById) {
    window.setTimeout("document.getElementById('installToBrowserLink').click();", 1);
}
//-->
</script>


<%@ include file="footer.inc" %>

