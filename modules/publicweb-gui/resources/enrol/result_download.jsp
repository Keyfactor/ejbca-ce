<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
<%
//We need to set the response encoding before we generated the URL variable that is then used from the header.
response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding());
org.ejbca.ui.web.RequestHelper.setDefaultCharacterEncoding(request);
finder.lookupCertificateInfo(request.getParameter("issuer"), request.getParameter("serno"));
%>
<c:set var="THIS_TITLE" value="Certificate Created" />
<c:choose>
    <c:when test="${param.resulttype == 1}"> <%-- PEM cert --%>
        <c:set var="format" value="PEM"/>
    </c:when>
    <c:when test="${param.resulttype == 2}"> <%-- PKCS7 --%>
        <c:set var="format" value="PKCS7"/>
    </c:when>
    <c:when test="${param.resulttype == 3}"> <%-- Binary cert --%>
        <c:set var="format" value=""/>
    </c:when>
    <c:when test="${param.resulttype == 4}"> <%-- PEM cert chain --%>
        <c:set var="format" value="chain"/>
    </c:when>
    <c:when test="${param.installtobrowser == &quot;netscape&quot;}"> <%-- Installing to browser --%>
        <c:set var="installtobrowser" value="netscape"/>
    </c:when>
</c:choose>
<c:url var="header_redirect_url" value="../publicweb/webdist/certdist" scope="request">
    <c:param name="cmd" value="lastcert"/>
    <c:param name="installtobrowser" value="${installtobrowser}"/>
    <c:param name="subject" value="${finder.subjectDN}"/>
    <c:param name="format" value="${format}"/>
    <c:param name="hidemenu" value="${param.hidemenu}"/>
</c:url>
<%@ include file="header.jsp" %>

<h1 class="title">Certificate Created</h1>

<table>
<tr><td>Subject DN: </td><td><strong><c:out value="${finder.subjectDN}" /></strong><br /></td></tr>
<tr><td>Issuer DN: </td><td><strong><c:out value="${finder.issuerDN}" /></strong><br /></td></tr>
<tr><td>Serial Number: </td><td><strong><c:out value="${finder.serialNumber}" /></strong><br /></td></tr>
</table>

<p>
<c:choose>
    <c:when test="${!empty installtobrowser}">
        <c:set var="infotext" value="If your certificate is not installed automatically, please click here to install it:"/>
        <c:set var="linktext" value="Install certificate"/>
    </c:when>
    <c:otherwise>
        <c:set var="infotext" value="You should receive your certificate file in a few seconds. If nothing happens, click this link:"/>
        <c:set var="linktext" value="Download certificate"/>
    </c:otherwise>
</c:choose>
<c:out value="${infotext}"/><br />
<a id="installToBrowserLink" href="<c:out value="${header_redirect_url}" />"><c:out value="${linktext}"/></a>
</p>

<%@ include file="footer.inc" %>

