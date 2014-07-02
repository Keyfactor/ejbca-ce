<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<%@ include file="header.jsp" %>
    <c:set var="subject" value="${param.subject}" />
    <c:choose> 
        <c:when test="${subject == null || subject == ''}"> 
            <h1 class="title">No subject</h1> 
            <p>Please enter a valid subject in the <a href="list_certs.jsp">search form</a>!</p>
        </c:when>
        <c:otherwise> 
            <jsp:useBean id="subject" type="java.lang.String" scope="page" />
            <jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
            <jsp:useBean id="certificates" class="java.util.ArrayList" scope="page" />
        
            <%
                finder.initialize(request.getRemoteAddr());
                finder.lookupCertificatesBySubject(subject, certificates);
            %>
    
            <h1 class="title"><c:out value="Certificates for ${subject}" /></h1> 
    
            <c:choose> 
                <c:when test="${certificates == null || fn:length(certificates) == 0}"> 
                    <h2><c:out value="No certificates exist for '${subject}'." /></h2>
                </c:when>
                <c:otherwise> 
                    <c:forEach var="certificate" items="${certificates}">
<pre>
<c:out value="Subject:            ${certificate.subjectDN}" />
<c:out value="Issuer:             ${certificate.issuerDN}" />
<c:out value="NotBefore:          ${certificate.validFrom}" />
<c:out value="NotAfter:           ${certificate.validTo}" />
<c:out value="Serial number:      ${certificate.serialNumber}" />
<c:out value="SHA1 fingerprint:   ${certificate.SHA1Fingerprint}" />
<c:out value="SHA256 fingerprint: ${certificate.SHA256Fingerprint}" />
</pre>
                        <c:url var="download" value="../publicweb/webdist/certdist" >
                            <c:param name="cmd" value="eecert" />
                            <c:param name="issuer" value="${certificate.issuerDN}" />
                            <c:param name="serno" value="${certificate.serialNumber}" />
                            <c:param name="hidemenu" value="<c:out value="${hidemenu}" />" />
                        </c:url>
                        <p><a href="${download}">Download certificate</a></p>
                        <c:url var="check_status" value="check_status_result.jsp" >
                            <c:param name="issuer" value="${certificate.issuerDN}" />
                            <c:param name="serno" value="${certificate.serialNumber}" />
                            <c:param name="hidemenu" value="<c:out value="${hidemenu}" />" />
                        </c:url>
                        <p><a href="${check_status}">Check if certificate is revoked</a></p>
                    </c:forEach>
                </c:otherwise> 
            </c:choose> 
        </c:otherwise> 
    </c:choose> 
<%@ include file="footer.inc" %>
