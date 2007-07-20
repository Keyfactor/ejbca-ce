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
Subject:          ${certificate.subjectDN}
Issuer:           ${certificate.issuerDN}
NotBefore:        ${certificate.validFrom}
NotAfter:         ${certificate.validTo}
Serial number:    ${certificate.serialNumber}
SHA1 fingerprint: ${certificate.SHA1Fingerprint}
MD5 fingerprint:  ${certificate.MD5Fingerprint}
</pre>
                        <c:url var="check_status" value="check_status_result.jsp" >
                            <c:param name="issuer" value="${certificate.issuerDN}" />
                            <c:param name="serno" value="${certificate.serialNumber}" />
                        </c:url>
                        <p><a href="${check_status}">Check if certificate is revoked</a></p>
                    </c:forEach>
                </c:otherwise> 
            </c:choose> 
        </c:otherwise> 
    </c:choose> 
<%@ include file="footer.inc" %>
