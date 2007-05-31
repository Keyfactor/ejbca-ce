<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
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
    
            <h1 class="title">Certificates for ${subject}</h1> 
    
            <c:choose> 
                <c:when test="${certificates == null}"> 
                    <h1 class="title">No certificates exists for '${subject}'.</h1> 
                </c:when>
                <c:otherwise> 
                    <c:forEach var="certificate" items="${certificates}">
<pre>
Subject:       ${certificate.subjectDN}
Issuer:        ${certificate.issuerDN}
NotBefore:     ${certificate.notBefore}
NotAfter:      ${certificate.notAfter}
Serial number: ${certificate.serialNumber}
</pre>
                        <c:url var="check_status" value="check_status_result.jsp" >
                            <c:param name="issuer" value="${certificate.issuerDN}" />
                            <c:param name="serno" value="${certificate.serialNumber}" />
                        </c:url>
                        <a href="${check_status}">Check if certificate is revoked</a>
                    </c:forEach>
                </c:otherwise> 
            </c:choose> 
        </c:otherwise> 
    </c:choose> 
<%@ include file="footer.inc" %>
