<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ include file="header.jsp" %>

	<h1 class="title">Certificate Status</h1>
	
    <c:set var="issuer" value="${param.issuer}" />
    <jsp:useBean id="issuer" type="java.lang.String" scope="page" />

    <c:set var="serno" value="${param.serno}" />
    <jsp:useBean id="serno" type="java.lang.String" scope="page" />

    <jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
    <jsp:useBean id="certInfo" class="org.ejbca.core.model.ca.crl.RevokedCertInfo" scope="page" />

    <%
        finder.initialize(request.getRemoteAddr());
        finder.lookupRevokedInfo(issuer, serno, certInfo);
    %>

    <c:choose> 
        <c:when test="${certInfo.userCertificate == null}"> 
            <p>The certificate does not exist!</p> 
        </c:when> 
        <c:otherwise> 
            <p>Issuer: ${issuer}</p> 
            <p>Serial number: ${serno}</p>
            <c:choose> 
                <c:when test="${certInfo.revoked}"> 
                    <h1>The certificate has been REVOKED!</h1>
                    <p>The revocation date is ${certInfo.revocationDate}.<br /> 
                    The reason for revocation was &quot;${certInfo.humanReadableReason}&quot; (${certInfo.reason}). 
                </c:when> 
                <c:otherwise>
                    <p>The certificate has <strong>NOT</strong> been revoked.
                </c:otherwise> 
            </c:choose> 

        </c:otherwise> 
    </c:choose> 

<%@ include file="footer.inc" %>
