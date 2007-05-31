<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ include file="header.jsp" %>

	<h1>@EJBCA@ Fetch CA CRL</h1>

	<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
	<% finder.initialize(request.getRemoteAddr()); %>

	<c:forEach var="ca_id" items="${finder.availableCAs}">
		<jsp:useBean id="ca_id" type="java.lang.Integer" />
		<% finder.setCurrentCA(ca_id); %>

		<c:set var="ca" value="${finder.CAInfo}" />

		<c:url var="der" value="../certdist" >
			<c:param name="cmd" value="crl" />
			<c:param name="issuer" value="${ca.subjectDN}" />
		</c:url>
		<c:url var="pem" value="../certdist" >
			<c:param name="cmd" value="crl" />
			<c:param name="format" value="PEM" />
			<c:param name="issuer" value="${ca.subjectDN}" />
		</c:url>
		<c:url var="moz" value="../certdist" >
			<c:param name="cmd" value="crl" />
			<c:param name="issuer" value="${ca.subjectDN}" />
			<c:param name="moz" value="y" />
		</c:url>

		<hr>
		<h2>CA: ${ca.name}</h2>
		<p>The Certificate Revocation List is available in three ways:
		<ul>
		  	<li><a href="${der}">DER format</a></li> 
		  	<li><a href="${pem}">PEM format</a></li> 
		  	<li><a href="${moz}">Mozilla/Netscape direct import</a></li>
		</ul>
	</c:forEach>
<%@ include file="footer.inc" %>
