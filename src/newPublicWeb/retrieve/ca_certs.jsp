<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ include file="header.jsp" %>

	<h1 class="title">@EJBCA@ Fetch CA Certificate</h1>

	<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
	<% finder.initialize(request.getRemoteAddr()); %>

	<c:forEach var="ca_id" items="${finder.availableCAs}">
		<jsp:useBean id="ca_id" type="java.lang.Integer" />
		<% finder.setCurrentCA(ca_id); %>

		<jsp:useBean id="ca" class="org.ejbca.core.model.ca.caadmin.CAInfo" scope="page" />
		<c:set var="ca" value="${finder.CAInfo}" />

		<hr>
		<h2>CA: ${ca.name}</h2>

		<c:set var="issuerdn" value="none" />
		<c:forEach var="issuercert" items="${finder.CACertificateChain}" begin="0" end="0">
			<jsp:useBean id="issuercert" type="java.security.cert.X509Certificate" />
			<c:set var="issuerdn" value="${issuercert.subjectDN.name}" />
		</c:forEach>

		<c:if test="${issuerdn == 'none'}">
			No CA certificates exist
		</c:if>
		<c:if test="${issuerdn != 'none'}">
	
			<h3>In PEM format:</h3>
			<c:forEach var="pemcert" items="${finder.CACertificateChain}" varStatus="status">
				<jsp:useBean id="pemcert" type="java.security.cert.X509Certificate" />
	
				<c:url var="pem" value="../certdist" >
					<c:param name="cmd" value="cacert" />
					<c:param name="issuer" value="${issuerdn}" />
					<c:param name="level" value="${status.count - 1}" />
				</c:url>
				<p><a href="${pem}">${pemcert.subjectDN.name}</a>,

				<c:url var="pem_ocsp" value="../certdist" >
					<c:param name="cmd" value="ocspcert" />
					<c:param name="issuer" value="${pemcert.subjectDN.name}" />
				</c:url>
				<a href="${pem_ocsp}">OCSPResponder certificate</a>
				</p>
			</c:forEach>

			<h3>For Netscape/Mozilla:</h3>
			<c:forEach var="nscert" items="${finder.CACertificateChain}" varStatus="status">
				<jsp:useBean id="nscert" type="java.security.cert.X509Certificate" />
	
				<c:url var="ns" value="../certdist" >
					<c:param name="cmd" value="nscacert" />
					<c:param name="issuer" value="${issuerdn}" />
					<c:param name="level" value="${status.count - 1}" />
				</c:url>
				<p><a href="${ns}">${nscert.subjectDN.name}</a>,

				<c:url var="ns_ocsp" value="../certdist" >
					<c:param name="cmd" value="nsocspcert" />
					<c:param name="issuer" value="${nscert.subjectDN.name}" />
				</c:url>
				<a href="${ns_ocsp}">OCSPResponder certificate</a>
				</p>
			</c:forEach>

			<h3>For Internet Explorer:</h3>
			<c:forEach var="iecert" items="${finder.CACertificateChain}" varStatus="status">
				<jsp:useBean id="iecert" type="java.security.cert.X509Certificate" />
	
				<c:url var="ie" value="../certdist" >
					<c:param name="cmd" value="iecacert" />
					<c:param name="issuer" value="${issuerdn}" />
					<c:param name="level" value="${status.count - 1}" />
				</c:url>
				<p><a href="${ie}">${iecert.subjectDN.name}</a>,

				<c:url var="ie_ocsp" value="../certdist" >
					<c:param name="cmd" value="ieocspcert" />
					<c:param name="issuer" value="${iecert.subjectDN.name}" />
				</c:url>
				<a href="${ie_ocsp}">OCSPResponder certificate</a>
				</p>
			</c:forEach>
		</c:if>
	</c:forEach>
	
<%@ include file="footer.inc" %>
