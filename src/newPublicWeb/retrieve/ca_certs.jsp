<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ include file="header.jsp" %>

	<h1 class="title">@EJBCA@ Fetch CA Certificate</h1>

	<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />
	<% finder.initialize(request.getRemoteAddr()); %>

	<c:forEach var="ca_id" items="${finder.availableCAs}">
		<jsp:useBean id="ca_id" type="java.lang.Integer" />
		<% finder.setCurrentCA(ca_id); %>

		<c:set var="ca" value="${finder.CAInfo}" />

		<hr />
		<h2>CA: ${ca.name}</h2>

		<c:set var="chain" value="${finder.CACertificateChain}" />
	
		<c:choose>
			<c:when test="${fn:length(chain) == 0}">
				<p>No CA certificates exist</p>
			</c:when>
			<c:otherwise>
				<c:set var="issuercert" value="${chain[0]}" />
				<c:set var="issuerdn" value="${issuercert.subjectDN.name}" />

				<h3>In PEM format:</h3>
				<c:forEach var="pemcert" items="${chain}" varStatus="status">
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
					<a href="${pem_ocsp}">OCSPResponder certificate</a></p>
				</c:forEach>
	
				<h3>For Netscape/Mozilla:</h3>
				<c:forEach var="nscert" items="${chain}" varStatus="status">
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
					<a href="${ns_ocsp}">OCSPResponder certificate</a></p>
				</c:forEach>
	
				<h3>For Internet Explorer:</h3>
				<c:forEach var="iecert" items="${chain}" varStatus="status">
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
					<a href="${ie_ocsp}">OCSPResponder certificate</a></p>
				</c:forEach>
			</c:otherwise>
		</c:choose>
	</c:forEach>
	
<%@ include file="footer.inc" %>
