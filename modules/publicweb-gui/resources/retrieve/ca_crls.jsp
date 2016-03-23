<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ include file="header.jsp" %>

	<h1>Fetch CA CRLs</h1>

	<jsp:useBean id="finder" class="org.ejbca.ui.web.pub.retrieve.CertificateFinderBean" scope="page" />

	<c:forEach var="ca_id" items="${finder.availableCAs}">
		<jsp:useBean id="ca_id" type="java.lang.Integer" />
		<% finder.setCurrentCA(ca_id); %>

		<c:set var="caName" value="${finder.CAInfo.name}" />
		<c:set var="caDN" value="${finder.CADN}" />

		<c:url var="der" value="../publicweb/webdist/certdist" >
			<c:param name="cmd" value="crl" />
			<c:param name="issuer" value="${caDN}" />
		</c:url>
		<c:url var="pem" value="../publicweb/webdist/certdist" >
			<c:param name="cmd" value="crl" />
			<c:param name="format" value="PEM" />
			<c:param name="issuer" value="${caDN}" />
		</c:url>
		
		<% if(finder.existsDeltaCrlForCurrentCA()) { %>
		<c:url var="derdelta" value="../publicweb/webdist/certdist" >
			<c:param name="cmd" value="deltacrl" />
			<c:param name="issuer" value="${caDN}" />
		</c:url>
		<c:url var="pemdelta" value="../publicweb/webdist/certdist" >
			<c:param name="cmd" value="deltacrl" />
			<c:param name="format" value="PEM" />
			<c:param name="issuer" value="${caDN}" />
		</c:url>
		<% } %>

		<hr />
		<h2>CA: ${caName}</h2>
		<table>
		<thead><tr>
			<th style="text-align: left;">CRL</th>
			<th style="text-align: left;">Delta CRL</th>
		</tr></thead>
		<tbody>
		<tr>
		<td style="padding-right: 4em;">
		<ul>
		  	<li><a href="${der}">DER format</a></li> 
		  	<li><a href="${pem}">PEM format</a></li> 
		</ul>
		</td>
		<td>
		<% if(finder.existsDeltaCrlForCurrentCA()) { %>
		<ul>
		  	<li><a href="${derdelta}">DER format</a></li> 
		  	<li><a href="${pemdelta}">PEM format</a></li> 
		</ul>
		<% } else { %>
			<p><i>None available</i><p>
		<% } %>
		</td>
		</tr>
		</tbody>
		</table>
	</c:forEach>
<%@ include file="footer.inc" %>
