<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<%@ include file="header.jsp" %>

<h1 class="title">Request Browser Certificate Renewal</h1>

<p>On this page, you can request renewal of your browser certificate.</p> 

<c:choose>
	<c:when test="${!empty errorMessage}">
		<p style="color: red">
			<c:out value="${errorMessage}"/>
		</p>
	</c:when>
	<c:when test="${!empty statusMessage}">
		<p>
			<c:out value="${statusMessage}"/>
		</p>
	</c:when>
	<c:otherwise>
		<form action="index.jsp" method="post">
		<fieldset>
			<legend>Request</legend>
			<input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" />
			You are authenticated as: <strong>${certificate.subjectDN}</strong><br />
			<br />
			Press the button below to request renewal:<br />
			<input type="submit" name="${buttonRenew}" value="Renew" />
		</fieldset>
		</form>
	</c:otherwise>
</c:choose>

<%@ include file="footer.inc" %>
