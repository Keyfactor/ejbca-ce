<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:set var="THIS_TITLE" value="Certificate Enrollment from CSR" />
<%@ include file="header.jsp" %>
<h1 class="title">Certificate enrollment from a CSR</h1>
<p>Please give your username and password, select a PEM- or DER-formated certification request file (CSR) for upload, 
or paste a PEM-formated request into the field below and click OK to fetch your certificate. 
</p>

<p>A PEM-formatted request is a BASE64 encoded certificate request starting with<br />
  <code>-----BEGIN CERTIFICATE REQUEST-----</code><br />
  and ending with<br />
  <code>-----END CERTIFICATE REQUEST-----</code>
</p>

<form name="EJBCA" action="../certreq" method="post" enctype="multipart/form-data">
  <fieldset >
    <legend>Enroll</legend>
	<label for="user">Username</label>
	<input type="text" size="40" name="user" id="user" accesskey="u" />
	<br />
	<label for="password">Password</label>
	<input type="password" autocomplete="off" size="40" name="password" id="password" accesskey="p" />

	<br />
	<br />
	<label for="pkcs10file">Request file</label>
	<input type="file" size="40" name="pkcs10file" id="pkcs10file"></input>
	<br />
	<label for="pkcs10req">or pasted request</label>
	<textarea rows="15" cols="66" name="pkcs10req" id="pkcs10req"></textarea>

	<br />
	<br />
	<label for="resulttype">Result type</label>
	<select name="resulttype" id="resulttype">
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_CERTIFICATE%>">PEM  - certificate only</option> 
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_CERTIFICATE_CHAIN%>">PEM  - full certificate chain</option> 
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_PKCS7%>">PKCS#7 certificate</option>
	</select>
	<br />
	<label for="ok"></label>
	<input type="submit" id="ok" value="OK" />
  </fieldset>
</form>

<%@ include file="footer.inc" %>
