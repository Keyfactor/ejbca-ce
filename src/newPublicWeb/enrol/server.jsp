<%@ include file="header.jsp" %>
<p>Please give your username and password, paste the PEM-formated PKCS10 certification request into the field below and
   click OK to fetch your certificate. 
</p><p>
   A PEM-formatted request is a BASE64 encoded PKCS10 request between the two lines:
</p><pre>
   -----BEGIN CERTIFICATE REQUEST-----
   -----END CERTIFICATE REQUEST-----
</pre>
<form name="EJBCA" action="../certreq" enctype="x-www-form-encoded" method="post">
	<label for="user">Username</label> <input type="text" size="10" name="user" value="foo"><br />
	<label for="password">Password</label> <input type="text" size="10" name="password" value="foo123"><br />
	<br />
	<textarea rows="15" cols="70" name="pkcs10req" wrap="physical"></textarea><br />
	<br />
	<select name="resulttype">
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_CERTIFICATE%>">PEM Certificate</option> 
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_PKCS7%>">PKCS7</option>
	</select>
	<br />
<input type="submit" value="OK">
</form>
<%@ include file="footer.inc" %>
