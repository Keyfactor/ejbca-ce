<%@ include file="header.jsp" %>
<h1 class="title">Enrol For Server Certificate</h1>
<p>Please give your username and password, paste the PEM-formated PKCS10 certification request into the field below and
   click OK to fetch your certificate. 
</p>

<div class="frame">
   <div class="label">Note</div>
   <div class="content">
  	  <p>A PEM-formatted request is a BASE64 encoded PKCS10 request between the two lines:</p>
  	  <pre>
	     -----BEGIN CERTIFICATE REQUEST-----
	     -----END CERTIFICATE REQUEST-----
	  </pre>
   </div>
</div>

<form name="EJBCA" action="../certreq" enctype="x-www-form-encoded" method="post">
  <fieldset name="Enrol">
	<label for="user">Username</label> <input type="text" size="10" name="user" value="foo" accesskey="u" />
	<br />
	<label for="password">Password</label> <input type="text" size="10" name="password" value="foo123" accesskey="p" />
	<br />
	<br />
	<textarea rows="15" cols="70" name="pkcs10req" wrap="physical"></textarea>
	<br />
	<br />
	<label for="resulttype">Result type</label>
	<select name="resulttype" accesskey="r">
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_CERTIFICATE%>">PEM Certificate</option> 
		<option value="<%=org.ejbca.ui.web.RequestHelper.ENCODED_PKCS7%>">PKCS7</option>
	</select>
	<br />
	<label for="dummy"> </label>
	<input type="submit" value="OK">
  </fieldset>
</form>

<%@ include file="footer.inc" %>
