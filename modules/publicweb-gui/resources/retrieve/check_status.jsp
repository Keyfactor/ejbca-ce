<%@ include file="header.jsp" %>
<h1 class="title">Check certificate status</h1>
<p>Enter the serial number of a certificate (in hexadecimal form) and click 'Check revocation'
   to see if the certificate is revoked.
</p>
<form action="check_status_result.jsp" enctype="x-www-form-encoded" method="post">
  <fieldset>
    <legend>Certificate data</legend>

    <input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" />
	<input type="hidden" name="cmd" value="revoked" />

	<label for="issuer">Issuer DN</label>
	<input name="issuer" id="issuer" type="text" size="60" accesskey="i" />
	<br />
	<label for="serno">Serial No.</label>
	<input name="serno" id="serno" type="text" size="40" accesskey="s" />

	<br />
	<label for="ok"></label>
	<input type="submit" id="ok" value="Check revocation" />
  </fieldset>
</form>
<%@ include file="footer.inc" %>

