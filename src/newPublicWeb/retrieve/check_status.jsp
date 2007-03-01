<%@ include file="header.jsp" %>
<h1 class="title">Check Certificate Status</h1>
<p>Enter the serial number of a certificate and click 'Check revocation'
  to see if the certificate is revoked.
  <br />
<form action="check_status_result.jsp" enctype=x-www-form-encoded method="GET">
  <fieldset>
    <legend>Certificate data</legend>
	<input type="hidden" name="cmd" value="revoked">
	<label for="issuer">Issuer DN</label>
	<input name="issuer" type=text size=30 value="c=SE, O=AnaTom, CN=TestCA">
	<br>
	<label for="serno">Serial number (hex)</label>
	<input name="serno" type=text size=30 value="">
	<br>
	<br>
	<input type="submit" value="Check revocation">
  </fieldset>
</form>
<%@ include file="footer.inc" %>

