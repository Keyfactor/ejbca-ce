<%@ include file="header.jsp" %>

<object classid="$CLASSID" id="keystore"></object>
<!-- New updated enrollment activeX-control 2002-09-02 (Q323172)
New Xenroll.dll information:
Class ID: {127698e4-e730-4e5c-a2b1-21490a70c8a1}
sXEnrollVersion="5,131,3659,0"

New Scrdenrl.dll information:
Class ID: {c2bbea20-1f2b-492f-8a06-b1c5ffeace3b}
sScrdEnrlVersion="5,131,3642,0"
-->
<!-- Old Xenroll.dll information:
Class ID: {43F8F289-7A20-11D0-8F06-00C04FC295E1}

Old Scrdenrl.dll information:
Class ID: {80CB7887-20DE-11D2-8D5C-00C04FC29D45}
-->

	<script language="VBScript" type="text/vbscript">
	  Sub installcert
	    cert = "MIICdgYJKoZIhvcNAQcCoIICZzCCAmMCAQExADALBgkqhkiG9w0BBwGgggJLMIIC" & _
	    err.clear
	    On Error Resume Next
	    keystore.acceptPKCS7(cert)
	    if err.number <> 0 then
	      r = Msgbox("The certificate could not be installed in this web browser", , "Certificate Management")
	      rem document.write("The certificate could not be installed.")
	      rem window.navigate("NoInstall.html")
	    else
	      r = Msgbox ("A new certificate has been installed", , "Certificate Management")
	    end if
	  End Sub
	
	  installcert
	</script>

	<h1 class="title">Internet Explorer Certificate enrollment.</h1>
    <p>Your certificate has	been installed in your web browser.<br>
	You may now start using your certificate.<br>
	You can look at your certificate with &quot;<tt>Tools-&gt;Internet
	Options-&gt;Content-&gt;Certificates</tt>&quot;.</p>

	<p><a href="javascript:history.back()">Go back</a></p>

<%@ include file="footer.inc" %>
