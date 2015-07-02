<!-- Header -->

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1" />
    <meta http-equiv="x-ua-compatible" content="IE=10">
    <title><%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Public Web</title>
	<link rel="shortcut icon" href="images/favicon.png" type="image/png" />
    <link rel="stylesheet" href="styles.css" type="text/css" />
    <script type="text/javascript" src="scripts/functions.js"></script>
    <script type="text/vbscript" src="scripts/functions.vbs"></script>
  </head>

  <body>
    <div id="header">
		<div id="banner">
			<a href="."><img src="images/banner_ejbca-public.png" alt="EJBCA" /></a>
		</div>
    </div>
    <c:if test="${hidemenu != 'true'}">
    <div class="menucontainer">
      <div class="menu">
        <ul>
          <li><div class="menuheader">Enroll</div>
            <ul>
              <li>
                <a href="enrol/browser.jsp">Create Browser Certificate</a>
              </li>
              <li>
                <a href="enrol/server.jsp">Create Certificate from CSR</a>
              </li>
              <li>
                <a href="enrol/keystore.jsp">Create Keystore</a>
              </li>
              <li>
                <a href="enrol/cvcert.jsp">Create CV certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Register</div>
            <ul>
              <li>
                <a href="enrol/reg.jsp">Request Registration</a>
              </li>
            </ul>
          </li>
          <li><div class="menuheader">Retrieve</div>
            <ul>
              <li>
                <a href="retrieve/ca_certs.jsp">Fetch CA Certificates</a>
              </li>
              <li>
                <a href="retrieve/ca_crls.jsp">Fetch CA CRLs</a>
              </li>
              <li>
                <a href="retrieve/list_certs.jsp">List User's Certificates</a>
              </li>
              <li>
                <a href="retrieve/latest_cert.jsp">Fetch User's Latest Certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Inspect</div>
            <ul>
              <li>
                <a href="inspect/request.jsp">Inspect certificate/CSR</a>
              </li>
                <li>
                <a href="retrieve/check_status.jsp">Check Certificate Status</a>
              </li>
            </ul>
          </li>
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
              <a href="adminweb/">Administration</a>
            </li>
              <li>
              <a href="doc/concepts.html/">Documentation</a>
            </li>
            </ul>
          </li>  
        </ul>
      </div>
    </div>
    <div class="main">
      <div class="content">
    </c:if>
    
    <c:if test="${hidemenu == 'true'}">
    <div class="main hidemenu">
      <div class="content hidemenu">
    </c:if>

<!-- Header -->

<object classid="$CLASSID" id="g_objClassFactory"></object>
<!-- Updated w CertEnroll for Vista
Class ID: {884e2049-217d-11da-b2a4-000e7bbb2b09}
-->
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
	    cert = "MIICdgYJKoZIhvcNAQcCoIICZzCCAmMCAQExADALBgkqhkiG9w0BBwGgggJLMIIC" & _
	
		' This function can be moved to functions.vbs when the header is parsed as jsp
		Sub installcertvista
			Dim objEnroll
			Set objEnroll = g_objClassFactory.CreateObject("X509Enrollment.CX509Enrollment")
			Call objEnroll.Initialize(1)	'EnrollmentContext UserContext
			err.clear
			On Error Resume Next
	        Call objEnroll.InstallResponse(0, cert, 6, "")	'AllowNone, , XCN_CRYPT_STRING_BASE64_ANY, pw
	        If err.number = -2146762487	Then	' 0x800b0109 Not trusted root
	        	r = Msgbox("Could not complete the request since, the CAs' certificates were not properly installed.", , "Certificate Management")
			ElseIf err.number <> 0 Then
				r = Msgbox("The certificate could not be installed", , "Certificate Management")
			Else
				r = Msgbox("A new certificate has been installed", , "Certificate Management")
			End If
		End Sub
	
		Sub installcert
			Err.Clear
			On Error Resume Next
			g_objClassFactory.acceptPKCS7(cert)
			If Err.Number <> 0 Then
				r = Msgbox("The certificate could not be installed in this web browser", , "Certificate Management")
			Else
				r = Msgbox ("A new certificate has been installed", , "Certificate Management")
			End if
		End Sub
	
		If InStr(navigator.userAgent, "Windows NT 6") <> 0 Then
			installcertvista
		Else
			installcert
		End If
	</script>

	<h1 class="title">Internet Explorer Certificate enrollment.</h1>
    <p>If the installation was completed without any errors, your certificate has
    been installed in your web browser and you may now start using your certificate.<br />
	You can look at your certificate with &quot;<tt>Tools-&gt;Internet
	Options-&gt;Content-&gt;Certificates</tt>&quot;.</p>
	
<!-- Footer -->
      </div>
    </div>
  </body>
</html>
<!-- Footer -->
