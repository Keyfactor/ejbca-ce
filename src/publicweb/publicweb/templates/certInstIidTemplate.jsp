<%@ include file="header.jsp" %>

	<script type="text/javascript">
	<!--
		// This function is parsed by CertReqServlet/RequestHelper and has to remain in this file.
		function showLocalCSPActiveX() {
			sClassid = '$CLASSID';
			if ( navigator.appName.indexOf("Explorer") != -1 ) {
				document.writeln("<object classid=\""+sClassid+"\" id=\"g_objClassFactory\"></object>");
			}
		}
		showLocalCSPActiveX()
	-->
	</script>
	
	<!--<object classid="$CLASSID" id="g_objClassFactory"></object>-->
	
	
	<script type="text/VBScript">
		Function ControlExists(objectID)
			on error resume next
			ControlExists = IsObject(CreateObject(objectID))
		End Function
		
		' This function also exists in functions.vbs and can be removed when the header is parsed as jsp
		Function IsCSPInstalled(sCSPName)
			on error resume next
			Dim objCSPInformations
			Set objCSPInformations	= g_objClassFactory.CreateObject("X509Enrollment.CCspInformations")
			If Err.Number=0 Then
				objCSPInformations.AddAvailableCsps
			End If
			IsCSPInstalled = IsObject(objCSPInformations.ItemByName(sCSPName))
		End Function
	</script>
	<script type="text/javascript">
	
    var plugin;
    // Used by apply_nav.jspf, and cardCertApply.jsp
	function myDeclare() {
		if (navigator.appName.indexOf("Explorer") == -1) {
			explorer = false;
			plugin = navigator.mimeTypes["application/x-iid"];
		} else {
			explorer = true;
			if ( navigator.userAgent.indexOf("Windows NT 6") == -1 ) {
				plugin = ControlExists("IID.iIDCtl");
			} else {
				plugin = IsCSPInstalled("Net iD - CSP");
			}
		}
		if (plugin) {
			if (explorer) {
				document.writeln("<object name=\"iID\" classid=\"CLSID:5BF56AD2-E297-416E-BC49-00B327C4426E\" width=\"0\" height=\"0\"></object>");
			} else {
				document.writeln("<object name=\"iID\" type=\"application/x-iid\" width=\"0\" height=\"0\"></object>");
			}
		} else {
			document.writeln("The CryptoAPI component is not installed.");
		}
	}
	
		function downloadCert()	{
	        if (plugin) {
			    document.iID.SetProperty('Certificate', 'TAG_cert');
			    rv = document.iID.Invoke('WriteCertificate');
			    if (rv != 0) {
			        alert("Error when writing certificate to card: "+rv);
			    }
	        }
		}
		
		myDeclare();
		downloadCert();
	</script>

	<h1 class="title">Certificate enrollment.</h1>

	<noscript>
		<div class="frame">
		  <div class="label">Note</div>
		  <div class="content">
		    <p>Either Javascript is turned off or your browser cannot 
			handle Javascript.</p>
		  </div>
		</div>
	</noscript>
	
	<script language="JavaScript" type="text/javascript">
		document.writeln("<h2>A new certificate has been installed on your card.</h2>");
	</script>
	<p><a href="javascript:history.back()">Go back</a></p>

<%@ include file="footer.inc" %>
