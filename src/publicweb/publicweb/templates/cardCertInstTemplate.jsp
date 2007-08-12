<%@ include file="header.jsp" %>

<object classid="$CLASSID" id="g_objClassFactory"></object>
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
        Function ControlExists(objectID)
	        on error resume next
	        ControlExists = IsObject(CreateObject(objectID))
        End Function
        
		Function IsCSPInstalled(sCSPName)
			'on error resume next
			Dim objCSPInformations
			Set objCSPInformations	= g_objClassFactory.CreateObject("X509Enrollment.CCspInformations")                 
			If Err.Number=0 Then
				objCSPInformations.AddAvailableCsps  
			End If
			IsCSPInstalled = IsObject(objCSPInformations.ItemByName(sCSPName))
		End Function
	
    </script>
    <script language="JavaScript" type="text/javascript">
	// <!--
	var success;
	var plugin;
    function myDeclare() {
    	success = false;
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
            }
            else
                document.writeln("<object name=\"iID\" type=\"application/x-iid\" width=\"0\" height=\"0\"></object>");
        } else {
            document.writeln("The CryptoAPI component is not installed.");
        }
    }
        
        function downloadCert()
        {
	        success = true;
            document.iID.SetProperty('Certificate', 'TAG_certToRemove1');
            rv = document.iID.Invoke('DeleteCertificate');
    
            document.iID.SetProperty('Certificate', 'TAG_certToRemove2');
            rv = document.iID.Invoke('DeleteCertificate');
    
            document.iID.SetProperty('Certificate', 'TAG_certToRemove3');
            rv = document.iID.Invoke('DeleteCertificate');
    
            document.iID.SetProperty('Certificate', 'TAG_certToRemove4');
            rv = document.iID.Invoke('DeleteCertificate');
    
            document.iID.SetProperty('Certificate', 'TAG_authb64cert');
            rv = document.iID.Invoke('WriteCertificate');
            if (rv != 0) {
                success = false;
			}
            
            document.iID.SetProperty('Certificate', 'TAG_signb64cert');
            rv = document.iID.Invoke('WriteCertificate');
            if (rv != 0) {
                success = false;
			}
        }
        
        myDeclare();
	    downloadCert();

        // -->
    </script>

    <h1 class="title">Internet Explorer Certificate Enrollment.</h1>

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
    	if (plugin && success) {
	    	document.writeln("<h2>The certificate was successfully downloaded to your card.<\/h2>");
	    } else {
	    	document.writeln("<h2>An error has occurred during the certificate import.<\/h2>");
	    }
    </script>

	<p><a href="javascript:history.back()">Go back</a></p>
<%@ include file="footer.inc" %>
