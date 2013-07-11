<!-- Header -->

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<c:set var="hidemenu" value="${param['hidemenu'] == 'true' ? 'true' : 'false'}" />

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
     "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1" />
    <title><%= org.ejbca.config.InternalConfiguration.getAppNameCapital() %> Public Web</title>
	<link rel="shortcut icon" href="../images/favicon.png" type="image/png" />
    <link rel="stylesheet" href="../styles.css" type="text/css" />
    <script type="text/javascript" src="../scripts/functions.js"></script>
    <script type="text/vbscript" src="../scripts/functions.vbs"></script>
  </head>

  <body>
    <div id="header">
		<div id="banner">
			<a href="../"><img src="../images/ejbca_pki_by_primekey_logo.png" alt="EJBCA" /></a>
		</div>
    </div>
    <div class="menucontainer">
      <c:if test="${hidemenu != 'true'}">
      <div class="menu">
        <ul>
          <li><div class="menuheader">Enroll</div>
            <ul>
              <li>
                <a href="../enrol/browser.jsp">Create Browser Certificate</a>
              </li>
              <li>
                <a href="../enrol/server.jsp">Create Server Certificate</a>
              </li>
              <li>
                <a href="../enrol/keystore.jsp">Create Keystore</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Retrieve</div>
            <ul>
              <li>
                <a href="../retrieve/ca_certs.jsp">Fetch CA Certificates</a>
              </li>
              <li>
                <a href="../retrieve/ca_crls.jsp">Fetch CA CRLs</a>
              </li>
              <li>
                <a href="../retrieve/latest_cert.jsp">Fetch User's Latest Certificate</a>
              </li>
            </ul>
          </li>  
          <li><div class="menuheader">Miscellaneous</div>
            <ul>
              <li>
                <a href="../retrieve/list_certs.jsp">List User's Certificates</a>
              </li>
              <li>
                <a href="../retrieve/check_status.jsp">Check Certificate Status</a>
              </li>
              <li>
              <a href="../adminweb/">Administration</a>
            </li>
            </ul>
          </li>  
        </ul>
      </div>
      </c:if>
    </div>
    <div class="main">
      <div class="content">
<!-- Header -->

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
		<div class="message">
		  <div class="label">Note</div>
		  <div class="content">
		    <p>Either JavaScript is turned off or your browser cannot 
			handle JavaScript.</p>
		  </div>
		</div>
	</noscript>
	
	<script type="text/javascript">
		document.writeln("<h2>A new certificate has been installed on your card.</h2>");
	</script>

<!-- Footer -->
      </div>
    </div>
  </body>
</html>
<!-- Footer -->
