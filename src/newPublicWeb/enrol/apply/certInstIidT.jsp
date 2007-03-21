<%@ include file="header.jsp" %>

	<object classid="$CLASSID" id="keystore"></object>
	<script type="text/VBScript">
		Function ControlExists(objectID)
			on error resume next
			ControlExists = IsObject(CreateObject(objectID))
		End Function
	</script>
	<script type="text/javascript">
	
	    function myDeclare()
	    {
	        if (navigator.appName.indexOf("Explorer") == -1)
	        {
	            explorer = false;
	            plugin = navigator.mimeTypes["application/x-iid"];
	        }
	        else
	        {
	            explorer = true;
	            plugin = ControlExists("IID.iIDCtl");
	        }
	        if (plugin)
	        {
	            if (explorer)
		            document.writeln("<object name='iID' classid='CLSID:5BF56AD2-E297-416E-BC49-00B327C4426E' width='0' height='0'><\/object>");
		        else
	                document.writeln("<object name='iID' type='application/x-iid' width='0' height='0'><\/object>");
	        }
	        else
	        {
	            document.writeln("<h2>NetID is not installed.<\/h2");
	        }
	    }
	
		function downloadCert()
		{
		    document.iID.SetProperty('Certificate', 'TAG_cert');
		    rv = document.iID.Invoke('WriteCertificate');
		    if (rv != 0)
		        alert("Error when writing certificate to card: "+rv);
		}
		
		myDeclare();
		downloadCert();
	</script>

	<h1 class="title">Mozilla Certificate enrollment.</h1>

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
		document.writeln("<h2>A new certificate has been installed on your card.<\/h2>");
	</script>
	<p><a href="javascript:history.back()">Go back</a></p>

<%@ include file="footer.inc" %>
