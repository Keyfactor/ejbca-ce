
	// Used in apply_exp.jspf
	function showCSPActiveX() {
		if (navigator.appName.indexOf("Explorer") != -1) {
		    if ( navigator.userAgent.indexOf("Windows NT 6") != -1 ) {
				document.writeln("<object classid=\"clsid:884e2049-217d-11da-b2a4-000e7bbb2b09\" id=\"g_objClassFactory\" height=\"0\" width=\"0\" ></object>");
			} else {
				document.writeln("<object classid=\"clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1\" id=\"newencoder\" codebase=\"/CertControl/xenroll.cab#Version=5,131,3659,0\" height=\"0\" width=\"0\" ></object>");
				document.writeln("<object classid=\"clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1\" id=\"oldencoder\" height=\"0\" width=\"0\" ></object>");
			}
		}
	}

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
		}
		// if the plugin is not available we silently ignore it.
	}

    function selectKey() {
       if ( plugin ) {
          //document.writeln("Plugin installed<br>");
          var doTryNext = true;
          for ( i=0; doTryNext; i++ ) {
             sKey = document.iID.EnumProperty('Key',i);
             doTryNext = sKey!="";
             if ( doTryNext ) {
                aKey = sKey.split(";");
            if ( parseInt(aKey[2],16)<0x47 )
                   document.writeln("<option value=\""+sKey+"\">Slot: "+aKey[0]+". Key label: "+aKey[3]+". Key type: "+aKey[4]+". Key size: "+aKey[6]+".</option>");
             }
          }
       }
    }

    // Used by cardCertApply.jsp
    function generate_card_pkcs10()
    {
        document.iID.SetProperty('Base64', 'true');
        document.iID.SetProperty('URLEncode', 'false');
        document.iID.SetProperty('Password', '');
        document.iID.SetProperty('TokenLabel', "Prime EID IP1 (basic PIN)");
        document.iID.SetProperty('Subject', "2.5.4.5=197205250777");
        document.iID.SetProperty('KeyId', '45');
    
        rv = document.iID.Invoke('CreateRequest');
        if (rv == 0)
            document.form1.authpkcs10.value = document.iID.GetProperty("Request");
        else
            document.form1.authpkcs10.value = rv;
    
        document.iID.SetProperty('Base64', 'true');
        document.iID.SetProperty('URLEncode', 'false');
        document.iID.SetProperty('Password', '');
        document.iID.SetProperty('TokenLabel', "Prime EID IP1 (signature PIN)");
        document.iID.SetProperty('Subject', "2.5.4.5=197205250777");
        document.iID.SetProperty('KeyId', '46');
    
        rv = document.iID.Invoke('CreateRequest');
        if (rv == 0)
            document.form1.signpkcs10.value = document.iID.GetProperty("Request");
        else
            document.form1.signpkcs10.value = rv;

        document.form1.submit();    
    }
    

