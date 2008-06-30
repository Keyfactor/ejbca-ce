
	Dim g_objEnroll, g_objPrivateKey, g_objRequest, g_objRequestCMC, g_objCSPInformations, g_certEnrollLoadError
	' Used by apply_exp.jspf
	Function InitVistaCSP()
		On Error resume next
		Set g_objEnroll				= g_objClassFactory.CreateObject("X509Enrollment.CX509Enrollment")
		Set g_objPrivateKey			= g_objClassFactory.CreateObject("X509Enrollment.CX509PrivateKey")
		Set g_objRequest			= g_objClassFactory.CreateObject("X509Enrollment.CX509CertificateRequestPkcs10")
		Set g_objCSPInformations	= g_objClassFactory.CreateObject("X509Enrollment.CCspInformations")                 
		If 0<>Err.Number Then
			g_certEnrollLoadError = Err.Number
		Else
			g_certEnrollLoadError = 0
			g_objCSPInformations.AddAvailableCsps  
		End If
		On Error Goto 0
	End Function

	' Used by apply_exp.jspf
	Function GetCertEnrollCSPList()
	    On Error Resume Next
	    Dim nDefaultCSP, nCSPIndex, CspInformations, CspInformation, oOption
		Set CspInformations = g_objCSPInformations
	    nDefaultCSP = -1
	    ' Add error message if no CSPs are found
	    If CspInformations.Count = 0 Then
		    Set oOption=document.createElement("Option")
		    oOption.text="N/A"
			document.CertReqForm.CspProvider.add(oOption)
        Else 
        	'Loop through all CspInformation objects
        	For nCSPIndex = 0 To CspInformations.Count-1
				Set CspInformation = CspInformations.ItemByIndex(nCSPIndex)
				If True = CspInformation.LegacyCsp Then	'Make sure that it's a Next Generation (CNG) provider
					Set oOption = document.createElement("Option")
					oOption.text = CspInformation.Name
					oOption.Value = CspInformation.Type
					document.CertReqForm.CspProvider.add(oOption)
					If InStr(CspInformation.Name, "Microsoft Enhanced Cryptographic Provider") <> 0 Then
						oOption.selected = True
						nDefaultCSP = nCSPIndex
					End If
					If InStr(CspInformation.Name, "Microsoft Base Cryptographic Provider") <> 0 Then
						If nDefaultCSP = -1 Then nDefaultCSP = nCSPIndex
					End If
       			End If
	        Next
	    End If ' if 0 == CspInformations.Count
	    If nDefaultCSP <> -1 Then
		    Document.CertReqForm.CspProvider.selectedIndex = nDefaultCSP
		Else
		    Document.CertReqForm.CspProvider.selectedIndex = 0	'Select first or N/A
	    End If
    End Function	'GetCertEnrollCSPList

	' Used by apply_exp.jspf
	Function IsCSPInstalled(sCSPName)
		on error resume next
		Dim objCSPInformations
		Set objCSPInformations	= g_objClassFactory.CreateObject("X509Enrollment.CCspInformations")                 
		If Err.Number=0 Then
			objCSPInformations.AddAvailableCsps  
		End If
		IsCSPInstalled = IsObject(objCSPInformations.ItemByName(sCSPName))
	End Function

	' Used by cardCertApply.jsp
	Function ControlExists(objectID)
		on error resume next
		ControlExists = IsObject(CreateObject(objectID))
	End Function

	