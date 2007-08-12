
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

	' Used b apply_exp.jspf
	Function GetCSR()
		GetCSR = ""
		' Get provider name and type
		Dim ProviderName, ProviderType
		ProviderName = document.all.CspProvider.options(document.all.CspProvider.options.selectedIndex).text
		ProviderType = document.all.CspProvider.options(document.all.CspProvider.options.selectedIndex).value
		g_objPrivateKey.ProviderName = ProviderName
		g_objPrivateKey.ProviderType = ProviderType
		g_objPrivateKey.Length = document.CertReqForm.keysize.value
		If ProviderType < 2 Then
			g_objPrivateKey.KeySpec = 1	'AT_KEYEXCHANGE
		Else
			g_objPrivateKey.KeySpec = 2	'AT_SIGNATURE
		End If
		g_objPrivateKey.MachineContext = false
		g_objPrivateKey.KeyProtection = 1	' (XCN_NCRYPT_UI_PROTECT_KEY_FLAG = 1)
		g_objPrivateKey.ExportPolicy = 1	' (XCN_NCRYPT_ALLOW_EXPORT_FLAG = 1)
	    If Document.CertReqForm.enchancedeid.checked then
	    	If Document.CertReqForm.containername = "" Then
				g_objPrivateKey.ContainerName = "\Prime EID IP1 (basic PIN)\E"
			Else
				g_objPrivateKey.ContainerName = Document.CertReqForm.containername.value
			End If
			g_objPrivateKey.Existing = True
		Else
			g_objPrivateKey.Existing = False
		End if
		' Initialize
		Call g_objRequest.InitializeFromPrivateKey(1, g_objPrivateKey, "")	'X509CertificateEnrollmentContext.ContextUser
		Dim X500DistinguishedName
		Set X500DistinguishedName = g_objClassFactory.CreateObject("X509Enrollment.CX500DistinguishedName")
		Call X500DistinguishedName.Encode("CN=6AEK347fw8vWE424", 0)	'XCN_CERT_NAME_STR_NONE
		g_objRequest.Subject = X500DistinguishedName
		' Set hash algo
		Dim CspInformation, CspAlgorithms, CspAlgorithm, nBestIndex, nAlgIndex
		Set CspInformation = g_objCSPInformations.ItemByName(ProviderName)
		Set CspAlgorithms = CspInformation.CspAlgorithms
		nBestIndex = 0
		For nAlgIndex=0 To CspAlgorithms.Count-1
			If CspAlgorithms.ItemByIndex(nAlgIndex).Name = "sha1" Then
				nBestIndex = nAlgIndex
			End If
			If CspAlgorithms.ItemByIndex(nAlgIndex).Name = "md5" AND CspAlgorithms.ItemByIndex(nBestIndex).Name <> "sha1" Then
				nBestIndex = nAlgIndex
			End If
		Next
		Set CspAlgorithm = CspAlgorithms.ItemByIndex(nBestIndex)
		If CspAlgorithm.Type = 2 Then	'XCN_CRYPT_HASH_INTERFACE
			g_objRequest.HashAlgorithm = CspAlgorithm.GetAlgorithmOid(0, 0)	', AlgorithmFlagsNone
		End if
		' Try to create request
		g_objEnroll.InitializeFromRequest(g_objRequest)
		GetCSR = g_objEnroll.CreateRequest(3)	'CRYPT_STRING_BASE64REQUESTHEADER
		if len(GetCSR)<>0 then Exit Function
	End Function	'GetCSR

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

	