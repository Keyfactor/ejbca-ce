<script language="vbscript">
<!--

    Dim useold
    useold=false

	' Used by apply_exp.jspf
    Function GetProviderList()
	
	   Dim CspList, cspIndex, ProviderName
	   On Error Resume Next
	
	   count = 0
	   base = -1
	   enhanced = 0
	   CspList = ""
	   ProviderName = ""
	
	   For ProvType = 0 to 13
	      cspIndex = 0
	      newencoder.ProviderType = ProvType
	      ProviderName = newencoder.enumProviders(cspIndex,0)
	
	      while ProviderName <> ""
	         Set oOption = document.createElement("option")
	         oOption.text = ProviderName
	         oOption.value = ProvType
	         Document.CertReqForm.CspProvider.add(oOption)
	         if ProviderName = "Microsoft Base Cryptographic Provider v1.0" Then
	            base = count
	         end if
	         if ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0" Then
	            enhanced = count
	         end if
	         cspIndex = cspIndex +1
	         ProviderName = ""
	         ProviderName = newencoder.enumProviders(cspIndex,0)
	         count = count + 1
	      wend
	   Next
	   If base = -1 Then
	     useold=true
	     Document.CertReqForm.classid.value="clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1"
	     count = 0
	     enhanced = 0
	     basename = ""
	     enhancedname = ""
	     CspList = ""
	     ProviderName = ""
	
	     For ProvType = 0 to 13
	         cspIndex = 0
	         oldencoder.ProviderType = ProvType
	         ProviderName = oldencoder.enumProviders(cspIndex,0)
	
	        while ProviderName <> ""
	           Set oOption = document.createElement("option")
	           oOption.text = ProviderName
	           oOption.value = ProvType
	           Document.CertReqForm.CspProvider.add(oOption)
	           if ProviderName = "Microsoft Base Cryptographic Provider v1.0" Then
	            base = count
	           end if
	           if ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0" Then
	            enhanced = count
	           end if
	           cspIndex = cspIndex +1
	           ProviderName = ""
	           ProviderName = oldencoder.enumProviders(cspIndex,0)
	           count = count + 1
	        wend
	     Next
	   End If 
	   Document.CertReqForm.CspProvider.selectedIndex = base
	   if enhanced then
	      Document.CertReqForm.CspProvider.selectedIndex = enhanced
	   end if
   End Function

   Function NewCSR(keyflags)
      NewCSR = ""
      szName = "CN=6AEK347fw8vWE424"
       newencoder.reset  
       newencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       newencoder.providerName = options(index).text
       tmpProviderType = options(index).value
       newencoder.providerType = tmpProviderType
       if Document.CertReqForm.enchancedeid.checked then      
         newencoder.ContainerName = "\Prime EID IP1 (basic PIN)\E"
       end if
       newencoder.KeySpec = 2
       if tmpProviderType < 2 Then
          newencoder.KeySpec = 1
       end if
       
       keysize = document.CertReqForm.keysize.value
       keymask = keysize * 65536
       
       newencoder.GenKeyFlags = (keymask + 1) OR keyflags
 
       NewCSR = newencoder.createPKCS10(szName, "")
       if len(NewCSR)<>0 then Exit Function
       newencoder.GenKeyFlags = keymask OR keyflags
       NewCSR = newencoder.createPKCS10(szName, "")
       if len(NewCSR)<>0 then Exit Function
       if newencoder.providerName = "Microsoft Enhanced Cryptographic Provider v1.0" Then
          if MsgBox("1024-bit key generation failed. Would you like to try 512 instead?", vbOkCancel)=vbOk Then
             newencoder.providerName = "Microsoft Base Cryptographic Provider v1.0"
          else
             Exit Function
          end if
       end if
       newencoder.GenKeyFlags = 1 OR keyflags
       NewCSR = newencoder.createPKCS10(szName, "")
       if len(NewCSR)<>0 then Exit Function
       newencoder.GenKeyFlags = keyflags
       NewCSR = newencoder.createPKCS10(szName, "")
       if len(NewCSR)<>0 then Exit Function
       newencoder.GenKeyFlags = 0
       NewCSR = newencoder.createPKCS10(szName, "")
    End Function

   Function OldCSR(keyflags)
      OldCSR = ""
      szName = "CN=6AEK347fw8vWE424"
       oldencoder.reset
       oldencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       oldencoder.providerName = options(index).text
       tmpProviderType = options(index).value
       oldencoder.providerType = tmpProviderType
       if Document.CertReqForm.enchancedeid.checked then         
         oldencoder.ContainerName = "\Prime EID IP1 (basic PIN)\E"
       end if
       oldencoder.KeySpec = 2
       if tmpProviderType < 2 Then
          oldencoder.KeySpec = 1
       end if
       
       keysize = document.CertReqForm.keysize.value
       keymask = keysize * 65536
       
       oldencoder.GenKeyFlags = (keymask + 1) OR keyflags
       OldCSR = oldencoder.createPKCS10(szName, "")
       if len(OldCSR)<>0 then Exit Function
       oldencoder.GenKeyFlags = keymask OR keyflags
       OldCSR = oldencoder.createPKCS10(szName, "")
       if len(OldCSR)<>0 then Exit Function
       if oldencoder.providerName = "Microsoft Enhanced Cryptographic Provider v1.0" Then
          if MsgBox("1024-bit key generation failed. Would you like to try 512 instead?", vbOkCancel)=vbOk Then
             oldencoder.providerName = "Microsoft Base Cryptographic Provider v1.0"
          else
             Exit Function
          end if
       end if
       oldencoder.GenKeyFlags = 1 OR keyflags
       OldCSR = oldencoder.createPKCS10(szName, "")
       if len(OldCSR)<>0 then Exit Function
       oldencoder.GenKeyFlags = keyflags
       OldCSR = oldencoder.createPKCS10(szName, "")
       if len(OldCSR)<>0 then Exit Function
       oldencoder.GenKeyFlags = 0
       OldCSR = oldencoder.createPKCS10(szName, "")
    End Function

    Sub GenReq_OnClick
       Dim TheForm
       Set TheForm = Document.CertReqForm
       err.clear
       If useold Then
         result = OldCSR(2)
       Else
         result = NewCSR(2)
       End If
       if len(result)=0 Then
          result = MsgBox("Unable to generate PKCS#10 certificate request.", 0, "Alert")
          Exit Sub
       end if
       TheForm.pkcs10.Value = result
       TheForm.Submit
       Exit Sub
    End Sub

	' Used by cardCertApply.jsp
	Function ControlExists(objectID)
		on error resume next
		ControlExists = IsObject(CreateObject(objectID))
	End Function

' -->
</script>
