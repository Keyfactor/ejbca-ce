<HEAD>
<TITLE>EJBCA IE Certificate Enroll</TITLE>

 
<link rel="stylesheet" href="../indexmall.css" type="text/css">
<object
   classid="clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1"
   CODEBASE="/CertControl/xenroll.cab#Version=5,131,3659,0"
   id="newencoder">
 </object>
<object
   classid="clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1"
   id="oldencoder">
 </object>
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

<SCRIPT LANGUAGE=VBSCRIPT>
<!--
   Dim useold
   useold=false   

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
         Set oOption = document.createElement("OPTION")
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
           Set oOption = document.createElement("OPTION")
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
      szName          = "CN=6AEK347fw8vWE424"
       newencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       newencoder.providerName = options(index).text
       tmpProviderType = options(index).value
       newencoder.providerType = tmpProviderType
       newencoder.KeySpec = 2
       if tmpProviderType < 2 Then
          newencoder.KeySpec = 1
       end if
       newencoder.GenKeyFlags = &h04000001 OR keyflags
       NewCSR = newencoder.createPKCS10(szName, "")
       if len(NewCSR)<>0 then Exit Function
       newencoder.GenKeyFlags = &h04000000 OR keyflags
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
      szName          = "CN=6AEK347fw8vWE424"
       oldencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       oldencoder.providerName = options(index).text
       tmpProviderType = options(index).value
       oldencoder.providerType = tmpProviderType
       oldencoder.KeySpec = 2
       if tmpProviderType < 2 Then
          oldencoder.KeySpec = 1
       end if
       oldencoder.GenKeyFlags = &h04000001 OR keyflags
       OldCSR = oldencoder.createPKCS10(szName, "")
       if len(OldCSR)<>0 then Exit Function
       oldencoder.GenKeyFlags = &h04000000 OR keyflags
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
-->      
</SCRIPT>


</HEAD>
<BODY onLoad="GetProviderList()" bgcolor="#ffffff" link="black" vlink="black" alink="black">
<center>
  <strong class="titel"><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A</span> 
  IE Certificate Enrollment </strong> 
</center>

<HR>
Welcome to certificate enrollment. <BR>
<p>
If you want to, you can manually install the CA certificate(s) in your browser, otherwise this will be done automatically 
when your certificate is retrieved.

<P>Install CA certificates:

<%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Collection chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()), caid);
    if (chain.size() == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<li><a href=\"../webdist/certdist?cmd=iecacert&level=0&caid="+caid+"\">Root CA</a></li>");
        if (chain.size() > 1) {
            for (int i=chain.size()-1;i>0;i--) {
                out.println("<li><a href=\"../webdist/certdist?cmd=iecacert&level="+i+"&caid="+caid+"\">CA</a></li>");
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<HR>

<FORM NAME="patched" ACTION="<%=THIS_FILENAME%>"  METHOD=POST>
        <INPUT NAME='<%= ACTION %>' TYPE="hidden" VALUE='<%=ACTION_GENERATETOKEN %>'> 
        <INPUT NAME="<%=HIDDEN_BROWSER%>" TYPE="hidden" VALUE="<%= browser %>">
	<INPUT NAME="<%=TEXTFIELD_USERNAME %>"  TYPE="hidden" VALUE="<%=username%>">
	<INPUT NAME="<%=TEXTFIELD_PASSWORD %>" TYPE="hidden"  VALUE="<%=password%>">
</FORM>

<FORM NAME="CertReqForm" ACTION="certreq" ENCTYPE=x-www-form-encoded METHOD=POST>
 
 <b>NOTE!</b> If you do not get a list of CSPs in the list below, you may have to upgrade Internet Explorer
 with the new certificate enrollment control (see Microsoft support issue Q323172).
 <br>Please perform a 'Windows Update'.
 <hr>
 Please give your username and password, then click OK to fetch your certificate.<BR>

	<INPUT NAME=user TYPE="hidden" VALUE="<%=username%>">
	<INPUT NAME=password TYPE="hidden"  VALUE="<%=password%>">
	<INPUT NAME=classid TYPE="hidden"  VALUE="">

    <P>Please choose the CSP you wish to use from the list below (the default is probably good):</P>
    <SELECT NAME="CspProvider">
    </SELECT></P>

    <INPUT TYPE="hidden" NAME="pkcs10" VALUE="">

<INPUT type="button" value="OK" name="GenReq">

</FORM>
</BODY>
</HTML>

