<%@page contentType="text/html"%>
<%@ page language="Java" import="javax.naming.*,javax.rmi.*,java.util.*,java.security.cert.*,se.anatom.ejbca.ca.sign.*, se.anatom.ejbca.log.Admin"%>

<HTML>
<HEAD>
<TITLE>EJBCA IE Demo Certificate Enroll</TITLE>
<link rel="stylesheet" href="indexmall.css" type="text/css">
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
       szName = Document.CertReqForm.user.value
       newencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       encoder.providerName = options(index).text
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
       szName = Document.CertReqForm.user.value
       oldencoder.HashAlgorithm = "MD5"
       err.clear
       On Error Resume Next
       set options = document.all.CspProvider.options
       index = options.selectedIndex
       encoder.providerName = options(index).text
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
       if len(TheForm.cn.Value)=0 Then
           MsgBox("Please fill in the name field!")
           TheForm.cn.focus()
           Exit Sub
       end if
       TheForm.user.Value=TheForm.dn.Value+TheForm.cn.value
       if len(TheForm.email.Value)>0 Then
          If InStr(1, TheForm.email.Value, "@", 1)<2 Then
             MsgBox("Email address should contain an @ character!")
             Exit Sub
          end if
       end if
       If useold Then
         result = OldCSR(2)
       Else
         result = NewCSR(2)
       End If
       if len(result)=0 Then
          result = MsgBox("Unable to generate PKCS#10 certificate request.", 0, "Alert")
          Exit Sub
       end if
       TheForm.pkcs10req.Value = result
       TheForm.Submit
       Exit Sub
    End Sub
-->      
</SCRIPT>

</HEAD>
<BODY onLoad="GetProviderList()" bgcolor="#ffffff" link="black" vlink="black" alink="black">
<center>
  <strong><span class="E">E</span><span class="J">J</span><span class="B">B</span><span class="C">C</span><span class="A">A 
  </span><span class="titel">IE Demo Certificate Enrollment</span> </strong> 
</center>

<HR width="450">
<div align="center">Welcome to the certificate enrollment. <BR>
  If you haven't done so already, you must first install <br>
  the CA certificate(s) in your browser. </div>
<P align="center">Install CA certificates: 
<%
try  {
    InitialContext ctx = new InitialContext();
    ISignSessionHome home = home = (ISignSessionHome) PortableRemoteObject.narrow(
            ctx.lookup("RSASignSession"), ISignSessionHome.class );
    ISignSessionRemote ss = home.create();
    Certificate[] chain = ss.getCertificateChain(new Admin(Admin.TYPE_PUBLIC_WEB_USER, request.getRemoteAddr()));
    if (chain.length == 0) {
        out.println("No CA certificates exist");
    } else {
        out.println("<li><a href=\"../webdist/certdist?cmd=iecacert&level=0\">Root CA</a></li>");
        if (chain.length > 1) {
            for (int i=chain.length-1;i>0;i--) {
                out.println("<li><a href=\"../webdist/certdist?cmd=iecacert&level="+i+"\">CA</a></li>");
            }
        }
    }
} catch(Exception ex) {
    ex.printStackTrace();
}                                             
%>
<HR align="center" width="550">
<FORM NAME="CertReqForm" ACTION="democertreq" ENCTYPE=x-www-form-encoded METHOD=POST>
  <div align="center">PLEASE NOTE! Certificates issued by this CA comes with absolutely<br>
    NO WARRANTY whatsoever. NO AUTHENTICATION is<br>
    performed on the information entered below. </div>
  <p align="center"> Please fill out the form, then click OK to fetch your certificate.<br>
    <INPUT name=user type=hidden>
    <br>
    <INPUT name=dn type=hidden value="C=SE,O=AnaTom,CN=">
    <INPUT NAME=classid TYPE="hidden"  VALUE="">
    <br>
    Full name, e.g. Sven Svensson: 
    <INPUT NAME=cn TYPE=text SIZE=25 maxlength="60" class="input">
  <p align="center"> E-mail (optional): 
    <INPUT name=email TYPE=text size=25 maxlength="60" class="input">

  <p align="center">If necessary, choose the CSP you wish to use from the list 
    below<br>
    (we recommend the default for most users):<br>
    <br>
  <div align="center">
    <p>
      <SELECT NAME="CspProvider">
      </SELECT>
      <INPUT TYPE="hidden" NAME="pkcs10req" VALUE="">
    </p>
    <p>
      <INPUT type="button" value="OK" name="GenReq">
    </p>
  </div>
</FORM>



</BODY>
</HTML>