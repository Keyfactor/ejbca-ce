<%               
  TreeMap rootcaprofiles = info.getAuthorizedRootCACertificateProfileNames();
  TreeMap subcaprofiles = info.getAuthorizedSubCACertificateProfileNames();    
  
  TreeMap casigners = info.getCANames();

  HashMap certprofileidtonamemap = info.getCertificateProfileIdToNameMap();
  HashMap publisheridtonamemap = ejbcawebbean.getInformationMemory().getPublisherIdToNameMap();

  int[]    availablecatokentypes = {CATokenInfo.CATOKENTYPE_P12};  
  String[] availablecatokentypetexts = {"SOFTCATOKEN"};
 
  row = 0;

  CAInfo cainfo = null;
  X509CAInfo x509cainfo = null;
  
  String catokentext = null;
  CATokenInfo catokeninfo = null;
  
  boolean revokable = true;
  boolean signbyexternal = false;
  boolean isexternal = false;
  boolean waitingresponse = false;  

  if(editca){
    cainfo = cabean.getCAInfo(caid).getCAInfo();
    catokeninfo = cainfo.getCATokenInfo();

    if(catokeninfo instanceof SoftCATokenInfo)
      catokentext = ejbcawebbean.getText("SOFT"); 

    revokable = cainfo.getStatus() != SecConst.CA_REVOKED && cainfo.getStatus() != SecConst.CA_EXTERNAL && cainfo.getStatus() != SecConst.CA_WAITING_CERTIFICATE_RESPONSE;

    signbyexternal = cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
    isexternal = cainfo.getStatus() == SecConst.CA_EXTERNAL;
    waitingresponse = cainfo.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE;

    x509cainfo = (X509CAInfo) cainfo;
  }

  OCSPCAServiceInfo ocspcainfo = null; 
  java.security.cert.X509Certificate ocspcert = null; 
  if(editca && !isexternal){
    Iterator iter = x509cainfo.getExtendedCAServiceInfos().iterator();       
    while(iter.hasNext()){
      ExtendedCAServiceInfo serviceinfo = (ExtendedCAServiceInfo) iter.next();
      if(serviceinfo instanceof OCSPCAServiceInfo){
        ocspcainfo = (OCSPCAServiceInfo) serviceinfo;
        if(ocspcainfo.getOCSPSignerCertificatePath() != null)
          ocspcert = (java.security.cert.X509Certificate) ocspcainfo.getOCSPSignerCertificatePath().get(0);
      }
     }
   }

%>
<SCRIPT language="JavaScript">
<!--  
<% if(!editca){ %>
  var rootcaprofiles = new Array(<%= rootcaprofiles.keySet().size()%>);
  var subcaprofiles = new Array(<%= subcaprofiles.keySet().size()%>);
  var NAME       = 0;
  var ID         = 1;
<%
      Iterator iter = rootcaprofiles.keySet().iterator();
      int i = 0;
      while(iter.hasNext()){
        String next = (String) iter.next();  %> 
    rootcaprofiles[<%=i%>] = new Array(2);
    rootcaprofiles[<%=i%>][NAME] = "<%= next %>";      
    rootcaprofiles[<%=i%>][ID] = <%= rootcaprofiles.get(next) %>;
   <%   i++; 
      }
 
      iter = subcaprofiles.keySet().iterator();
      i = 0;
      while(iter.hasNext()){
        String next = (String) iter.next();  %> 
    subcaprofiles[<%=i%>] = new Array(2);
    subcaprofiles[<%=i%>][NAME] = "<%= next %>";      
    subcaprofiles[<%=i%>][ID] = <%= subcaprofiles.get(next) %>;
   <%   i++; 
      }
%>
      
function fillCertProfileField(){
   var certprofselect   =  document.ca.<%=SELECT_CERTIFICATEPROFILE%>; 

   var num = certprofselect.length;
   for( i=num-1; i >= 0; i-- ){
       certprofselect.options[i]=null;
    }   
 
   var profiles = subcaprofiles;
   if(document.ca.<%= SELECT_SIGNEDBY %>.options[document.ca.<%= SELECT_SIGNEDBY %>.options.selectedIndex].value == <%= CAInfo.SELFSIGNED %>)
      profiles = rootcaprofiles;

   for( i=0; i < profiles.length; i ++){
     certprofselect.options[i]=new Option(profiles[i][NAME],
                                     profiles[i][ID]);    
     
   }
}

  <% if(!processrequest){ %>
function isExternal(){
   var makebutton      =  document.ca.<%= BUTTON_MAKEREQUEST %>; 
   var createbutton    =  document.ca.<%= BUTTON_CREATE %>; 
   var validityfield   =  document.ca.<%=TEXTFIELD_VALIDITY%>;
   var certproffield   =  document.ca.<%=SELECT_CERTIFICATEPROFILE %>;
   var subjectaltname  =  document.ca.<%=TEXTFIELD_SUBJECTALTNAME%>;
   var policyidfield   =  document.ca.<%=TEXTFIELD_POLICYID%>;
   var activateocsp    =  document.ca.<%=CHECKBOX_ACTIVATEOCSPSERVICE%>;
   

   makebutton.disabled = true;
   createbutton.disabled = false; 
   validityfield.disabled = false; 
   certproffield.disabled = false; 
   subjectaltname.disabled = false; 
   policyidfield.disabled = false; 
   activateocsp.disabled = false;
   activateocsp.checked = true;   

   if(document.ca.<%= SELECT_SIGNEDBY %>.options[document.ca.<%= SELECT_SIGNEDBY %>.options.selectedIndex].value == <%= CAInfo.SIGNEDBYEXTERNALCA %>){
      makebutton.disabled = false;   
      createbutton.disabled = true;
      validityfield.disabled = true; 
      certproffield.disabled = true; 
      subjectaltname.disabled = true; 
      policyidfield.disabled = true;   
      activateocsp.disabled = true;
      activateocsp.checked = false;   
   } 
}


    <% } %>
<% }
   if(revokable){ %>
function confirmrevokation(){
  var returnval = false;
  if(document.ca.<%= SELECT_REVOKEREASONS %>.options.selectedIndex == -1){
     alert("<%= ejbcawebbean.getText("AREVOKEATIONREASON") %>"); 
     returnval = false;
  }else{
    returnval = confirm("<%= ejbcawebbean.getText("AREYOUSUREREVOKECA") %>");
  } 
  return returnval;
}

<%  }  

   if(editca && !isexternal){ %>
function confirmrenewal(){
    
  return confirm("<%= ejbcawebbean.getText("AREYOUSURERENEWCA") %>") && checkallfields();     
}

  <% if(ocspcert != null){ %>
function viewocspcert(){        
    var link = "<%= VIEWCERT_LINK %>?<%= CERTSERNO_PARAMETER %>=<%= java.net.URLEncoder.encode(ocspcert.getSerialNumber().toString(16) + "," + CertTools.getIssuerDN(ocspcert),"UTF-8")%>";
    link = encodeURI(link);
    window.open(link, 'view_cert','height=600,width=500,scrollbars=yes,toolbar=no,resizable=1');
}
 
function checkactivateocsp(){ 
  if(document.ca.<%=CHECKBOX_ACTIVATEOCSPSERVICE%>.checked){
    document.ca.<%=BUTTON_REVOKERENEWOCSPCERTIFICATE%>.disabled = false;
  }
  else{    
    document.ca.<%=BUTTON_REVOKERENEWOCSPCERTIFICATE%>.disabled = true;
  }
}

<% } 
}  %>  

function checkusefield(usefield, criticalfield){
  var usebox = eval("document.ca." + usefield);
  var cribox = eval("document.ca." + criticalfield);
  if(usebox.checked){
    cribox.disabled = false;
  }
  else{
    cribox.checked=false;
    cribox.disabled = true;
  }
}

function checkallfields(){
    var illegalfields = 0;
    

    <% if(!editca){ %>
    if(!checkfieldforcompletednchars("document.ca.<%=TEXTFIELD_SUBJECTDN%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText("SUBJECTDN") %>"))
      illegalfields++;
    if((document.ca.<%= TEXTFIELD_SUBJECTDN %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText("SUBJECTDN")%>");
      illegalfields++;
    }
   <% } %> 

    <% if(!editca || (editca && cainfo.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA)){ %>
    if(!checkfieldfordecimalnumbers("document.ca.<%=TEXTFIELD_VALIDITY%>","<%= ejbcawebbean.getText("ONLYDECNUMBERSINVALIDITY") %>"))
      illegalfields++;
    if((document.ca.<%= TEXTFIELD_VALIDITY %>.value == "") && document.ca.<%= SELECT_SIGNEDBY %>.options[document.ca.<%= SELECT_SIGNEDBY %>.options.selectedIndex].value != <%= CAInfo.SIGNEDBYEXTERNALCA %>){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText("VALIDITY")%>");
      illegalfields++;
    }   
    <% }

       if(catype == CAInfo.CATYPE_X509){ 
         if(!editca){%>        
    if(!checkfieldforcompletednchars("document.ca.<%=TEXTFIELD_SUBJECTALTNAME%>","<%= ejbcawebbean.getText("ONLYCHARACTERS") + " " + ejbcawebbean.getText("SUBJECTALTNAME")%>"))
      illegalfields++;
   if(!checkfieldforipaddess("document.ca.<%=TEXTFIELD_POLICYID%>","<%= ejbcawebbean.getText("ONLYNUMBERALSANDDOTS") + ejbcawebbean.getText("POLICYID")%>"))
      illegalfields++;
      <% } %>
      <% if(!processrequest){ %>
    if(!checkfieldfordecimalnumbers("document.ca.<%=TEXTFIELD_CRLPERIOD%>","<%= ejbcawebbean.getText("ONLYDECNUMBERSINCRLPERIOD") %>"))
      illegalfields++;
    if((document.ca.<%= TEXTFIELD_CRLPERIOD %>.value == "")){
      alert("<%= ejbcawebbean.getText("YOUAREREQUIRED") + " " + ejbcawebbean.getText("CRLPERIOD")%>");
      illegalfields++;
    }
    <%  } 
      }  %> 
     return illegalfields == 0;  
   } 
-->

</SCRIPT>
<body <% if(!editca) out.write(" onload='fillCertProfileField()' "); %>> 
<div align="center"> 
  <% if(processrequest){ %>
  <h2><%= ejbcawebbean.getText("PROCESSREQUEST") %><br></h2>
  <h3><%= ejbcawebbean.getText("CANAME")+ " : " + caname %><br>
      <%= ejbcawebbean.getText("ONLYTHEPUBLICKEY") %></h3>
  <% }else{
       if(editca){ %>
  <h2><%= ejbcawebbean.getText("EDITCA") %><br></h2>
  <h3><%= ejbcawebbean.getText("CANAME")+ " : " + cainfo.getName() %> </h3>
  <%   }else{ %>
   <h2><%= ejbcawebbean.getText("CREATECA") %><br></h2>
   <h3><%= ejbcawebbean.getText("CANAME")+ " : " + caname %> </h3>
  <%   }
     }%>
</div>
  <table width="100%" border="0" cellspacing="3" cellpadding="3">
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="left"> 
          <h3>&nbsp;</h3>
        </div>
      </td>
      <td width="50%" valign="top"> 
        <div align="right">
        <A href="<%=THIS_FILENAME %>"><u><%= ejbcawebbean.getText("BACKTOCAS") %></u></A>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
   <!--     <A  onclick='displayHelpWindow("<%= ejbcawebbean.getHelpfileInfix("ca_help.html") + "#cas"%>")'>
        <u><%= ejbcawebbean.getText("HELP") %></u> </A></div> -->
      </td>
    </tr>
   <% if(!processrequest){ %>
    <form name="changecatype" action="<%= THIS_FILENAME %>" method="post">
      <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHOOSE_CATYPE %>'>
      <tr id="Row<%=row++%2%>"> 
        <td width="50%"  align="right"> 
          <%= ejbcawebbean.getText("TYPEOFCA") %>
        </td>
        <td width="50%" valign="top"> 
           X509
        </td>
      </tr>
    </form>

    <% if(!isexternal) {
         if(editca){ %>
        <tr id="Row<%=row++%2%>">
          <td width="50%"  align="right">          
            <%= ejbcawebbean.getText("CATOKENTYPE") %>
         </td>	 
	 <td><%= catokentext %>
         </td>	
      </tr>

    <%   }else{ %>
    <form name="changecatokentype" action="<%= THIS_FILENAME %>" method="post">
       <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CHOOSE_CATOKENTYPE %>'>
       <tr>
          <td width="50%"  align="right">          
            <%= ejbcawebbean.getText("CATOKENTYPE") %>
         </td>	 
	 <td><select name="<%=SELECT_CATOKEN %>" size="1" onchange="document.changecatokentype.submit()"'>
                <% for(int i=0; i < availablecatokentypes.length; i++){%>                
	 	<option value="<%=availablecatokentypes[i] %>" <% if(catokentype == availablecatokentypes[i])
                                             out.write("selected"); %>>
 
                         <%= availablecatokentypetexts[i] %>
                </option>
                <% } %>
	     </select>
         </td>	
      </tr>
    </form>
    <%   }
       }
     }%>
  <form name="ca" method="post" action="<%=THIS_FILENAME %>" ENCTYPE="post">
    <input type="hidden" name='<%= HIDDEN_CATOKENTYPE %>' value='<%=catokentype %>'>
    <input type="hidden" name='<%= HIDDEN_CATYPE %>' value='<%=catype %>'>
  <% if(processrequest){ %>  
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_PROCESSREQUEST2 %>'>
    <input type="hidden" name='<%= HIDDEN_CANAME %>' value='<%=caname %>'>
  <% } else { %>
  <%   if(editca){ %>  
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_EDIT_CA %>'>
    <input type="hidden" name='<%= HIDDEN_CAID %>' value='<%=caid %>'>
    <input type="hidden" name='<%= HIDDEN_CANAME %>' value='<%=cainfo.getName() %>'>
  <%   } else { %>
    <input type="hidden" name='<%= ACTION %>' value='<%=ACTION_CREATE_CA %>'>
    <input type="hidden" name='<%= HIDDEN_CANAME %>' value='<%=caname %>'>
  <%   }
     }

   if( catokentype == CATokenInfo.CATOKENTYPE_P12 && !processrequest && !isexternal){ %>
   <%@ include file="softcatokenpage.jsp" %> 
<%}  %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTDN") %>
      </td>
      <td width="50%"> 
        <% if(editca){
              out.write(cainfo.getSubjectDN() + "<br>"); 
           }else{ %>
        <input type="text" name="<%=TEXTFIELD_SUBJECTDN%>" size="40" <% if(processrequest) out.write(" value='" + processedsubjectdn + "'"); %> maxlength="255">
        <% } %>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SIGNEDBY") %>
      </td>
      <td width="50%">
           <% if(processrequest){ %>
                <select name="<%=SELECT_SIGNEDBY %>" size="1" onchange="fillCertProfileField();">                
                <% Iterator iter = casigners.keySet().iterator();
                   while(iter.hasNext()){
                     String nameofca = (String) iter.next();  %>              
                     <option value="<%= casigners.get(nameofca)%>"><%= nameofca %></option>  
                <% } %> 
	        </select> 
           <% }else{
                if(editca){
                if(cainfo.getSignedBy() >= 0 && cainfo.getSignedBy() <= CAInfo.SPECIALCAIDBORDER){
                  if(cainfo.getSignedBy() == CAInfo.SELFSIGNED)
                    out.write(ejbcawebbean.getText("SELFSIGNED"));
                  if(cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA)
                    out.write(ejbcawebbean.getText("SIGNEDBYEXTERNALCA"));
                }else
                  out.write((String) caidtonamemap.get(new Integer(cainfo.getSignedBy())));
              }else{%>
        <select name="<%=SELECT_SIGNEDBY %>" size="1" onchange="fillCertProfileField(); isExternal()">
                <option value="<%= CAInfo.SELFSIGNED%>" selected><%= ejbcawebbean.getText("SELFSIGNED") %></option>  
                <option value="<%= CAInfo.SIGNEDBYEXTERNALCA%>"><%= ejbcawebbean.getText("EXTERNALCA") %></option>  
                <% Iterator iter = casigners.keySet().iterator();
                   while(iter.hasNext()){
                     String nameofca = (String) iter.next();  %>              
                     <option value="<%= casigners.get(nameofca)%>"><%= nameofca %></option>  
                <% } %> 
	 </select>
           <%   }
              }%> 
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CERTIFICATEPROFILE") %>
      </td>
      <td width="50%"> 
           <% if(editca){
                if(cainfo.getCertificateProfileId() != 0)
                  out.write((String) certprofileidtonamemap.get(new Integer(cainfo.getCertificateProfileId())));
                else
                  out.write(ejbcawebbean.getText("NOTUSED"));
              }else{%>
        <select name="<%=SELECT_CERTIFICATEPROFILE %>" size="1" >                
	</select>
           <% } %> 
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("VALIDITY") %> (<%= ejbcawebbean.getText("DAYS") %>)
      </td>
      <td width="50%"> 
        <% if(isexternal || (editca && cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA)){
              if(cainfo.getValidity() != 0)
                out.write("" + cainfo.getValidity());
              else
                out.write(ejbcawebbean.getText("NOTUSED"));
           }else{ %>
        <input type="text" name="<%=TEXTFIELD_VALIDITY%>" size="5" maxlength="255" 
           <% if(editca) out.write(" value='" +cainfo.getValidity() + "'> <i>" + 
                                    ejbcawebbean.getText("USEDINCARENEWAL") + "</i>");
              else out.write(">");
           }%>
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("DESCRIPTION") %>
      </td>
      <td width="50%"> 
        <% if(isexternal){
              out.write(cainfo.getDescription());
           }else{ %>
        <textarea name="<%=TEXTFIELD_DESCRIPTION%>" cols=40 rows=6><% if(editca) out.write(cainfo.getDescription());%></textarea>
       <% } %>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        &nbsp;
      </td>
      <td width="50%"> 
        &nbsp;
      </td>
    </tr>
   <% if(catype == CAInfo.CATYPE_X509){ 
        
        %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SUBJECTALTNAME") %>
      </td>
      <td width="50%">
         <% if(editca)
              if(x509cainfo.getSubjectAltName() == null || x509cainfo.getSubjectAltName().trim().equals(""))
                out.write(ejbcawebbean.getText("NONE")); 
              else
                out.write(x509cainfo.getSubjectAltName());                
            else{  %>  
         <input type="text" name="<%=TEXTFIELD_SUBJECTALTNAME%>" size="40" maxlength="255">
         <% } %>   
      </td>
    </tr> 
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("POLICYID") %>
        <% if(!editca) out.write("<br><i>" + ejbcawebbean.getText("LEAVEBLANKTOUSEDEFAULT") + "</i>");%>
      </td>
      <td width="50%">
         <% if(editca) 
              if(x509cainfo.getPolicyId() == null || x509cainfo.getPolicyId().trim().equals(""))
                out.write(ejbcawebbean.getText("NONE")); 
              else
                out.write(x509cainfo.getPolicyId());                
            else{  %>  
         <input type="text" name="<%=TEXTFIELD_POLICYID%>" size="40" maxlength="255">
         <% } %>   
      </td>
    </tr> 
   <% if(!processrequest && !isexternal){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLSPECIFICDATA") %>
      </td>
      <td width="50%"> 
        &nbsp;
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
         <%= ejbcawebbean.getText("AUTHORITYKEYID") %> <br> <%= ejbcawebbean.getText("AUTHORITYKEYIDCRITICAL") %> 
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_AUTHORITYKEYIDENTIFIER %>" onClick="checkusefield('<%=CHECKBOX_AUTHORITYKEYIDENTIFIER %>', '<%=CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if((editca && x509cainfo.getUseAuthorityKeyIdentifier()) || !editca)
                 out.write("CHECKED");
              if(isexternal) out.write(" disabled ");
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_AUTHORITYKEYIDENTIFIERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(editca){
               if(!x509cainfo.getUseAuthorityKeyIdentifier() || isexternal)
                 out.write(" disabled ");  
               else
               if(x509cainfo.getAuthorityKeyIdentifierCritical())
                 out.write("CHECKED");
             }%>> 
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
         <%= ejbcawebbean.getText("CRLNUMBER") %> <br> <%= ejbcawebbean.getText("CRLNUMBERCRITICAL") %> 
      </td>
      <td width="50%">
           <input type="checkbox" name="<%=CHECKBOX_USECRLNUMBER %>" onClick="checkusefield('<%=CHECKBOX_USECRLNUMBER %>', '<%=CHECKBOX_CRLNUMBERCRITICAL %>')" value="<%=CHECKBOX_VALUE %>" 
           <% if((editca && x509cainfo.getUseCRLNumber()) || !editca)
                 out.write("CHECKED");
              if(isexternal) out.write(" disabled "); 
           %>> <br> 
          <input type="checkbox" name="<%=CHECKBOX_CRLNUMBERCRITICAL %>" value="<%=CHECKBOX_VALUE %>" 
           <%
             if(editca){
               if(!x509cainfo.getUseCRLNumber() || isexternal)
                 out.write(" disabled ");  
               else
               if(x509cainfo.getCRLNumberCritical())
                 out.write("CHECKED");
             }%>> 
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("CRLPERIOD") %> (<%= ejbcawebbean.getText("HOURS") %>)
      </td>
      <td width="50%">
           <% if(isexternal){
                out.write("" + x509cainfo.getCRLPeriod());
              }else{ %>
         <input type="text" name="<%=TEXTFIELD_CRLPERIOD%>" size="40" maxlength="255"
            <% if(editca) out.write(" value='" + x509cainfo.getCRLPeriod()+ "'");%>>
           <% } %> 
      </td>
    </tr>    
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%" align="right"> 
        <%= ejbcawebbean.getText("CRLPUBLISHERS") %> <br>&nbsp;
      </td>
      <td width="50%"> 
        <select name="<%=SELECT_AVAILABLECRLPUBLISHERS%>" size="5" multiple >
           <%   Collection usedpublishers = null;
                if(editca) usedpublishers = x509cainfo.getCRLPublishers(); 
                Iterator iter = publisheridtonamemap.keySet().iterator(); 
                while(iter.hasNext()){
                  Integer next = (Integer) iter.next(); %>
           <option  value="<%= next %>" 
              <%    if(editca && usedpublishers.contains(next))
                      out.write(" selected ");
                  %>>
              <%= publisheridtonamemap.get(next) %>         
           </option>  
              <% } %>
        </select>
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("OTHERDATA") %>
      </td>
      <td width="50%"> 
        &nbsp;
      </td>
    </tr>
    <% if(!editca || (editca && ocspcainfo != null)){ %>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("OCSPSERVICE") %>
      </td>
      <td width="50%"> <%= ejbcawebbean.getText("ACTIVE") %> 
        <input type="checkbox" onclick="checkactivateocsp()" name="<%=CHECKBOX_ACTIVATEOCSPSERVICE %>" value="<%=CHECKBOX_VALUE %>" 
           <% if(waitingresponse) out.write(" disabled ");%>
            <% if((editca && (ocspcainfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE)) || !editca)
                 out.write("CHECKED");%>>
         <% if(editca && ocspcert != null){ %> &nbsp;&nbsp;         
         <input type="submit" name="<%= BUTTON_REVOKERENEWOCSPCERTIFICATE %>" <% if(ocspcainfo.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE || waitingresponse) out.write(" disabled ");%> value="<%= ejbcawebbean.getText("REVOKERENEWOCSPCERT") %>" >
         <br>         
         <a style="cursor:hand;" onClick="viewocspcert()"><u><%= ejbcawebbean.getText("VIEWOCSPCERTIFICATE")%></u></a>
         <% } %>
      </td>
    </tr>    
    <% } %>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("FINISHUSER") %>
      </td>
      <td width="50%"> 
        <input type="checkbox" name="<%=CHECKBOX_FINISHUSER %>" value="<%=CHECKBOX_VALUE %>" 
            <% if((editca && x509cainfo.getFinishUser()) || !editca)
                 out.write("CHECKED");%>>         
      </td>
    </tr>
   <%  } 
    }
    if(editca && !waitingresponse){%>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        &nbsp;
      </td>
      <td width="50%"> 
        <a style="cursor:hand;" onClick="window.open('<%=VIEWCERT_LINK%>?caid=<%=caid%>', 'view_cert','height=600,width=600,scrollbars=yes,toolbar=no,resizable=1')";><u><%= ejbcawebbean.getText("VIEWCACERTIFICATE")%></u></a>
      </td>
    </tr>
    <% } %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top"> 
      <% if(!isexternal){ 
           if(processrequest){ %>
          <input type="submit" name="<%= BUTTON_PROCESSREQUEST %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("PROCESSREQUEST") %>">
      <% }else{
            if(editca){ %>
          <input type="submit" name="<%= BUTTON_SAVE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("SAVE") %>">
        <%  }else{ %>
          <input type="submit" name="<%= BUTTON_CREATE %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("CREATE") %>">
        <%  }
         } %>   
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">
        <% }else{ %>
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("BACK") %>">
        <% } %>
      </td>
    </tr>
       <% if(editca && revokable){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top">&nbsp;</td>
      <td width="51%" valign="top">         
        <select name="<%=SELECT_REVOKEREASONS %>" >
          <% for(int i=0; i < RevokedInfoView.reasontexts.length; i++){ 
               if(i!= 7){%>
               <option value='<%= i%>'><%= ejbcawebbean.getText(RevokedInfoView.reasontexts[i]) %></option>
          <%   } 
             } %>
        </select>
        <input type="submit" name="<%= BUTTON_REVOKECA %>" value="<%= ejbcawebbean.getText("REVOKE") %>" onClick='return confirmrevokation()'>     
      </td>
    </tr>
        <% } %>   
       <% if(!editca && !processrequest){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top" align="right"></td>
      <td width="51%" valign="top">             
        <input type="submit" disabled name="<%= BUTTON_MAKEREQUEST %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("MAKEREQUEST") %>" >
      </td>
    </tr>
        <% } %>   
       <% if(editca && !isexternal && !waitingresponse){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top" align="right"></td>
      <td width="51%" valign="top">             
        <input type="submit" name="<%= BUTTON_RENEWCA %>" onClick='return confirmrenewal()' value="<%= ejbcawebbean.getText("RENEWCA") %>" >
      </td>
    </tr>
        <% } %>   
       <% if(editca && waitingresponse){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top" align="right"></td>
      <td width="51%" valign="top">             
        <input type="submit" name="<%= BUTTON_RECEIVEREQUEST %>" onClick='return checkallfields()' value="<%= ejbcawebbean.getText("RECIEVEREQUEST") %>" >
      </td>
    </tr>
        <% } %>   
       <% if(editca && !isexternal && !waitingresponse){ %>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top" align="right"></td>
      <td width="51%" valign="top">             
        <input type="submit" name="<%= BUTTON_PUBLISHCA %>"  value="<%= ejbcawebbean.getText("REPUBLISHCA") %>" >
      </td>
    </tr>
        <% } %>   
  </form>
  </table>
