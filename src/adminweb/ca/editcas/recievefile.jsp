
<% 
  String[] headlines = {"MAKEREQUEST","RECIEVEREQUEST","PROCESSREQUEST"};
  String[] helptexts = {"MAKEREQUESTHELP","RECIEVEREQUESTHELP","PROCESSREQUESTHELP"};
  String[] buttontexts = {"MAKEREQUEST","RECIEVEREQUEST","PROCESSREQUEST"};
  String[]  actions     = { ACTION_MAKEREQUEST, ACTION_RECEIVERESPONSE, ACTION_PROCESSREQUEST};

  row = 0;
%>
<body > 
<SCRIPT language="JavaScript">
<!--  

function check()
{  
  
  if(document.recievefile.<%= FILE_RECIEVEFILE %>.value == ''){   
     alert("<%= ejbcawebbean.getText("YOUMUSTSELECT") %>"); 
   }else{  
     return true;  
   }
  
   return false;
}
-->
</SCRIPT>
<div align="center">   
   <h2><%= ejbcawebbean.getText(headlines[filemode]) %><br></h2>
   <h3><%= ejbcawebbean.getText("CANAME")+ " : " + caname %> </h3>
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
    <form name="recievefile" action="<%= THIS_FILENAME %>" method="post" enctype='multipart/form-data' onSubmit='return check()'>
      <input type="hidden" name='<%= ACTION %>' value='<%=actions[filemode] %>'>
      <input type="hidden" name='<%= HIDDEN_CAID %>' value='<%= caid %>'>
      <input type="hidden" name='<%= HIDDEN_CANAME %>' value='<%= caname%>'>
    <tr  id="Row<%=row++%2%>"> 
      <td width="49%" valign="top" align="right"><%= ejbcawebbean.getText(helptexts[filemode]) %></td>
      <td width="51%" valign="top">     
        <input TYPE="FILE" NAME="<%= FILE_RECIEVEFILE %>">            
        <input type="submit" name="<%= BUTTON_RECIEVEFILE %>"  value="<%= ejbcawebbean.getText(buttontexts[filemode]) %>" ><br><br>
        <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">     
      </td>
    </tr>
    </form>
  </table>