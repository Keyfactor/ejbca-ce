<%               
  SoftCATokenInfo softcatokeninfo = (SoftCATokenInfo) catokeninfo; 
  int[] AVAILABLEKEYSIZES = {1024,2048,4096};
%>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("SIGNALGORITHM") %>
      </td>
      <td width="50%"> 
           <% if(editca){
                  out.write(softcatokeninfo.getSignatureAlgorithm());
              }else{%>
        <select name="<%=SELECT_SIGNATUREALGORITHM %>" size="1">
                
                <% for(int i=0; i < SoftCATokenInfo.AVAILABLE_SIGALGS.length; i++){ %>
                     <option value="<%= SoftCATokenInfo.AVAILABLE_SIGALGS[i]%>"><%= SoftCATokenInfo.AVAILABLE_SIGALGS[i] %></option>  
                <% } %> 
	 </select>
           <% } %> 
      </td>
    </tr>
    <tr  id="Row<%=row++%2%>"> 
      <td width="50%"  align="right"> 
        <%= ejbcawebbean.getText("KEYSIZE") %>
      </td>
      <td width="50%"> 
           <% if(editca){
                out.write(Integer.toString(softcatokeninfo.getKeySize()));
              }else{%>
        <select name="<%=SELECT_KEYSIZE %>" size="1" >                
                <% for(int i=0; i < AVAILABLEKEYSIZES.length; i++){ %>
                     <option value="<%= AVAILABLEKEYSIZES[i]%>"><%= AVAILABLEKEYSIZES[i] %></option>  
                <% } %> 
	</select>
           <% } %> 
      </td>
    </tr>
 