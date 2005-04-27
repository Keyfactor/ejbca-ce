<%               
  int[] signpintypes = { HardTokenProfile.PINTYPE_4DIGITS,HardTokenProfile.PINTYPE_6TO8DIGITS,
  		         HardTokenProfile.PINTYPE_6TO8DIGITSLETTERS, HardTokenProfile.PINTYPE_6TO8ALLPRINTABLE}; 
		
  int[] authencpintypes = { HardTokenProfile.PINTYPE_4DIGITS,HardTokenProfile.PINTYPE_6TO8DIGITS,
                            HardTokenProfile.PINTYPE_6TO8DIGITSLETTERS, HardTokenProfile.PINTYPE_6TO8ALLPRINTABLE,
			    SwedishEIDProfile.PINTYPE_AUTHENC_SAME_AS_SIGN};

  String[] signpintexts    = {"4DIGITS","6TO8DIGITS","6TO8DIGITSLETTERS","6TO8ALLPRINTABLE"};
  String[] authencpintexts = {"4DIGITS","6TO8DIGITS","6TO8DIGITSLETTERS","6TO8ALLPRINTABLE", "SAMEASSIGNCERT"};

  String[] keytexts = {"RSA1024BIT", "RSA2048BIT"};

  SwedishEIDProfile curprofile = (SwedishEIDProfile) helper.profiledata;

%>

   <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
         &nbsp;
        </div>
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
   </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("MINKEYLENGTH") %>
        </div>
      </td>
      <td width="50%" valign="top">   
        <select name="<%=EditHardTokenProfileJSPHelper.SELECT_MINKEYLENGTH%>" size="1"  >       
            <% int currentkeylength = curprofile.getMinimumKeyLength(SwedishEIDProfile.CERTUSAGE_SIGN);      
               for(int i=0;i < SwedishEIDProfile.AVAILABLEMINIMUMKEYLENGTHS.length;i++){ %>
              <option value="<%=SwedishEIDProfile.AVAILABLEMINIMUMKEYLENGTHS[i]%>" <% if(SwedishEIDProfile.AVAILABLEMINIMUMKEYLENGTHS[i] == currentkeylength) out.write(" selected "); %>> 
                  <%= ejbcawebbean.getText(keytexts[i]) %>
               </option>
            <%}%>
          </select>         
      </td>
    </tr>
   <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
         &nbsp;
        </div>
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
    </tr>    
   <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("CERTIFICATESETTINGS") %>:
        </div>
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("SIGNINGCERTIFICATE") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("CERTIFICATEPROFILE") %>
        </div>
      </td>
      <td width="50%" valign="top">   
        <select name="<%=EditHardTokenProfileJSPHelper.SELECT_CERTIFICATEPROFILE + "0"%>" size="1"  >       
            <% int currentcert = curprofile.getCertificateProfileId(SwedishEIDProfile.CERTUSAGE_SIGN);
               Iterator iter = authorizedcertprofiles.keySet().iterator();
               while(iter.hasNext()){
                 String certprof = (String) iter.next();
                 Integer certprofid = (Integer) authorizedcertprofiles.get(certprof);%>
              <option value="<%=certprofid.intValue()%>" <% if(certprofid.intValue() == currentcert) out.write(" selected "); %>> 
                  <%= certprof %>
               </option>
            <%}%>
          </select>         
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("PINTYPE") %>
        </div>
      </td>
      <td width="50%" valign="top">          
         <select name="<%=EditHardTokenProfileJSPHelper.SELECT_PINTYPE + "0"%>" size="1"  >
            <% int currentpintype = curprofile.getPINType(SwedishEIDProfile.CERTUSAGE_SIGN);
               
               for(int i=0;i < signpintypes.length;i++){%>
              <option value="<%=signpintypes[i]%>" <% if(signpintypes[i] == currentpintype) out.write(" selected "); %>> 
                  <%= ejbcawebbean.getText(signpintexts[i]) %>
               </option>
            <%}%>
          </select>         
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        &nbsp;
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("AUTHENCCERTIFICATE") %>
        </div>
      </td>
      <td width="50%" valign="top"> 
         &nbsp;
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("CERTIFICATEPROFILE") %>
        </div>
      </td>
      <td width="50%" valign="top">   
        <select name="<%=EditHardTokenProfileJSPHelper.SELECT_CERTIFICATEPROFILE + "1"%>" size="1"  >       
            <% currentcert = curprofile.getCertificateProfileId(SwedishEIDProfile.CERTUSAGE_AUTHENC);
               iter = authorizedcertprofiles.keySet().iterator();
               while(iter.hasNext()){
                 String certprof = (String) iter.next();
                 Integer certprofid = (Integer) authorizedcertprofiles.get(certprof);%>
              <option value="<%=certprofid.intValue()%>" <% if(certprofid.intValue() == currentcert) out.write(" selected "); %>> 
                  <%= certprof %>
               </option>
            <%}%>
          </select>         
      </td>
    </tr>
    <tr id="Row<%=row++%2%>"> 
      <td width="50%" valign="top"> 
        <div align="right"> 
          <%= ejbcawebbean.getText("PINTYPE") %>
        </div>
      </td>
      <td width="50%" valign="top">          
         <select name="<%=EditHardTokenProfileJSPHelper.SELECT_PINTYPE + "1"%>" size="1"  >
            <% currentpintype = curprofile.getPINType(SwedishEIDProfile.CERTUSAGE_AUTHENC);
               
               for(int i=0;i < authencpintypes.length;i++){%>
              <option value="<%=authencpintypes[i]%>" <% if(authencpintypes[i] == currentpintype) out.write(" selected "); %>> 
                  <%= ejbcawebbean.getText(authencpintexts[i]) %>
               </option>
            <%}%>
          </select>         
      </td>
    </tr>
