package se.anatom.ejbca.webdist.hardtokeninterface;

import java.util.Date;

import se.anatom.ejbca.hardtoken.*;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;

/**
 * A class representing a web interface view of a hard token in the ra database.
 *
 * @version $Id: UserView.java,v 1.0 2003/01/26 20:00:01 herrvendil Exp $
 */
public class HardTokenView implements java.io.Serializable, Cloneable {
    // Public constants.

    public HardTokenView(AvailableHardToken[] availablehardtokens){
      this.tokendata = new HardTokenData();      
      this.availablehardtokens = availablehardtokens;
   }
    
 
    public HardTokenView(AvailableHardToken[] availablehardtokens, HardTokenData newtokendata){
      tokendata = newtokendata;  
      this.availablehardtokens = availablehardtokens;
    }
  
    public void setUsername(String user) { tokendata.setUsername(user);}
    public String getUsername() {return tokendata.getUsername();}
     
    public void setHardTokenType(String tokentype) {
      for(int i=0; i < availablehardtokens.length; i++){
        if(tokentype.equals(availablehardtokens[i].getName()))
          tokendata.setTokenType(Integer.parseInt(availablehardtokens[i].getId()));
      } 
    }
    
    public String getHardTokenType() {
      String returnval ="";  
      for(int i=0; i < availablehardtokens.length; i++){
        if(tokendata.getTokenType() == Integer.parseInt(availablehardtokens[i].getId()))
          returnval= availablehardtokens[i].getName();
      } 
      return returnval;
    } 
    
    public void setTokenSN(String tokensn) { tokendata.setTokenSN(tokensn);}
    public String getTokenSN() {return tokendata.getTokenSN();}    

    public void setCreateTime(Date createtime){ tokendata.setCreateTime(createtime); }    
    public Date getCreateTime(){ return tokendata.getCreateTime(); }   

    public void setModifyTime(Date modifytime){ tokendata.setModifyTime(modifytime); }    
    public Date getModifyTime(){ return tokendata.getModifyTime(); }  
    
    public int getNumberOfFields(){       
      return tokendata.getHardToken().getNumberOfFields();   
    }
    
    public String getTextOfField(int index){
      if(tokendata.getHardToken().getFieldText(index).equals(HardToken.EMPTYROW_FIELD))
        return "";
      else
        return tokendata.getHardToken().getFieldText(index);   
    }
    
    public Object getField(int index){
      HardToken token = tokendata.getHardToken();
      if(token.getFieldPointer(index).equals(HardToken.EMPTYROW_FIELD))
        return (Object) "";
      else
        return  (Object) token.getField(token.getFieldPointer(index));
    }
         
    // Private constants.  
    
    // Private methods.
    private HardTokenData tokendata;
    private AvailableHardToken[] availablehardtokens;
}
