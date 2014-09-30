/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.admin.hardtokeninterface;

import java.util.Collection;
import java.util.Date;

import org.cesecore.util.StringTools;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.HardToken;



/**
 * A class representing a web interface view of a hard token in the ra database.
 *
 * @version $Id$
 */
public class HardTokenView implements java.io.Serializable, Cloneable {
  
    private static final long serialVersionUID = 4090246269386728977L;

    // Public constants.
    public HardTokenView() {
        this.tokendata = new HardTokenInformation();        
    }

    public HardTokenView(HardTokenInformation newtokendata) {
        tokendata = newtokendata;        
    }

    public void setUsername(String user) {
        tokendata.setUsername(StringTools.stripUsername(user));
    }

    public String getUsername() {
        return tokendata.getUsername();
    }


    public void setTokenSN(String tokensn) {
        tokendata.setTokenSN(tokensn);
    }


    public String getTokenSN() {
        return tokendata.getTokenSN();
    }

    public void setCreateTime(Date createtime) {
        tokendata.setCreateTime(createtime);
    }

    public Date getCreateTime() {
        return tokendata.getCreateTime();
    }

    public void setModifyTime(Date modifytime) {
        tokendata.setModifyTime(modifytime);
    }

    public Date getModifyTime() {
        return tokendata.getModifyTime();
    }
    
    public String getLabel(){
    	return tokendata.getHardToken().getLabel();
    }

    public int getNumberOfFields() {
        return tokendata.getHardToken().getNumberOfFields();
    }

    public String getTextOfField(int index) {
        if (tokendata.getHardToken().getFieldText(index).equals(HardToken.EMPTYROW_FIELD)) {
            return "";
        }
        return tokendata.getHardToken().getFieldText(index);
    }
    
    public boolean isOriginal(){
      return tokendata.isOriginal();	
    }
    
    public String getCopyOf(){
      return tokendata.getCopyOf();	
    }
    
    public Collection<String> getCopies(){
      return tokendata.getCopies();	
    }
    
    public Integer getHardTokenProfileId(){    	
    	  return Integer.valueOf(tokendata.getHardToken().getTokenProfileId());
    }

    public Object getField(int index) {
        HardToken token = tokendata.getHardToken();

        if (token.getFieldPointer(index).equals(HardToken.EMPTYROW_FIELD)) {
            return "";
        }
        return token.getField(token.getFieldPointer(index));
    }

    // Private constants.
    // Private methods.
    private HardTokenInformation tokendata;    
}
