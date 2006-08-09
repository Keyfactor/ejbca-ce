package org.ejbca.ui.web.admin.approval;
/*
 * Created on 2005-jun-19
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
import java.io.Serializable;

/**
 * Class used to present comparable data with red text for rows that doesn't match.
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class TextComparisonView implements Serializable {
	
	private  String orgvalue;
	private  String newvalue;
	
	public TextComparisonView(String orgvalue, String newvalue){
		this.orgvalue = orgvalue;
		this.newvalue = newvalue;	
	}
	
	
	public String getTextComparisonColor(){
	  if(orgvalue != null && !orgvalue.equals(newvalue)) {
	  	return "alert";
	  }
	  	
	  
	  return "";
	}

	public String getNewvalue() {
		return newvalue;
	}
	public String getOrgvalue() {
		return orgvalue;
	}
}
