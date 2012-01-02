package org.ejbca.ui.web.admin.configuration;

import org.ejbca.util.HTMLTools;

/**
 * Class used to retrieve EJBCA language resources in JSF views
 * 
 * Implements a Map used for retrieving resources.
 * @author Philip Vendil
 * @version $Id$
 */
public class EjbcaJSFLanguageResource {

	private EjbcaWebBean ejbcawebbean;
	
	public EjbcaJSFLanguageResource(EjbcaWebBean ejbcawebbean){
		this.ejbcawebbean = ejbcawebbean;
	}

	public boolean containsKey(Object arg0) {
		return ejbcawebbean.getText((String) arg0) != null;
	}

	public String get(String arg0) {
		String str = ejbcawebbean.getText(arg0);
		return HTMLTools.htmlunescape(str);
	}

}
