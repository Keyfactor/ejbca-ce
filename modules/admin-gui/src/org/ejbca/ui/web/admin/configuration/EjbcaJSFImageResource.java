package org.ejbca.ui.web.admin.configuration;

import javax.ejb.EJBException;

/**
 * Class used to retrieve EJBCA image resources in JSF views
 * 
 * @author Philip Vendil
 * @version $Id$
 * @see org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getImagefileInfix(String)
 */
public class EjbcaJSFImageResource {

	private EjbcaWebBean ejbcawebbean;
	
	public EjbcaJSFImageResource(EjbcaWebBean ejbcawebbean){
		this.ejbcawebbean = ejbcawebbean;
	}
	
	public void clear() {
		throw new EJBException("Method clear not supported");
	}

	public boolean containsKey(String arg0) {		
		return ejbcawebbean.getImagefileInfix(arg0) != null;
	}

	public String get(String arg0) {
		return ejbcawebbean.getImagefileInfix(arg0);
	}

}
