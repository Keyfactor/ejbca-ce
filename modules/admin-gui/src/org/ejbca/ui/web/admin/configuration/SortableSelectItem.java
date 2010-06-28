/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.configuration;

import javax.faces.model.SelectItem;

/**
 * An extention to the SelectItem class that is
 * sortable, used by select lists that should be alphabetic
 * order. 
 * 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: SortableSelectItem.java 5585 2008-05-01 20:55:00Z anatom $
 */

public class SortableSelectItem extends SelectItem implements Comparable{

	public SortableSelectItem(Object arg0, String arg1, String arg2, boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

	public SortableSelectItem(Object arg0, String arg1, String arg2) {
		super(arg0, arg1, arg2);
	}

	public SortableSelectItem(Object arg0, String arg1) {
		super(arg0, arg1);
	}

	public int compareTo(Object arg0) {
		int retval = 0;
		if(arg0 instanceof SelectItem){
			return this.getLabel().compareTo(((SelectItem) arg0).getLabel());
		}
		return retval;
	}

}
