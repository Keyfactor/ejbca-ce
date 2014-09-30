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

package org.ejbca.ui.web.admin.configuration;

import javax.faces.model.SelectItem;

/**
 * An extension to the SelectItem class that is
 * sortable, used by select lists that should be alphabetic
 * order. 
 * 
 *
 * @version $Id$
 */

public class SortableSelectItem extends SelectItem implements Comparable<SelectItem>{

	private static final long serialVersionUID = -3282242436064530974L;

    public SortableSelectItem(Object arg0, String arg1, String arg2, boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

	public SortableSelectItem(Object arg0, String arg1, String arg2) {
		super(arg0, arg1, arg2);
	}

	public SortableSelectItem(Object arg0, String arg1) {
		super(arg0, arg1);
	}

	public int compareTo(SelectItem arg0) {
		int retval = 0;
		if(arg0 instanceof SelectItem){
			return this.getLabel().compareTo(arg0.getLabel());
		}
		return retval;
	}

}
