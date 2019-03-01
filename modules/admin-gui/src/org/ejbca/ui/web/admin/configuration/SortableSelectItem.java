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
 * An extension to the SelectItem class that is sortable.
 * Used by select lists that should be alphabetic order, ignoring case.
 *  
 * @version $Id$
 */

public class SortableSelectItem extends SelectItem implements Comparable<SelectItem>{

	private static final long serialVersionUID = -3282242436064530974L;

    public SortableSelectItem(final Object value, final String label, final String description, final boolean disabled) {
		super(value, label, description, disabled);
	}

	public SortableSelectItem(final Object value, final String label, final String description) {
		super(value, label, description);
	}

	public SortableSelectItem(final Object value, final String label) {
		super(value, label);
	}

	@Override
	public int compareTo(final SelectItem other) {
		return this.getLabel().compareToIgnoreCase(other.getLabel());
	}

}
