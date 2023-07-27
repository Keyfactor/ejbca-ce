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
package org.ejbca.util;

import com.keyfactor.util.CeSecoreNameStyle;
import org.bouncycastle.asn1.x500.X500NameStyle;

/**
 * The following enum singleton is to comply with the case when the {@link CeSecoreNameStyle} should be serializable.
 */
public enum CeSecoreNameStyleEnumSingleton {

	CE_SECORE_NAME_STYLE(CeSecoreNameStyle.INSTANCE);

	private final X500NameStyle style;

	CeSecoreNameStyleEnumSingleton(X500NameStyle style) {
		this.style = style;
	}

	public X500NameStyle getStyle() {
		return style;
	}
}
