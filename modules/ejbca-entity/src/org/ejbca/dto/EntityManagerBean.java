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

package org.ejbca.dto;

public interface EntityManagerBean<Dto> {

    String KEY_VERSION = "version";

    int getRowVersion();

    void setRowVersion(final int rowVersion);

    String getRowProtection();

    void setRowProtection(final String rowProtection);

    String getProtectString(final int version);

    int getProtectVersion();

    Dto toDto();

    void init(final Dto dto);

    default void upgrade() {
    }

}
