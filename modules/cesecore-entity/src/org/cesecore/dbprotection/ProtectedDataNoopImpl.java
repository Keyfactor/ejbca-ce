/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.dbprotection;


/**
 * @version $Id$
 */
public class ProtectedDataNoopImpl implements ProtectedDataImpl {

    @Override
    public void setTableName(final String table) {
        // Do nothing
    }

    @Override
    public void protectData(final ProtectedData obj) {
        // Do nothing
    }

    @Override
    public void verifyData(final ProtectedData obj) {
        // Do nothing
    }
	
    @Override
    public String calculateProtection(final ProtectedData obj) {
        // Do nothing
        return null;
    }

    @Override
    public void onDataVerificationError(DatabaseProtectionException e) {
        // Do nothing
    }

}
