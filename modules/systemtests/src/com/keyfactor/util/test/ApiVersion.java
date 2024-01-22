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

package com.keyfactor.util.test;

/** Interface for version enums used by MethodApiDescriptor */
public interface ApiVersion {

    public static final ApiVersion INITIAL_VERSION = new ApiVersion() {
        @Override
        public int versionOrdinal() {
            return -1;
        }
        @Override
        public String toString() {
            return "<Initial version>";
        }
    };

    public static final ApiVersion ALL_VERSIONS = new ApiVersion() {
        @Override
        public int versionOrdinal() {
            return Integer.MAX_VALUE;
        }
        @Override
        public String toString() {
            return "<All versions>";
        }
    };

    /** Converts a version number to an ordered integer, so it can be compared */
    int versionOrdinal();
}
