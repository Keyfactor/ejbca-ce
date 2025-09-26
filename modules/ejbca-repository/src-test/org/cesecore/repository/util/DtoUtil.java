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

package org.cesecore.repository.util;

import org.cesecore.dto.DummyCertWithIndex;
import org.cesecore.dto.DummyCertWithIndexRecord;

import java.util.Map;

public class DtoUtil {

    public static DummyCertWithIndex getDummyCertWithIndex(Long id, String commonName, String name, String author, int years) {
        return new DummyCertWithIndexRecord(id, commonName, name, Map.of("author", author, "years", years));
    }

}
