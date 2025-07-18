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

package org.cesecore.repository.mock;

public class DeleteTypedQueryMock<T> extends TypedQueryMock<T> {

    DeleteTypedQueryMock(EntityManagerMock entityManagerMock) {
        super(entityManagerMock);
    }

    @Override
    public int executeUpdate() {
        var remainingList = getResultList().stream()
                .filter((element)->!isIncluded(element))
                .toList();
        getEntityManagerMock().setResultList(remainingList);
        return getExecutionResult();
    }

}
