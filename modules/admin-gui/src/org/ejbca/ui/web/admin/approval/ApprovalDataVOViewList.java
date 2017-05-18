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

package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.ejbca.core.model.approval.ApprovalDataVO;

/**
 * Class used to manage the list of approvaldatas resulted in the query.
 * 
 * @version $Id$
 */

public class ApprovalDataVOViewList extends AbstractList<ApprovalDataVOView> implements Serializable {

    private static final long serialVersionUID = 1680993305950225012L;
    private String sort;
    private boolean ascending;
    private List<ApprovalDataVOView> listData;

    public ApprovalDataVOViewList(Collection<ApprovalDataVO> approvalDataVOs) {
        listData = new ArrayList<ApprovalDataVOView>();
        for(ApprovalDataVO approvalDataVO : approvalDataVOs) {
            listData.add(new ApprovalDataVOView(approvalDataVO));
        }

    }

    public ApprovalDataVOView get(int arg0) {
        return listData.get(arg0);
    }

    public int size() {
        return listData.size();
    }


    /**
     * Sort the list.
     */
    protected void sort(final String column, final boolean ascending) {
        Comparator<ApprovalDataVOView> comparator = new Comparator<ApprovalDataVOView>() {
            public int compare(ApprovalDataVOView c2, ApprovalDataVOView c1) {
                if (column == null || column.equals("requestDate")) {
                    return ascending ? c1.getApproveActionDataVO().getRequestDate().compareTo(c2.getApproveActionDataVO().getRequestDate()) : c2
                            .getApproveActionDataVO().getRequestDate().compareTo(c1.getApproveActionDataVO().getRequestDate());
                } else if (column.equals("approveActionName")) {
                    return ascending ? c1.getApproveActionName().compareTo(c2.getApproveActionName()) : c2.getApproveActionName().compareTo(
                            c1.getApproveActionName());
                } else if (column.equals("requestUsername")) {
                    return ascending ? c1.getRequestAdminName().compareTo(c2.getRequestAdminName()) : c2.getRequestAdminName().compareTo(
                            c1.getRequestAdminName());
                } else if (column.equals("status")) {
                    return ascending ? c1.getStatus().compareTo(c2.getStatus()) : c2.getStatus().compareTo(c1.getStatus());
                } else {
                    return 0;
                }
            }
        };

        Collections.sort(listData, comparator);
    }

    /**
     * Is the default sort direction for the given column "ascending" ?
     */
    protected boolean isDefaultAscending(String sortColumn) {
        return true;
    }

    public void sort(String sortColumn) {
        if (sortColumn == null) {
            throw new IllegalArgumentException("Argument sortColumn must not be null.");
        }

        if (sort.equals(sortColumn)) {
            // current sort equals new sortColumn -> reverse sort order
            ascending = !ascending;
        } else {
            // sort new column in default direction
            sort = sortColumn;
            ascending = isDefaultAscending(sort);
        }

        sort(sort, ascending);
    }

    public void sort() {
        sort(sort);
    }

    public List<ApprovalDataVOView> getData() {
        sort(getSort(), isAscending());
        return this;
    }

    public void setData(List<ApprovalDataVOView> data) {

    }

    public String getSort() {
        return sort;
    }

    public void setSort(String sort) {
        this.sort = sort;
    }

    public boolean isAscending() {
        return ascending;
    }

    public void setAscending(boolean ascending) {
        this.ascending = ascending;
    }

}
