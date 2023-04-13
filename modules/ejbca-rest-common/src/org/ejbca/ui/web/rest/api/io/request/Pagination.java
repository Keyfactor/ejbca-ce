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
package org.ejbca.ui.web.rest.api.io.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing pagination parameters with a page size and a current page.
 */
@JsonPropertyOrder({ "page_size", "current_page" })
public class Pagination {

    @ApiModelProperty(value = "Number of results per page", example = "10")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("page_size")
    private int pageSize;

    @ApiModelProperty(value = "Current page number", example = "1")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("current_page")
    private int currentPage;

    public Pagination() {
        super();
    }

    public Pagination(final int pageSize, final int currentPage) {
        super();
        this.pageSize = pageSize;
        this.currentPage = currentPage;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(final int pageSize) {
        this.pageSize = pageSize;
    }

    public int getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(final int currentPage) {
        this.currentPage = currentPage;
    }
        
}
