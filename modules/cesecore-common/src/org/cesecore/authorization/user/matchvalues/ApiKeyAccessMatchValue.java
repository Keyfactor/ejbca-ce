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

// SUBJECT FOR ECA-6877. LEAVE OUT UNTIL FINAL IMPLEMENTATION IS COMPLETE

package org.cesecore.authorization.user.matchvalues;

//import java.util.Arrays;
//import java.util.List;
//
//import org.cesecore.authentication.tokens.ApiKeyAuthenticationTokenMetaData;
//import org.cesecore.authorization.user.AccessMatchType;
//
///**
// * 
// * @version $Id$
// *
// */
//public enum ApiKeyAccessMatchValue implements AccessMatchValue {
//    API_KEY(0);
//
//    private final int numericValue;
//    
//    private ApiKeyAccessMatchValue(int numericValue) {
//        this.numericValue = numericValue;
//    }
//    
//    @Override
//    public int getNumericValue() {
//        return numericValue;
//    }
//
//    @Override
//    public boolean isDefaultValue() {
//        return numericValue == API_KEY.numericValue;
//    }
//
//    @Override
//    public String getTokenType() {
//        return ApiKeyAuthenticationTokenMetaData.TOKEN_TYPE;
//    }
//
//    @Override
//    public boolean isIssuedByCa() {
//        // Not required for API key
//        return false;
//    }
//
//    @Override
//    public List<AccessMatchType> getAvailableAccessMatchTypes() {
//        // Always use case sensitive match for API keys
//        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
//    }
//
//    @Override
//    public String normalizeMatchValue(String value) {
//        return value != null ? value.trim() : null;
//    }
//}