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

package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.util.Arrays;

/**
 * This class contains Google's CT policy as specified in "Certificate Transparency in Chrome" from May 2016.
 * The policy document can be found here: https://goo.gl/cZZqLw
 * @version $Id$
 */
public final class GoogleCtPolicy implements Serializable {
    private static final long serialVersionUID = 1337L;

    /* Constants representing rows from Table 1 */
    private static final int LESS_THAN_15_MONTHS = 0;
    private static final int BETWEEN_15_AND_27_MONTHS = 1;
    private static final int BETWEEN_27_AND_39_MONTHS = 2;
    private static final int MORE_THAN_39_MONTHS = 3;

    /* Default policy values. Should not be changed unless the policy changes. */
    private final int[] minScts = new int[] { 2, 3, 4, 5, };
    private final int[] lessThanMonths = new int[] { 15, 27, 39, Integer.MAX_VALUE };

    /**
     * Validate the CT policy stored in this object. Currently checking the following:
     * <ul>
     *   <li>Ensure the number of CT logs are all greater than zero.</li>
     * </ul>
     */
    public boolean isValid() {
        for (int i = 0; i < minScts.length; i++) {
            if (minScts[i] <= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Set the minimum number of SCTs required for certificates with a lifetime
     * of less than 15 Months.
     * @param value a number of SCTs
     */
    public void setLessThan15Months(final int value) {
        this.minScts[LESS_THAN_15_MONTHS] = value;
    }

    /**
     * Set the minimum number of SCTs required for certificates with a lifetime
     * of ≥15 Months but ≤27 Months.
     * @param value a number of SCTs
     */
    public void setBetween15And27Months(final int value) {
        this.minScts[BETWEEN_15_AND_27_MONTHS] = value;
    }

    /**
     * Set the minimum number of SCTs required for certificates with a lifetime
     * of >27 Months but ≤39 Months.
     * @param value a number of SCTs
     */
    public void setBetween27And39Months(final int value) {
        this.minScts[BETWEEN_27_AND_39_MONTHS] = value;
    }

    /**
     * Set the minimum number of SCTs required for non EV-certificates with a lifetime
     * of more than 39 Months.
     * @param value a number of SCTs
     */
    public void setMoreThan39Months(final int value) {
        this.minScts[MORE_THAN_39_MONTHS] = value;
    }

    /**
     * Get the minimum number of SCTs required for certificates with a lifetime
     * of less than 15 Months.
     * @return a number of SCTs
     */
    public int getLessThan15Months() {
        return minScts[LESS_THAN_15_MONTHS];
    }

    /**
     * Get the minimum number of SCTs required for certificates with a lifetime
     * of ≥15 Months but ≤27 Months.
     * @return a number of SCTs
     */
    public int getBetween15And27Months() {
        return minScts[BETWEEN_15_AND_27_MONTHS];
    }

    /**
     * Get the minimum number of SCTs required for certificates with a lifetime
     * of >27 Months but ≤39 Months.
     * @return a number of SCTs
     */
    public int getBetween27And39Months() {
        return minScts[BETWEEN_27_AND_39_MONTHS];
    }

    /**
     * Get the minimum number of SCTs required for non EV-certificates with a lifetime
     * of more than 39 Months.
     * return a number of SCTs
     */
    public int getMoreThan39Months() {
        return minScts[MORE_THAN_39_MONTHS];
    }
    
    /**
     * Returns the minimum SCTs for the given index.
     * @param breakpointIndex Index
     * @throws IndexOutOfBoundsException if out of bounds.
     * @return Minimum SCTs
     * @see #getNumberOfBreakpoints
     */
    public int getMinSctsByIndex(int breakpointIndex) {
        return minScts[breakpointIndex];
    }
    
    /**
     * Returns the "less than months" validity restriction for the given index.
     * @param breakpointIndex Index
     * @throws IndexOutOfBoundsException if out of bounds.
     * @return "Less than months" value, or Integer.MAX_VALUE if infinite
     * @see #getNumberOfBreakpoints
     */
    public int getLessThanMonthsByIndex(int breakpointIndex) {
        return lessThanMonths[breakpointIndex];
    }
    
    /**
     * Returns the number of breakpoints (i.e. indices to getMinSctsByIndex/getLessThanMonthsByIndex)
     */
    public int getNumberOfBreakpoints() {
        return minScts.length;
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof GoogleCtPolicy)) {
            return false;
        }
        final GoogleCtPolicy other = (GoogleCtPolicy) obj;
        return Arrays.equals(minScts, other.minScts) && Arrays.equals(lessThanMonths, other.lessThanMonths);
    }

    @Override
    public int hashCode() {
        // We use a sum of the fields hashcodes. The second hashcode is multiplied by some prime number. This is common practice in Java (see String.hashCode)
        return Arrays.hashCode(minScts) + 311*Arrays.hashCode(lessThanMonths); 
    }
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("GoogleCtPolicy{");
        for (int i = 0; i < minScts.length; i++) {
            if (i != 0) {
                sb.append(',');
            }
            // Validity
            if (lessThanMonths[i] != Integer.MAX_VALUE) {
                sb.append(lessThanMonths[i]);
                sb.append("mo");
            } else {
                sb.append("longer");
            }
            // 
            sb.append('=');
                sb.append(minScts[i]);
        }
        sb.append('}');
        return sb.toString();
    }
}
