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
import java.util.ArrayList;
import java.util.List;

/**
 * This class contains Google's CT policy as specified in "Certificate Transparency in Chrome" from May 2016.
 * The policy document can be found here: https://goo.gl/cZZqLw
 * @version $Id$
 */
public final class GoogleCtPolicy implements Serializable {
    private static final long serialVersionUID = 1337L;

    private List<PolicyBreakpoint> breakpoints = new ArrayList<>();

    /* Default policy values. Should not be changed unless the policy changes. */
    /* Need to keep this variable from previous version of this class to retrieve saved SCTs from database.
    Otherwise, these saved 'Number of SCTs From Distinct Logs' values will be lost at the time of upgrading EJBCA to version 7.8.1 */
    private final int[] minScts = new int[] { 2, 3, 4, 5, };

    public List<PolicyBreakpoint> getBreakpoints() {
        if (breakpoints == null) {
            breakpoints = new ArrayList<>();
        }
        if (breakpoints.size() == 0) {
            breakpoints.add(new PolicyBreakpoint(0, 15, minScts[0]));
            breakpoints.add(new PolicyBreakpoint(15, 27, minScts[1]));
            breakpoints.add(new PolicyBreakpoint(27, 39, minScts[2]));
            breakpoints.add(new PolicyBreakpoint(39, Integer.MAX_VALUE, minScts[3]));
        }
        return breakpoints;
    }

    public void setBreakpoints(List<PolicyBreakpoint> breakpoints) {
        this.breakpoints = breakpoints;
    }

    public int[] getMinScts() {
        return minScts;
    }

    /**
     * Validate the CT policy stored in this object. Currently checking the following:
     * <ul>
     *   <li>Ensure the number of CT logs are all greater than zero.</li>
     * </ul>
     */
    public boolean isValid() {
        for (int i = 0; i < breakpoints.size(); i++) {
            if (breakpoints.get(i).getMinSct() <= 0) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Returns the minimum SCTs for the given index.
     * @param breakpointIndex Index
     * @throws IndexOutOfBoundsException if out of bounds.
     * @return Minimum SCTs
     * @see #getNumberOfBreakpoints
     */
    public int getMinSctsByIndex(int breakpointIndex) {
        return breakpoints.get(breakpointIndex).getMinSct();
    }
    
    /**
     * Returns the "less than months" validity restriction for the given index.
     * @param breakpointIndex Index
     * @throws IndexOutOfBoundsException if out of bounds.
     * @return "Less than months" value, or Integer.MAX_VALUE if infinite
     * @see #getNumberOfBreakpoints
     */
    public int getLessThanMonthsByIndex(int breakpointIndex) {
        return breakpoints.get(breakpointIndex).getLessThan();
    }
    
    /**
     * Returns the number of breakpoints
     */
    public int getNumberOfBreakpoints() {
        return breakpoints.size();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof GoogleCtPolicy)) {
            return false;
        }
        final GoogleCtPolicy other = (GoogleCtPolicy) obj;
        if (other.breakpoints == null ^ breakpoints == null) {
            return false;
        }
        if (other.breakpoints == null && breakpoints == null) {
            return true;
        }
        if (other.breakpoints.size() != breakpoints.size()) {
            return false;
        }

        for (int i = 0; i < breakpoints.size(); i++) {
            if (!breakpoints.get(i).equals(other.getBreakpoints().get(i))) {
                return false;
            }
        }

        return true;
    }

    @Override
    public int hashCode() {
        return breakpoints.stream().reduce(0, (acc, breakpoint) -> breakpoint.hashCode(), Integer::sum);
    }
    
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("GoogleCtPolicy{");
        for (int i = 0; i < breakpoints.size(); i++) {
            if (i != 0) {
                sb.append(',');
            }
            // Validity
            sb.append(breakpoints.get(i).toString());
        }
        sb.append('}');
        return sb.toString();
    }
}
