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
package org.ejbca.util;

import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A list of slots numbers and indexes. Can contain ranges and individual entries.
 * 
 * @version $Id$
 */
public class SlotList {
    
    private static final class Range implements Comparable<Range> { 
        public final int min, max;
        public Range(int min, int max) {
            if (min > max) {
                throw new IllegalArgumentException("Minimum value ("+min+") in slot range is greater than maximum value ("+max+")");
            }
            this.min = min;
            this.max = max;
        }
        
        @Override
        public int compareTo(Range o) {
            if (min < o.min) return -1;
            if (min > o.min) return 1;
            else return 0;
        }
    }
    
    private final TreeSet<Range> ranges = new TreeSet<Range>();
    private final TreeSet<Range> indexRanges = new TreeSet<Range>();
    
    
    private int intval(String s, int defaultValue) {
        return s != null ? Integer.valueOf(s) : defaultValue;
    }
    
    private void addRange(Matcher m, int groupMin, int groupMax) {
        final int min = intval(m.group(groupMin), Integer.MIN_VALUE);
        final int max = intval(m.group(groupMax), Integer.MAX_VALUE);
        addRangeTo(ranges, min, max);
        
    }
    
    private void addIndexRange(Matcher m, int groupMin, int groupMax) {
        final int min = intval(m.group(groupMin), Integer.MIN_VALUE);
        final int max = intval(m.group(groupMax), Integer.MAX_VALUE);
        addRangeTo(indexRanges, min, max);
    }
    
    private void addRangeTo(TreeSet<Range> r, int min, int max) {
        Range toAdd = new Range(min, max);
        
        // Check for overlap with lower numbers
        final Range lower = r.floor(toAdd);
        if (lower != null && (lower.max >= min-1 || lower.max >= min)) { // special handling for integer overflows
            if (lower.max >= max) return; // complete overlap
            min = lower.min; // expand self
            toAdd = new Range(min, max);
            r.remove(lower);
        }
        
        // Check for overlap with higher numbers
        final Range higher = r.ceiling(toAdd);
        if (higher != null && (higher.min <= max+1 || higher.min <= max)) {
            if (higher.min <= min) return; // complete overlap
            max = higher.max;
            toAdd = new Range(min, max); // expand self
            r.remove(higher);
        }
        
        r.add(toAdd);
    }
    
    
    private static final Pattern slotListSingle = Pattern.compile("^([0-9]+)$");
    private static final Pattern slotListRange = Pattern.compile("^([0-9]+)?-([0-9]+)?$");
    private static final Pattern slotListISingle = Pattern.compile("^i([0-9]+)$");
    private static final Pattern slotListIRange = Pattern.compile("^i([0-9]+)?-i([0-9]+)?$");
    
    public static SlotList fromString(String s) {
        if (s == null) return null;
        final SlotList sl = new SlotList();
        if (s.trim().isEmpty()) return sl;
        
        for (String piece : s.split(",")) {
            piece = piece.trim();
            Matcher m;
            
            // Single entries
            m = slotListSingle.matcher(piece);
            // create a range from the first matcher group
            if (m.find()) { sl.addRange(m, 1, 1); continue; }
            
            m = slotListISingle.matcher(piece);
            if (m.find()) { sl.addIndexRange(m, 1, 1); continue; }
            
            
            // Range entries
            m = slotListRange.matcher(piece);
            // create a range from the matcher groups 1 and 2
            if (m.find()) { sl.addRange(m, 1, 2); continue; }
            
            m = slotListIRange.matcher(piece);
            if (m.find()) { sl.addIndexRange(m, 1, 2); continue; }
            
            throw new IllegalArgumentException("Invalid syntax of slot number or range: "+piece);
        }
        
        return sl;
    }
    
    public boolean contains(String slot) {
        final boolean isIndexed = slot.startsWith("i");
        final int number = Integer.valueOf(isIndexed ? slot.substring(1) : slot);
        final TreeSet<Range> tree = (isIndexed ? indexRanges : ranges);
        
        Range lower = tree.floor(new Range(number, number));
        return lower != null && number <= lower.max;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        
        // Slot numbers
        for (Range r : ranges) {
            if (r.min != Integer.MIN_VALUE) {
                sb.append(r.min);
            }
            if (r.min != r.max) {
                sb.append('-');
                if (r.max != Integer.MAX_VALUE) {
                    sb.append(r.max);
                }
            }
            sb.append(", ");
        }
        
        // Slot index numbers
        for (Range r : indexRanges) {
            sb.append('i');
            if (r.min != Integer.MIN_VALUE) {
                sb.append(r.min);
            }
            if (r.min != r.max) {
                sb.append("-i");
                if (r.max != Integer.MAX_VALUE) {
                    sb.append(r.max);
                }
            }
            sb.append(", ");
        }
        
        // Remove trailing comma
        if (sb.length() > 1) {
            sb.delete(sb.length()-2, sb.length());
        }
        
        return sb.toString();
    }
}
