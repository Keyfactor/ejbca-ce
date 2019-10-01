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

package org.cesecore.certificates.ca;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

/**
 * This class represents a CA hierarchy as an immutable graph. Each node in the graph contains
 * a CA of type <code>T</code>.
 * 
 * <p>As a minimal example, consider a CA hierarchy with three CAs, one root and two issuing CAs. 
 * <pre>
 *             +---------+
 *        +----+ Root CA +-----+
 *        |    +---------+     |
 *        |                    |
 *        |                    |
 * +------v------+      +------v-----+
 * | Issuing CA 1|      |Issuing CA 2|
 * +-------------+      +------------+
 * </pre>
 * 
 * To create an instance of this class, you need to provide a set containing the three CAs, and a predicate which takes
 * a pair of CAs <code>(A, B)</code> and outputs true iff A has signed B.
 * 
 * <p>You can then call the the factory method {@link #singleCaHierarchyFrom(Set, BiPredicate)} to build the CA hierarchy, like this:
 * <pre>
 * final Set&#60;T&#62; cas = Set.of(rootCa, issuingCa1, issuingCa2);
 * final BiPredicate&#60;T, T&#62; isSignedBy = createSomePredicate();
 * final CaHierarchy&#60;T&#62; caHierarchy = CaHierarchy.singleCaHierarchyFrom(cas, isSignedBy);
 * System.out.println(caHierarchy);
 * </pre>
 * 
 * This would, for each pair <code>(A, B)</code> of CAs where A has signed B, output an edge <code>(A -> B)</code>, demonstrating
 * how the CA hierarchy is modeled:
 * <pre>
 * (rootCa -> rootCa)
 * (rootCa -> issuingCa1)
 * (rootCa -> issuingCa2)
 * </pre>
 * 
 * If we represent the CAs with {@link Certificate} objects, we can use the factory method {@link #singleCaHierarchyFrom(Set)}
 * to conveniently create a CA hierarchy with a built-in predicate.
 * <pre>
 * final CaHierarchy&#60;T&#62; caHierarchy = CaHierarchy.fromCertificates(cas);
 * </pre>
 * 
 * @version $Id$
 */
public class CaHierarchy<T> {
    /**
     * Represents an edge <code>(A -> B)</code> in a graph, where A and B are CAs and A has signed B.
     * 
     * <p>Used as a helper class when performing computations on the CA hierarchy.
     */
    private static final class Edge<T> {
        private final T a;
        private final T b;

        public static <T> boolean isAdjacent(final Edge<T> x, final Edge<T> y) {
            return y.getB() == x.getA() || 
                   y.getB() == x.getB() ||
                   y.getA() == x.getA() ||
                   y.getA() == x.getB();
        }

        /**
         * Create a new edge <code>(A -> B)</code> from a pair of CAs.
         * 
         * @param a the issuer CA.
         * @param b the subordinate CA signed by the issuer CA.
         */
        public Edge(final T a, final T b) {
            this.a = a;
            this.b = b;
        }
        
        public T getA() {
            return a;
        }

        public T getB() {
            return b;
        }

        public boolean isSelfLoop() {
            return a == b;
        }

        @Override
        public String toString() {
            return String.format("(%s -> %s)", a, b);
        }
    }
    
    private final List<Edge<T>> edges;

    /**
     * Create a single CA hierarchy from a set of certificates. Use {@link #caHierarchiesFrom(Set)} if your
     * input may represent multiple CA hierarchies.
     * 
     * @param certificates a set of certificates, where each certificate represents a CA in the CA hierarchy.
     * @return a single CA hierarchy.
     */
    public static CaHierarchy<Certificate> singleCaHierarchyFrom(final Set<Certificate> certificates) {
        return singleCaHierarchyFrom(certificates, isCertificateSignedBy());
    }

    /**
     * Create one or more CA hierarchies from a set of certificates.
     * 
     * @param certificates a set of certificates, where each certificate represents a CA in the CA hierarchy.
     * @return one or more CA hierarchies.
     */
    public static List<CaHierarchy<Certificate>> caHierarchiesFrom(final Set<Certificate> certificates) {
        return caHierarchiesFrom(certificates, isCertificateSignedBy());
    }

    /**
     * Create a single CA hierarchy from a set of objects of type <code>T</code> and a predicate. Use 
     * {@link #caHierarchiesFrom(Set)} if your input may represent multiple CA hierarchies.
     * 
     * @param <T> the type representing a CA.
     * @param cas a set of CAs in the CA hierarchy.
     * @param isSignedBy a predicate taking a pair of CAs (A, B), outputting true iff A has signed B.
     * @return a single CA hierarchy.
     */
    public static <T> CaHierarchy<T> singleCaHierarchyFrom(final Set<T> cas, final BiPredicate<T, T> isSignedBy) {
        final List<CaHierarchy<T>> caHierarchies = caHierarchiesFrom(cas, isSignedBy);
        if (caHierarchies.size() > 1) {
            throw new IllegalArgumentException("More than one CA hierarchy found.");
        }
        return caHierarchies.get(0);
    }

    /**
     * Create one or more CA hierarchies from a set of objects of type <code>T</code> and a predicate.
     * 
     * @param <T> the type representing a CA.
     * @param cas a set of CAs in the CA hierarchy.
     * @param isSignedBy a predicate taking a pair of CAs (A, B), outputting true iff A has signed B.
     * @return one or more CA hierarchies.
     */
    public static <T> List<CaHierarchy<T>> caHierarchiesFrom(final Set<T> cas, final BiPredicate<T, T> isSignedBy) {
        final List<CaHierarchy<T>> caHierarchies = computeCaHierarchies(cas, isSignedBy);
        if (caHierarchies.size() == 0) {
            throw new IllegalArgumentException("No CA hierarchies found.");
        }
        return caHierarchies;
    }
    
    private static <T> List<CaHierarchy<T>> computeCaHierarchies(final Set<T> cas, final BiPredicate<T, T> isSignedBy) {
        final List<Edge<T>> allEdges = cas.stream()
                .flatMap(a -> cas.stream().filter(b -> isSignedBy.test(a, b)).map(b -> new Edge<T>(a, b)))
                .collect(Collectors.toList());
        final List<CaHierarchy<T>> caHierarchies = new ArrayList<>();
        final Set<Edge<T>> edgesToProcess = new HashSet<>(allEdges);
        while (!edgesToProcess.isEmpty()) {
            caHierarchies.add(computeCaHierarchy(edgesToProcess));
        }
        return caHierarchies;
    }

    private static <T> CaHierarchy<T> computeCaHierarchy(final Set<Edge<T>> edgesToProcess) {
        final Optional<Edge<T>> selfLoop = edgesToProcess.stream()
                .filter(edge -> edge.isSelfLoop())
                .findAny();
        if (!selfLoop.isPresent()) {
            throw new IllegalArgumentException("CA hierarchy without a root found.");
        }
        final List<Edge<T>> edgesInCaHierarchy = new ArrayList<>();
        final List<Edge<T>> neighbouringEdges = new ArrayList<>();
        neighbouringEdges.add(selfLoop.get());
        while (!neighbouringEdges.isEmpty()) {
            final Edge<T> nextEdgeInCaHierarchy = neighbouringEdges.remove(0);
            edgesInCaHierarchy.add(nextEdgeInCaHierarchy);
            edgesToProcess.remove(nextEdgeInCaHierarchy);
            final List<Edge<T>> moreNeighbouringEdges = edgesToProcess.stream()
                    .filter(x -> Edge.isAdjacent(x, nextEdgeInCaHierarchy))
                    .filter(x -> !edgesInCaHierarchy.contains(x))
                    .collect(Collectors.toList());
            neighbouringEdges.addAll(moreNeighbouringEdges);
        }
        return new CaHierarchy<>(edgesInCaHierarchy);
    }

    /**
     * Predicate determining whether a CA is signed by another CA based on two certificates.
     * 
     * @return a predicate taking a pair of certificates (A, B) as input, and outputting true iff A has signed B.
     */
    private static BiPredicate<Certificate, Certificate> isCertificateSignedBy() {
        return (a, b) -> {
            try {
                b.verify(a.getPublicKey());
                return true;
            } catch (final SignatureException e) {
                return false;
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private CaHierarchy(final List<Edge<T>> edges) {
        this.edges = edges;
    }

    /**
     * Returns a textual representation of this CA hierarchy as a list of edges <code>(A -> B)</code>
     * where A and B are CAs, such that A has signed B.
     * 
     * <p>Example output for a CA hierarchy with one root CA and one issuing CA:
     * <pre>
     * [(rootCa -> rootCa), (rootCa, issuingCa)]
     * </pre>
     */
    @Override
    public String toString() {
        return edges.toString();
    }
    
    /**
     * Computes the level of a CA in this CA hierarchy, where the level of a root CA is 0.
     * 
     * <p>If this CA given as argument chains to multiple roots, the return value indicates the length
     * of the longest path to any root.
     * 
     * @param ca the CA whose level should be computed.
     * @return the level of the CA given as argument, starting at zero.
     */
    private int computeLevel(final T ca) {
        final List<Edge<T>> incomingEdges = edges.stream()
                .filter(edge -> edge.getB() == ca)
                .collect(Collectors.toList());
        return traverseEdgesUpstream(incomingEdges);
    }

    private int traverseEdgesUpstream(final List<Edge<T>> incomingEdges) {
        if (incomingEdges.get(0).isSelfLoop()) {
            return 0;
        }
        int maxLevel = 0;
        for (final Edge<T> incomingEdge : incomingEdges) {
            final List<Edge<T>> newIncomingEdges = edges.stream()
                    .filter(x -> x.getB() == incomingEdge.getA())
                    .collect(Collectors.toList());
            final int nextLevel = traverseEdgesUpstream(newIncomingEdges) + 1;
            maxLevel = Math.max(nextLevel, maxLevel);
        }
        return maxLevel;
    }

    private Comparator<? super Entry<T, Integer>> compareAscending() {
        return (a, b) -> {
            return a.getValue().compareTo(b.getValue());
        };
    }

    /**
     * Computes a list of all (unique) CAs in this CA hierarchy, topologically ordered by level in the CA
     * hierarchy, i.e. if a CA A has signed another CA B, A is guaranteed to appear before B in the returned
     * list.
     * 
     * @return a topologically sorted list of all CAs in this CA hierarchy.
     */
    public List<T> toList() {
        return edges.stream()
                .map(edge -> edge.getB())
                .distinct()
                .map(ca -> new AbstractMap.SimpleImmutableEntry<T, Integer>(ca, computeLevel(ca)))
                .sorted(compareAscending())
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());
    }
}