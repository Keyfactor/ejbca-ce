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
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;

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
 * <p>You can then call the the factory method {@link #from(Set, BiPredicate)} to get a builder, and build the CA hierarchy like this:
 * <pre>
 * final Set&#60;T&#62; cas = Set.of(rootCa, issuingCa1, issuingCa2);
 * final BiPredicate&#60;T, T&#62; isSignedBy = createSomePredicate();
 * final CaHierarchy&#60;T&#62; caHierarchy = CaHierarchy.from(cas, isSignedBy)
 *     .buildSingleCaHierarchy();
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
 * If we represent the CAs with {@link Certificate} objects, we can use the factory method {@link #fromCertificates(Set)}
 * to conveniently create a builder with a built-in predicate.
 * <pre>
 * final CaHierarchy&#60;T&#62; caHierarchy = CaHierarchy.fromCertificates(cas)
 *     .buildSingleCaHierarchy();
 * </pre>
 * 
 * @version $Id$
 */
public class CaHierarchy<T> implements Comparable<CaHierarchy<T>>, Iterable<T> {
    private static final Logger log = Logger.getLogger(CaHierarchy.class);

    /**
     * The maximum permitted depth of a CA hierarchy.
     */
    private static final int MAX_DEPTH = 100;

    /**
     * A builder of {@link CaHierarchy} objects.
     */
    public static final class Builder<T> {
        private Set<T> cas;
        private BiPredicate<T, T> isSignedBy;

        /**
         * Create a new builder.
         * 
         * @param cas a set of CAs in the CA hierarchy.
         * @param isSignedBy a predicate taking a pair of CAs (A, B), outputting true iff A has signed B.
         */
        public Builder(final Set<T> cas, final BiPredicate<T, T> isSignedBy) {
            this.cas = cas;
            this.isSignedBy = isSignedBy;
        }

        /**
         * Build a single CA hierarchy. Use {@link #buildCaHierarchies()} if your input may represent
         * multiple CA hierarchies.
         * 
         * @return a single CA hierarchy.
         */
        public CaHierarchy<T> buildSingleCaHierarchy() {
            if (log.isTraceEnabled()) {
                log.trace("Creating a single CA hierarchy from: " + cas);
            }
            final List<CaHierarchy<T>> caHierarchies = buildCaHierarchies();
            if (caHierarchies.size() > 1) {
                throw new IllegalArgumentException("More than one CA hierarchy found.");
            }
            return caHierarchies.get(0);
        }

        /**
         * Build one or more CA hierarchies.
         * 
         * @return one or more CA hierarchies.
         */
        public List<CaHierarchy<T>> buildCaHierarchies() {
            if (log.isTraceEnabled()) {
                log.trace("Creating CA hierarchies from: " + cas);
            }
            final List<CaHierarchy<T>> caHierarchies = computeCaHierarchies();
            if (caHierarchies.isEmpty()) {
                throw new IllegalArgumentException("No CA hierarchies found.");
            }
            return caHierarchies;
        }
        
        private static <T> CaHierarchy<T> computeCaHierarchy(final Set<Edge<T>> edgesToProcess) {
            final Optional<Edge<T>> selfLoop = edgesToProcess.stream()
                    .filter(Edge::isSelfLoop)
                    .findAny();
            if (!selfLoop.isPresent()) {
                if (log.isTraceEnabled()) {
                    log.trace("Remaining edges: " + edgesToProcess);
                }
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
                        .filter(x -> !neighbouringEdges.contains(x))
                        .collect(Collectors.toList());
                neighbouringEdges.addAll(moreNeighbouringEdges);
            }
            return new CaHierarchy<>(edgesInCaHierarchy);
        }

        private List<CaHierarchy<T>> computeCaHierarchies() {
            final List<Edge<T>> allEdges = cas.stream().flatMap(a -> cas.stream().filter(b -> isSignedBy.test(a, b)).map(b -> new Edge<>(a, b)))
                    .collect(Collectors.toList());
            if (log.isTraceEnabled()) {
                log.trace("Computed edges: " + allEdges);
            }
            if (caHierarchyContainsDuplicateRoot(allEdges)) {
                throw new UnsupportedOperationException("CA hierarchy with duplicate root found.");
            }
            final List<CaHierarchy<T>> caHierarchies = new ArrayList<>();
            final Set<Edge<T>> edgesToProcess = new HashSet<>(allEdges);
            while (!edgesToProcess.isEmpty()) {
                caHierarchies.add(computeCaHierarchy(edgesToProcess));
            }
            return caHierarchies;
        }

        /**
         * Look for an edge (A -> B) where A ≠ B and both A and B are roots. This can happen if A and B both represent the
         * same CA, which would be the case if A has been renewed.
         *  
         * @param allEdges a list of edges describing one or more CA hierarchies.
         * @return true if a duplicate root was found, false otherwise.
         */
        private boolean caHierarchyContainsDuplicateRoot(final List<Edge<T>> allEdges) {
            return allEdges.stream().filter(candidate -> !candidate.isSelfLoop())
                    .filter(candidate -> allEdges.stream()
                            .filter(edge -> edge.isSelfLoop())
                            .anyMatch(edge -> edge.getA() == candidate.getA()))
                    .anyMatch(candidate -> allEdges.stream()
                            .filter(edge -> edge.isSelfLoop())
                            .anyMatch(edge -> edge.getB() == candidate.getB()));
        }
    }

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
    private final List<T> nodes;

    /**
     * Get a builder for building one or more CA hierarchies given a set of CAs of type <code>T</code> and a predicate.
     * 
     * @param cas a set of CAs in the CA hierarchy.
     * @param isSignedBy a predicate taking a pair of CAs (A, B), outputting true iff A has signed B.
     */
    public static <T> Builder<T> from(final Set<T> cas, final BiPredicate<T, T> isSignedBy) {
        return new Builder<>(cas, isSignedBy);
    }

    /**
     * Get a builder for building one or more CA hierarchies given a set of certificates.
     * 
     * @param certificates a set of certificates, where each certificate represents a CA in the CA hierarchy.
     * @return a builder.
     */
    public static Builder<Certificate> fromCertificates(final Set<Certificate> certificates) {
        return new Builder<>(certificates, isCertificateSignedBy());
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
        this.nodes = edges.stream()
                .map(edge -> edge.getB())
                .distinct()
                .map(ca -> new AbstractMap.SimpleImmutableEntry<>(ca, computeLevel(ca)))
                .sorted(compareAscending())
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());
        if (log.isTraceEnabled()) {
            log.trace("Initialized CA hierarchy with edges: " + edges + " and nodes: " + nodes);
        }
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
        return traverseEdgesUpstream(incomingEdges, 1);
    }

    private int traverseEdgesUpstream(final List<Edge<T>> incomingEdges, final int currentDepth) {
        if (currentDepth >= MAX_DEPTH) {
            if (log.isTraceEnabled()) {
                log.trace("Next set of edges to traverse: " + incomingEdges);
            }
            throw new IllegalStateException("The CA hierarchy is too deep.");
        }
        if (incomingEdges.get(0).isSelfLoop()) {
            return 0;
        }
        int maxLevel = 0;
        for (final Edge<T> incomingEdge : incomingEdges) {
            final List<Edge<T>> newIncomingEdges = edges.stream()
                    .filter(x -> x.getB() == incomingEdge.getA())
                    .collect(Collectors.toList());
            final int nextLevel = traverseEdgesUpstream(newIncomingEdges, currentDepth + 1);
            maxLevel = Math.max(nextLevel + 1, maxLevel);
        }
        return maxLevel;
    }

    private Comparator<? super Entry<T, Integer>> compareAscending() {
        return (a, b) -> {
            return a.getValue().compareTo(b.getValue());
        };
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
     * Computes a list of all (unique) CAs in this CA hierarchy, topologically ordered by level in the CA
     * hierarchy, i.e. if a CA A has signed another CA B, A is guaranteed to appear before B in the returned
     * list.
     * 
     * @return a topologically sorted list of all CAs in this CA hierarchy.
     */
    public List<T> toList() {
        return new ArrayList<>(nodes);
    }

    /**
     * Get the number of certificate authorities in this CA hierarchy.
     * 
     * @return the number of certificate authorities in this CA hierarchy.
     */
    public int size() {
        return nodes.size();
    }

    /**
     * Get the edges in this CA hierarchy. An edge (A -> B) is constructed for each pair of CAs, such
     * that A has signed B.
     * 
     * @return a list of edges describing this CA hierarchy.
     */
    protected List<Edge<T>> getEdges() {
        return new ArrayList<>(edges);
    }

    /**
     * Compares two CA hierarchies based on size in ascending order.
     * 
     * @param anotherCaHierarchy another CA hierarchy to compare with.
     * @return a negative number if this CA hierarchy is smaller than the other CA hierarchy, zero if they have
     * the same size, and a positive number of this CA hierarchy is larger than the other CA hierarchy.
     */
    @Override
    public int compareTo(final CaHierarchy<T> anotherCaHierarchy) {
        return Integer.compare(toList().size(), anotherCaHierarchy.toList().size());
    }

    /**
     * Get an iterator for this CA hierarchy, iterating over the CAs in this CA hierarchy in the order
     * returned by {@link #toList()}.
     * 
     * @return an iterator for this CA hierarchy.
     */
    @Override
    public Iterator<T> iterator() {
        return toList().iterator();
    }
}