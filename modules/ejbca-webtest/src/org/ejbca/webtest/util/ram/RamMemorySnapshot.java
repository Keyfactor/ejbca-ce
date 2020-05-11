package org.ejbca.webtest.util.ram;

/**
 * Container for a single RAM memory snapshot from Runtime containing:
 * <ul>
 *     <li>Location: a string reference to execution location;</li>
 *     <li>Used Memory: calculated as Total Memory - Free Memory;</li>
 *     <li>Free Memory: value of Runtime.getRuntime().freeMemory();</li>
 *     <li>Total Memory: value of Runtime.getRuntime().totalMemory();</li>
 *     <li>Maximum Memory: value of Runtime.getRuntime().maxMemory().</li>
 * </ul>
 */
public class RamMemorySnapshot {

    private final String location;
    private final long usedMemory;
    private final long freeMemory;
    private final long totalMemory;
    private final long maxMemory;

    private RamMemorySnapshot(
            final String location,
            final long usedMemory,
            final long freeMemory,
            final long totalMemory,
            final long maxMemory
    ) {
        this.location = location;
        this.usedMemory = usedMemory;
        this.freeMemory = freeMemory;
        this.totalMemory = totalMemory;
        this.maxMemory = maxMemory;
    }

    public String getLocation() {
        return location;
    }

    public long getUsedMemory() {
        return usedMemory;
    }

    public long getFreeMemory() {
        return freeMemory;
    }

    public long getTotalMemory() {
        return totalMemory;
    }

    public long getMaxMemory() {
        return maxMemory;
    }

    public static RamMemorySnapshotBuilder builder() {
        return new RamMemorySnapshotBuilder();
    }

    /**
     * Builder class.
     */
    public static class RamMemorySnapshotBuilder {

        private String location;
        private long usedMemory;
        private long freeMemory;
        private long totalMemory;
        private long maxMemory;

        private RamMemorySnapshotBuilder() {
        }

        public RamMemorySnapshotBuilder withLocation(final String location) {
            this.location = location;
            return this;
        }

        public RamMemorySnapshotBuilder withUsedMemory(final long usedMemory) {
            this.usedMemory = usedMemory;
            return this;
        }

        public RamMemorySnapshotBuilder withFreeMemory(final long freeMemory) {
            this.freeMemory = freeMemory;
            return this;
        }

        public RamMemorySnapshotBuilder withTotalMemory(final long totalMemory) {
            this.totalMemory = totalMemory;
            return this;
        }

        public RamMemorySnapshotBuilder withMaxMemory(final long maxMemory) {
            this.maxMemory = maxMemory;
            return this;
        }

        public RamMemorySnapshot build() {
            return new RamMemorySnapshot(location, usedMemory, freeMemory, totalMemory, maxMemory);
        }
    }
}
