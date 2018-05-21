package org.ejbca.ui.web.rest.api.types;

/**
 * @author Jekaterina Bunina, Helmes AS, jekaterina.bunina@helmes.ee
 */
public class ResponseStatus {
    private boolean moreResults;
    private int nextOffset;
    private int numberOfResults;

    private ResponseStatus(boolean moreResults, int nextOffset, int numberOfResults) {
        this.moreResults = moreResults;
        if(moreResults) {
            this.nextOffset = nextOffset;
            this.numberOfResults = numberOfResults;
        }
    }

    public boolean isMoreResults() {
        return moreResults;
    }

    public void setMoreResults(boolean moreResults) {
        this.moreResults = moreResults;
    }

    public int getNextOffset() {
        return nextOffset;
    }

    public void setNextOffset(int nextOffset) {
        this.nextOffset = nextOffset;
    }

    public int getNumberOfResults() {
        return numberOfResults;
    }

    public void setNumberOfResults(int numberOfResults) {
        this.numberOfResults = numberOfResults;
    }
    public static ResponseStatusBuilder builder() {
        return new ResponseStatusBuilder();
    }

    public static class ResponseStatusBuilder {
        private boolean moreResults;
        private int nextOffset;
        private int numberOfResults;

        public ResponseStatusBuilder setMoreResults(boolean moreResults) {
            this.moreResults = moreResults;
            return this;
        }

        public ResponseStatusBuilder setNextOffset(int nextOffset) {
            this.nextOffset = nextOffset;
            return this;
        }

        public ResponseStatusBuilder setNumberOfResults(int numberOfResults) {
            this.numberOfResults = numberOfResults;
            return this;
        }

        public ResponseStatus build() {
            return new ResponseStatus(moreResults, nextOffset, numberOfResults);
        }
    }
}
