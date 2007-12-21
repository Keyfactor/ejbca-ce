
# Format of column changed, no information was stored here earlier though
alter table CRLData add deltaCRLIndicator bigint NOT NULL DEFAULT -1;

