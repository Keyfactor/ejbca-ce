
# Format of column changed, no information was stored here earlier though
alter table CRLData add deltaCRLIndicator int(11) NOT NULL DEFAULT -1;
