
# Format of column changed, no information was stored here earlier though
alter table CRLData add deltaCRLIndicator INT;
update CRLData set deltaCRLIndicator = -1;
alter table CRLData alter column deltaCRLIndicator set not null;
alter table CRLData alter column deltaCRLIndicator set default -1;
