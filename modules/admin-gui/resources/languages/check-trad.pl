#!/usr/bin/perl

#
# Bruno Bonfils, <bbonfils@linagora.com>
#
# Check for untranslated tags from ejbca's translation properties file
#
# usage:
# ./check-trad.pl language.en.properties language.fr.properties

use strict;
use Data::Dumper;

my $file_en = shift;
my $file_fr = shift;

die "Can't open $file_en and/or $file_fr !"
	unless (-r $file_en and -r $file_fr);

my $tags_en = {};
my $tags_fr = {};

my @untranslated = ();
my @missing = ();

sub load_tags {
	my $file = shift;
	my $tags = shift;
	my $fh;
	open ($fh, "< $file") or die "can't open $file";
	while (<$fh>) {
		if (/^([^\s]+)\s+=\s+(.+)/) {
			$tags->{$1} = $2 unless (-z $1 or -z $2);
		}
	}
	close ($fh);
}

load_tags ($file_en, $tags_en);
load_tags ($file_fr, $tags_fr);

# Check for tags where the french tag is the same than the english one
foreach my $tag (keys %{$tags_en}) {
	if ($tags_en->{$tag} eq $tags_fr->{$tag}) {
		push @untranslated, $tag;
	}
}

# Check for missing (untranslated) tags
foreach my $tag (keys %{$tags_en}) {
	push @missing, $tag if not defined $tags_fr->{$tag}
}

print "The following tags seem not translated:\n";
foreach (@untranslated) {
	print "   $_ : ", $tags_fr->{$_} ,"\n";
}

print "The following tags are missing:\n";
foreach (@missing) {
	print "   $_\n";
}
