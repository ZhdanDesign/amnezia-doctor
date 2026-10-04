#!/usr/bin/perl
# amnezia-doctor — сборка report.json из facts.txt и findings.tsv.
# Ключи сортируются (canonical), порядок находок сохраняется: одинаковый вход — байт-в-байт одинаковый выход.
use strict;
use warnings;
use JSON::PP;
use open qw(:std :encoding(UTF-8));

my ($facts_path, $findings_path, $verdict, $primary_id, $primary_title) = @ARGV;

my %facts;
open(my $ff, '<', $facts_path) or die "facts: $!";
while (my $l = <$ff>) {
    chomp $l;
    next unless $l =~ /^([A-Z0-9_]+)=(.*)$/;
    $facts{$1} = $2 unless exists $facts{$1};
}
close $ff;

my @findings;
open(my $fi, '<', $findings_path) or die "findings: $!";
while (my $l = <$fi>) {
    chomp $l;
    my ($level, $id, $title, $evidence, $rec) = split /\t/, $l, 5;
    next unless defined $id;
    push @findings, {
        level          => $level,
        id             => $id,
        title          => $title // '',
        evidence       => $evidence // '',
        recommendation => $rec // '',
    };
}
close $fi;

my $doc = {
    schema   => $facts{META_SCHEMA} // '',
    version  => $facts{META_VERSION} // '',
    target   => $facts{META_TARGET} // '',
    verdict  => { status => $verdict, primary_id => $primary_id, primary_title => $primary_title },
    findings => \@findings,
    facts    => \%facts,
};

print JSON::PP->new->canonical(1)->pretty->encode($doc);
