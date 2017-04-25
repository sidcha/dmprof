#!/usr/bin/perl
use strict;

my $file=shift;

open my $F, '<', $file;

my @alloc_list=();
my @free_list=();
my @free_errors=();
my @anf_list=();

while (<$F>) {
        next if (/^ERROR:\s+Free\son\spersistent/);
        chomp;
        if (/^ERROR:\s+Free/) {
                s/^ERROR:\s+//;
                push @free_errors, $_;
        }
        next unless /^EVENT:\s/;
        s/EVENT:\s+//;
        if (/ALLOC\s+/) {
                s/ALLOC\s+//;
                push @alloc_list, $_;
                next;
        }
        if (/FREE\s+/) {
                s/FREE\s+//;
                push @free_list, $_;
                next;
        }
}

foreach my $alloc (@alloc_list) {
        my $found = 0;
        my ($alloc_uuid) = $alloc =~ m/\sUUID:(0x.{8})\s/;
        my $ndx = 0;
        foreach my $free (@free_list) {
                my ($free_uuid) = $free =~ m/\sUUID:(0x.{8})\s/;
                if ($free_uuid eq $alloc_uuid) {
                        $found =1;
                        splice @free_list, $ndx, 1;
                        last
                }
                $ndx++;
        }
	push @anf_list, $alloc unless ($found);
}

print "\ndmprof - Memory Report\n\n";

if (scalar @anf_list != 0) {
	print "Alloc No Free (ANF) list:\n";
	print "-------------------------\n";
	print "ANF: $_\n" foreach(@anf_list);
	print "\n";
}

if (scalar @free_list != 0) {
	print "Free Without Alloc (FWA) list:\n";
	print "-------------------\n";
	print "FWA: $_\n" foreach (@free_list);
	print "\n";
}

if (scalar @free_errors != 0) {
	print "Free Errors:\n";
	print "-------------------\n";
	print "FERR: $_\n" foreach (@free_errors);
	print "\n";
}

