#!/usr/bin/perl
# Password analysis for cain&abel output
# by Tengku Zahasman

#use strict;
use warnings;
use Getopt::Long;
use File::Basename;

my $basename = basename($0);

# usage information 
sub show_help {
	print <<HELP;
CAIN&ABEL PASSWORD ANALYSIS - by z3mms

Usage: ./$basename -f [PATH TO LMNT.LST]

Options:
	-f	file to LMNT.LST
	-c	common password to search
	-v	verbose weak users and their passwords (yes/no)
	-h	help
	
HELP
	exit 1;
}

# declare variables
my $file = 'LMNT.LST';
my $help = 0;
my @counter;
my @data;
my @line;
my $total_lines = 0;
my $common = "typical";
my $verbose = "no";

GetOptions(
	"f=s" => \$file,
	"c=s" => \$common,
	"v=s" => \$verbose,
	'h'   => \$help,
) or show_help;

$help and show_help;

open (FILE, $file) or die "Cannot open $file for read :$!";

#######################################
# analyse them passwords!
#######################################
sub analyse {

	# initialize counters
	$counter[0] = 0;
	$counter[1] = 0;
	$counter[2] = 0;
	$counter[3] = 0;
	$counter[4] = 0;
	$counter[5] = 0;
	$counter[6] = 0;
	$counter[7] = 0;
	$counter[8] = 0;
	$counter[9] = 0;
	$counter[10] = 0;
	$counter[11] = 0;
	
	# generic variable
	my $i;

	while(<FILE>) {
		@line = split(/\t/);
		
		# how many passwords cracked?
		if ($line[3] ne "") {
			$counter[0]++;
		}
		
		# how many users have passwords similar to their username?
		if (uc($line[0]) eq uc($line[3])) {
			$counter[1]++;
			$data[1][$counter[1]][1] .= $line[0];
			$data[1][$counter[1]][2] .= $line[3];
		}
		
		# how many users have passwords as 'password', 'password1', 'password12' or 'password123'?
		$i=0;
		if (uc($line[3]) =~ /PASSWORD([0-9]{1,2})*/) {
			$counter[2]++;
			$data[2][$counter[2]][1] .= $line[0];
			$data[2][$counter[2]][2] .= $line[3];
		}
		
		# how many users have passwords less than 8 characters?
		if (length($line[3]) < 8 and length($line[3]) != 0) {
			$counter[3]++;
			$data[3][$counter[3]][1] .= $line[0];
			$data[3][$counter[3]][2] .= $line[3];
		}
		
		# how many users have passwords as 123456?
		if ($line[3] eq "123456") {
			$counter[4]++;
			$data[4][$counter[4]][1] .= $line[0];
			$data[4][$counter[4]][2] .= $line[3];
		}
		
		# how many users have no password set?
		if ($line[3] eq "* empty *" && $line[0] ne "Guest") {
			$counter[5]++;
			$data[5][$counter[5]][1] .= $line[0];
			$data[5][$counter[5]][2] .= $line[3];
		}
		
		# how many users have password set as one of the four seasons?
		my @season = ( "SPRING", "SUMMER", "AUTUMN", "WINTER" );
		$i=0;
		foreach (@season) {
			$season[$i] = uc($season[$i]);
			if (uc($line[3]) =~ m/($season[$i])([0-9]{1,2})*/) {
				$counter[6]++;
				$data[6][$counter[6]][1] .= $line[0];
				$data[6][$counter[6]][2] .= $line[3];
			}
			$i++;
		}
		
		# how many users have password set as one of the calendar month?
		my @month = ( "JANUARY", "FEBRUARY", "MARCH", "APRIL", "MAY", "JUNE", "JULY", "AUGUST", "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER" );
		$i=0;
		foreach (@month) {
			$month[$i] = uc($month[$i]);
			if (uc($line[3]) =~ m/($month[$i])([0-9]{1,2})*/) {
				$counter[7]++;
				$data[7][$counter[7]][1] .= $line[0];
				$data[7][$counter[7]][2] .= $line[3];
			}
			$i++;
		}

		# how many users have password set as one of the week days?
		my @day = ( "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY" );
		$i=0;
		foreach (@day) {
			$day[$i] = uc($day[$i]);
			if (uc($line[3]) =~ m/($day[$i])([0-9]{1,2})*/) {
				$counter[8]++;
				$data[8][$counter[8]][1] .= $line[0];
				$data[8][$counter[8]][2] .= $line[3];
			}
			$i++;
		}

		# how many users have password set as abc123?
		if (uc($line[3]) eq "ABC123") {
			$counter[9]++;
			$data[9][$counter[9]][1] .= $line[0];
			$data[9][$counter[9]][2] .= $line[3];
		}
		
		my $common = uc($common);
		# how many users use the common passwords specified with -c ?
		if (uc($line[3]) =~ m/($common)([0-9]{1,2})*/) {
			$counter[10]++;
			$data[10][$counter[10]][1] .= $line[0];
			$data[10][$counter[10]][2] .= $line[3];
		}
		
		# how many users have their password hashes stored in LM format?
		if (uc($line[4]) ne "AAD3B435B51404EEAAD3B435B51404EE" && uc($line[4]) ne "NO PASSWORD*********************") {
			$counter[11]++;
			$data[11][$counter[11]][1] .= $line[0];
			$data[11][$counter[11]][2] .= $line[4];
		}  
		
		$total_lines++;
	}
	
	close (FILE);

	if ($counter[0] != 0) { print "* " . $counter[0] . " total passwords cracked out of ".$total_lines." passwords -- " . sprintf("%.2f",($counter[0]/$total_lines)*100) . "%\n"; }
	if ($counter[1] != 0) { print "* " . $counter[1] . " users have password similar to their username -- " . sprintf("%.2f",($counter[1]/$total_lines)*100) . "%\n"; }
	if ($counter[2] != 0) { print "* " . $counter[2] . " users have password such as '" . (scalar @{$data[2]} > 2 ? $data[2][rand(scalar @{$data[2]}-1)+1][2] . "', '" . $data[2][rand(scalar @{$data[2]}-1)+1][2] : $data[2][1][2]) . "' -- " . sprintf("%.2f",($counter[2]/$total_lines)*100) . "%\n"; }
	if ($counter[3] != 0) { print "* " . $counter[3] . " users have password less than 8 characters -- " . sprintf("%.2f",($counter[3]/$total_lines)*100) . "%\n"; }
	if ($counter[4] != 0) { print "* " . $counter[4] . " users have password as '123456' -- " . sprintf("%.2f",($counter[4]/$total_lines)*100) . "%\n"; }
	if ($counter[5] != 0) { print "* " . $counter[5] . " users have no password set -- " . sprintf("%.2f",($counter[5]/$total_lines)*100) . "%\n"; }
	if ($counter[6] != 0) { print "* " . $counter[6] . " users have their password set as one of the four seasons (eg: '". (scalar @{$data[6]} > 2 ? $data[6][rand(scalar @{$data[6]}-1)+1][2] . "', '" . $data[6][rand(scalar @{$data[6]}-1)+1][2] : $data[6][1][2]) ."') -- " . sprintf("%.2f",($counter[6]/$total_lines)*100) . "%\n"; }
	if ($counter[7] != 0) { print "* " . $counter[7] . " users have their password set as one of the calendar month (eg: '". (scalar @{$data[7]} > 2 ? $data[7][rand(scalar @{$data[7]}-1)+1][2] . "', '" . $data[7][rand(scalar @{$data[7]}-1)+1][2] : $data[7][1][2]) ."') -- " . sprintf("%.2f",($counter[7]/$total_lines)*100) . "%\n"; }
	if ($counter[8] != 0) { print "* " . $counter[8] . " users have their password set as one of the week days (eg: '". (scalar @{$data[8]} > 2 ? $data[8][rand(scalar @{$data[8]}-1)+1][2] . "', '" . $data[8][rand(scalar @{$data[8]}-1)+1][2] : $data[8][1][2]) ."') -- " . sprintf("%.2f",($counter[8]/$total_lines)*100) . "%\n"; }
	if ($counter[9] != 0) { print "* " . $counter[9] . " users have password as 'abc123' -- " . sprintf("%.2f",($counter[9]/$total_lines)*100) . "%\n"; }
	if ($counter[10] != 0) { print "* " . $counter[10] . " users have password containing '".$common."', eg: '". (scalar @{$data[10]} > 2 ? $data[10][rand(scalar @{$data[10]}-1)+1][2] . "', '" . $data[10][rand(scalar @{$data[10]}-1)+1][2] : $data[10][1][2]) ."' -- " . sprintf("%.2f",($counter[10]/$total_lines)*100) . "%\n"; }
	if ($counter[11] != 0) { print "* " . $counter[11] . " users have their password hashes stored in the weak LM format -- " . sprintf("%.2f",($counter[11]/$total_lines)*100) . "%\n"; }
	
	if ($verbose eq "yes") {
	
		if ($counter[1] != 0) {
		print "===============================\n";
		print "Users with passwords similar to their username\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[1]}) {
				print $data[1][$i][1] . "\t" . $data[1][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[2] != 0) {
		print "===============================\n";
		print "Users with passwords as '" . (scalar @{$data[2]} > 2 ? $data[2][rand(scalar @{$data[2]}-1)+1][2] . "', '" . $data[2][rand(scalar @{$data[2]}-1)+1][2] : $data[2][1][2]) . "', etc\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[2]}) {
				print $data[2][$i][1] . "\t" . $data[2][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[3] != 0) {
		print "===============================\n";
		print "Users with passwords less than 8 characters\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[3]}) {
				print $data[3][$i][1] . "\t" . $data[3][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[4] != 0) {
		print "===============================\n";
		print "Users with password as 123456\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[4]}) {
				print $data[4][$i][1] . "\t" . $data[4][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[5] != 0) {
		print "===============================\n";
		print "Users with no passwords set\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[5]}) {
				print $data[5][$i][1] . "\t" . $data[5][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[6] != 0) {
		print "===============================\n";
		print "Users with password as one of the four seasons (eg: '". (scalar @{$data[6]} > 2 ? $data[6][rand(scalar @{$data[6]}-1)+1][2] . "', '" . $data[6][rand(scalar @{$data[6]}-1)+1][2] : $data[6][1][2]) ."')\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[6]}) {
				print $data[6][$i][1] . "\t" . $data[6][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[7] != 0) {
		print "===============================\n";
		print "Users with password as one of the calendar months ('". (scalar @{$data[7]} > 2 ? $data[7][rand(scalar @{$data[7]}-1)+1][2] . "', '" . $data[7][rand(scalar @{$data[7]}-1)+1][2] : $data[7][1][2]) ."')\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[7]}) {
				print $data[7][$i][1] . "\t" . $data[7][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[8] != 0) {
		print "===============================\n";
		print "Users with password as one of the week days (eg: '". (scalar @{$data[8]} > 2 ? $data[8][rand(scalar @{$data[8]}-1)+1][2] . "', '" . $data[8][rand(scalar @{$data[8]}-1)+1][2] : $data[8][1][2]) ."')\n";
		print "===============================\n";
		$i = 1;
		while ($i < scalar @{$data[8]}) {
				print $data[8][$i][1] . "\t" . $data[8][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[9] != 0) {
		print "===============================\n";
		print "Users with password as abc123\n";
		print "===============================\n";
	    $i = 1;	
        while ($i < scalar @{$data[9]}) {
				print $data[9][$i][1] . "\t" . $data[9][$i][2] . "\n";
				$i++;
			}
		}
		
		if ($counter[10] != 0) {
		print "===============================\n";
		print "Users with password containing '".$common."', such as '" . (scalar @{$data[10]} > 2 ? $data[10][rand(scalar @{$data[10]}-1)+1][2] . "', '" . $data[10][rand(scalar @{$data[10]}-1)+1][2] : $data[10][1][2]) . "'\n";
		print "===============================\n";
	    $i = 1;	
        while ($i < scalar @{$data[10]}) {
				print $data[10][$i][1] . "\t" . $data[10][$i][2] . "\n";
				$i++;
			}
		}

		if ($counter[11] != 0) {
		print "===============================\n";
		print "Users having their passwords stored in weak LM format";
		print "===============================\n";
	    $i = 1;	
        while ($i < scalar @{$data[11]}) {
				print $data[11][$i][1] . "\t" . $data[11][$i][2] . "\n";
				$i++;
			}
		}
	}
}

# start
analyse();
