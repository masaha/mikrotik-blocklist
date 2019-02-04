#!/usr/bin/perl -w
#
# Download lists for blocking addresses (hosts and networks)
# formatted for Mikrotik RouterOS firewall
# marko(at)saha.se
#
#
use strict;
use warnings;
use Data::Dumper;
use HTTP::Tiny;
use LWP::Simple;
use Sys::Hostname;
use DBI;
use MCE::Loop;
#
sub uniq;
sub checkip;
#
# Define settings etc

my $time=scalar localtime();
my $tag=hostname;
# Settings for database
my $dsn = "DBI:mysql:DBNAME";
my $dbserver="DATABASE-SERVER";
my $username = "DBUSERNAME";
my $password = 'PASSWORD';
# Variables 
my $data;
my $url;
my $ipraw;
my $subnetraw;
my @SUBNET;
my @IPLIST;
my @IPCHECKED;
my %CHKSUBNET;
my %CHKIP;
my @temp;
#
# List of sources with ip-addresses to block
my @BLOCKLISTS=("http://danger.rulez.sk/projects/bruteforceblocker/blist.php", 
"http://cinsscore.com/list/ci-badguys.txt", 
"http://www.openbl.org/lists/base.txt", 
"http://www.autoshun.org/files/shunlist.csv", 
"http://lists.blocklist.de/lists/all.txt",
"https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt");
# List of sources with ip-address subnets to block
my @BLOCKNETLISTS=(
"http://www.wizcrafts.net/exploited-servers-iptables-blocklist.html",
"http://www.spamhaus.org/drop/drop.lasso");
#
# Lists with mixed entrys
my @MIXEDNETS=(
"https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset");
#
#
# main logic in script, two loops to fetch data
#
# check if we run locally on dbserver
if ($tag ne $dbserver) {
	print "Running on $tag\n";
	$dsn.=";host=".$dbserver;
	}
#
print "Start compiling blocklist\n";
print scalar localtime()."\n";
# This gets data from the various lists, first loop
foreach $url (@BLOCKLISTS) {
	print "Getting data from $url\n";
		if ( $data=get($url) ) {
			push @IPLIST, ($data =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
			print "Success fetching from $url\n";
		} else {
			print "Failed getting data from $url\n";
			}
}
#
# Second loop, get data from lists with subnets
# Need to use perl module HTTP::Tiny since some sites block lwp as user agent...
#
foreach $url (@BLOCKNETLISTS) {
	print "Getting data from $url\n";
		if ( $data=HTTP::Tiny->new->get($url) ) {
			push @SUBNET, (Dumper ($data) =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.\d{2})/g);
			print "Success fetching from $url\n";
		} else {
			print "Failed getting data from $url\n";
			}
}
#
# Third loop with mixed entrys
foreach $url (@MIXEDNETS) {
	print "Getting data from $url\n";
	if ( $data=get($url) ) {
		($data =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{0,2})/g);
		if ( ($4 ne "0") &&  ($4 == 0)) {
			push @SUBNET, (Dumper ($data) =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.\d{2})/g); 
		} else {
			push @IPLIST, ($data =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);
			}
	}
}
print "Done fetching data \n";
#
#
#
# Logic to find duplicates
#
my @UNIQ_IPLIST = uniq(@IPLIST);
my @UNIQ_SUBNET = uniq(@SUBNET);
#
# Check ip-address doesn't exists in ip subnet list, call 
# subroutine in_subnet for the checking, store in @IPCHECKED
# This is time consuming, area for optimisation...
#
my $found=0;
MCE::Loop::init {
        max_workers =>'auto', chunk_size =>1
};
@IPCHECKED = mce_loop { my $ipchecked;
        $ipraw=$_;
        $found=0;
        for my $i (0..$#UNIQ_SUBNET) {
                if ( checkip($ipraw,$UNIQ_SUBNET[$i]) ) {
                $found=1;
                last;
                }
                if (! $found) {
                        $ipchecked = $ipraw;
                }
        }
        MCE->gather($ipchecked);
} @UNIQ_IPLIST;
##
#
my @IPOUT = uniq(@IPCHECKED);
#
print "Finished compiling blocklist\n";
#
# Logic to import data to database, separate loop in case db connection fails
#
print "Dumping data to database $dsn\n";
#
# connect to MySQL database
my %attr = ( PrintError=>0,  # turn off error reporting via warn()
             RaiseError=>1);   # turn on error reporting via die()           
 
my $dbh  = DBI->connect($dsn,$username,$password, \%attr) or die "Error occurred: ",$DBI::errstr;
# Block with SQL insert statement
my $sth = $dbh->prepare("INSERT INTO adresses (address_type, address_value, created, updated, comment) values (?, ?, NOW(), NOW(), ?) ON DUPLICATE KEY UPDATE updated = NOW()");
#
for (@IPOUT) {
	chomp;
	$sth->execute("ip", $_, "") or die $DBI::errstr;
	
}
#
for (@UNIQ_SUBNET) {
	chomp;
	$sth->execute("block", $_, "") or die $DBI::errstr;
}
#
$sth->finish();
print "Finished dumping data to database!\n";
print scalar localtime()."\n";
exit;
#
# Subroutines
# -----------
#	
# Subroutine uniq
sub uniq {
	my %seen;
	return grep { !$seen{$_}++ } @_;
}
# Subroutine to check if ip-address is in subnet range
#
sub checkip() {
    my $ip = shift;
    my $block = shift;
    
    my @ip1 = split(/\./, $ip);
    my $ip1 = $ip1[0] * 2**24 + $ip1[1] * 2**16 + $ip1[2] * 2**8 + $ip1[3];
    my @temp = split(/\//, $block);
    
    my $ip2 = $temp[0];
    my $netmask = $temp[1];
    
    my @ip2 = split(/\./, $ip2);
    $ip2 = $ip2[0] * 2**24 + $ip2[1] * 2**16 + $ip2[2] * 2**8 + $ip2[3];
    
    if( $ip1 >> (32-$netmask) == $ip2 >> (32-$netmask) ) {
            return 1;
    }
    return 0;
}

