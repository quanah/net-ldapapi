#!/usr/bin/perl -w
#
#  testwrite.pl - Test of LDAP URL Operations in Perl5
#  Author:  Clayton Donley <donley@cig.mot.com>
#
#  This script tests some of the basic LDAP URL functions.
#  Call the script with an LDAP URL to perform a search.

use strict;
use Net::LDAPapi;

my $urlhref;
my $url = $ARGV[0] || "ldap://ldap.four11.com/??sub?(cn=Clayton Donley)";

if (ldap_is_ldap_url($url))
{
   $urlhref = ldap_url_parse($url);
} else {
   die "$url: Not an LDAP Url.";
}

if ($urlhref)
{
   print "host: " . $urlhref->{'host'} . "\n";
   print "port: " . $urlhref->{'port'} . "\n";
   print "base: " . $urlhref->{'dn'} . "\n";

   my $attr;
   foreach $attr (@{$urlhref->{'attr'}})
   {
      print "attr: " . $attr . "\n";
   }
   print "filter: " . $urlhref->{'filter'} . "\n";
   print "scope: " . $urlhref->{'scope'} . "\n";

# If using Netscape, there is an options key specifying the use of SSL, etc...

   if ($urlhref->{'options'})
   {
      print "options: " . $urlhref->{'options'} . "\n"
   }

   print "Connecting...\n";

   my $port = $urlhref->{"port"} || 389;
   my $ld = new Net::LDAPapi(-host=>$urlhref->{"host"},-port=>$port);

   if ($ld == -1)
   {
      die "Connection failed...";
   }

   $ld->bind_s;

   $ld->url_search_s($url,0);

   my %record = %{$ld->get_all_entries};

   $ld->unbind;

   my @dns = (sort keys %record);
   print $#dns+1 . " entries returned.\n";

   foreach my $dn (@dns)
   {
      print "dn: $dn\n";
      foreach my $attr (keys %{$record{$dn}})
      {
         foreach my $item (@{$record{$dn}{$attr}})
         {
            if ($attr =~ /binary/)
            {
               print "$attr: binary - length=" . length($item) . "\n";
            } else {
               print "$attr: $item\n";
            }
         }
      }
   }

} else {
   print "Invalid LDAP URL: $url\n";
}
