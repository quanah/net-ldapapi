#!/usr/bin/perl

use strict;
use warnings;
  
use Test::More;
use Test::BDD::Cucumber::StepFile;

use Net::LDAPapi;
use Convert::ASN1;

our %TestConfig = %main::TestConfig;

use Data::Dumper;

Given qr/the server side sort control definition/i, sub { 
  if (!defined(S->{'asn'}{'server side sort'})) {
    S->{'asn'}{'server side sort'} = Convert::ASN1->new;
  
    S->{'asn'}{'server side sort'}->prepare(<<ASN) or die "prepare: ", S->{'asn'}{'server side sort'}->error;
  
  SortKey ::= SEQUENCE {
    attributeType   OCTET STRING,
    orderingRule    [0] OCTET STRING OPTIONAL,
    reverseOrder    [1] BOOLEAN }

  SortKeyList ::= SEQUENCE OF SortKey

  SortResult ::= SEQUENCE {
    sortResult  ENUMERATED,
    attributeType [0] OCTET STRING OPTIONAL }

ASN
  }
};


When qr/I've created a server side sort control/i, sub {
  my $sss = S->{'asn'}{'server side sort'}->find('SortKeyList');

  my $sss_berval = $sss->encode($TestConfig{'server_controls'}{'sss'}) or die S->{'asn'}{'server side sort'}->error;

  my $sss_ctrl = S->{'object'}->create_control(
    -oid => '1.2.840.113556.1.4.473',
    -berval => $sss_berval,
  );

  push(@{S->{'server_controls'}{'server side sort'}}, $sss_ctrl);
};

Then qr/the server side sort control was successfully used/i, sub {
  my $sss_response = S->{'asn'}{'server side sort'}->find('SortResult');

  my $berval = undef;
  
  foreach my $ctrl (@{S->{'cache'}{'serverctrls'}}) {
    my $ctrl_oid = S->{'object'}->get_control_oid($ctrl);
    
    if ($ctrl_oid eq '1.2.840.113556.1.4.474') {
      $berval = S->{'object'}->get_control_berval($ctrl);
      last;
    }
  }
  
  isnt($berval, undef, "Was a berval returned?");
  
  my $result = $sss_response->decode($berval) || ok(0, $sss_response->error);

  is(ldap_err2string($result->{'sortResult'}), ldap_err2string(LDAP_SUCCESS), "Does server side sort result code match?");        
};

1;
