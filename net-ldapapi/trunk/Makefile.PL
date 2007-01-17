use ExtUtils::MakeMaker;
use Config;

print "\n\nNet::LDAPapi Perl5 Module - by Clayton Donley <donley\@cig.mcel.mot.com>\n\n";
print "OpenLDAP support by Symas Corporation -- http://www.symas.com\n";

$pl_path = $Config{'perlpath'};

unless ($sdk)
{
   print "\nSelect your Development Kit:\n";
   print "  1.  Netscape (default)\n";
   print "  2.  University of Michigan\n";
   print "  3.  ISODE (compiled with LDAP)\n";
   print "  4.  OpenLDAP\n";
   print "Choose: ";
   $sdk = <>;
}

$version = ($sdk == 2 ? 'UMICH' :
	    $sdk == 3 ? 'ISODE' :
	    $sdk == 4 ? 'OPENLDAP' :
	    'NETSCAPE');

$lname = ($version eq 'ISODE' ? 'ISODE' : 'LDAP');

if ($include_ldap eq "")
{
   if ($version eq 'ISODE')
   {
      print "Location *above* isode/ Include Dir (default: /usr/include):  ";
   } else {
      print "Location of $lname Include Files (default: /usr/include):  ";
   }
   chomp($include_ldap = <>);
   $include_ldap = "/usr/include" unless $include_ldap =~ /\S/;
}

# Sigh... isode-8 has isode/ldap.h, isode IC has isode/ldap/ldap.h
if (! -r "$include_ldap/ldap.h")
{
   for $ldapsubdir ("ldap","isode","isode/ldap")
   {
      if (-r "$include_ldap/$ldapsubdir/ldap.h")
      {
         $include_ldap .= "-I$include_ldap/$ldapsubdir";
         last;
      }
   }
}

if ($lib_ldap eq "")
{
   $df_lib = ($include_ldap =~ m%^(\S+)/include% ? "$1/lib" : "/usr/lib");
   print "Location of $lname Library Files (default: $df_lib):  ";
   chomp($lib_ldap = <>);
   $lib_ldap = $df_lib unless $lib_ldap =~ /\S/;
}

if ($version eq "UMICH" && $kerblibs eq "")
{
   print "Using Kerberos for Authentication (default: n)? ";
   $usekerb = <>;
   if ($usekerb =~ /^y.*/i)
   {
      $kerblibs = "-lkrb -ldes";
   }
}

if ($version eq "NETSCAPE")
{
   print "Using Netscape's NEW LDAPv3 Development Kit (default: n)? ";
   $useldapv3 = <>;
   if ($useldapv3 =~ /y.*/i)
   {
      if ($Config::Config{'osname'} eq 'MSWin32')
      {
         $ldap_lib = 'nsldapssl32v30';
      } elsif ($Config::Config{'osname'} eq 'aix')
      {
         $ldap_lib = 'ldapssl30';
      } else {
         $ldap_lib = 'ldapssl30';
      }
   } else {
      if ($Config::Config{'osname'} eq 'MSWin32')
      {
         $ldap_lib = 'nsldap32v11';
      } elsif ($Config::Config{'osname'} eq 'aix')
      {
         $ldap_lib = 'ldap10_shr';
      } else {
         $ldap_lib = 'ldap10';
      }
   }
}

if ($version eq "OPENLDAP")
{
    if ($^O eq "MSWin32")
    {
	$ldap_libs = 'ldap.lib lber.lib';
    }
    else
    {
	$ldap_libs = '-lldap -llber';
    }
}

sub MY::postamble
{
    "
constant.h:     constant.gen
	$pl_path constant.gen >constant.h 
";
}

WriteMakefile(
	'NAME'          =>      'Net::LDAPapi',
	'VERSION_FROM'  =>      'LDAPapi.pm',
	($include_ldap ne "/usr/include" ? (
	'INC'           =>      "-I$include_ldap -I$lib_ldap/../../local/include",
	) : (
	'INC'		=>	"",
	)),
	($version eq "NETSCAPE" ? (
	'LIBS'          =>      ["-L$lib_ldap -l$ldap_lib"],
	'DEFINE'        =>      '-DNETSCAPE_LDAP',
	) : $version eq "ISODE" ? (
	'LIBS'          =>      ["-L$lib_ldap -lldap -llber -lisode"],
	'DEFINE'        =>      '-DISODE_LDAP',
	) : $version eq "OPENLDAP" ? (
	'LIBS'          =>      ["-L$lib_ldap -L$lib_ldap/../../local/lib $ldap_libs"],
	'DEFINE'        =>      '-DOPENLDAP',
	) : (
	'LIBS'          =>      ["-L$lib_ldap -lldap -llber $kerblibs"],
	'DEFINE'        =>      '-Dbool=char -DHAS_BOOL',
	)),
	'depend'        =>      { 'LDAPapi.c' => 'constant.h' },
	'clean'         =>      { 'FILES'     => 'constant.h' },
);
