use ExtUtils::MakeMaker;
use Config;

print "\n\nNet::LDAPapi Perl5 Module - by Clayton Donley <donley\@cig.mcel.mot.com>\n\n";
print "OpenLDAP support by Symas Corporation -- http://www.symas.com\n";
print "Updated by Quanah Gibson-Mount to match modern products and vendors.\n";

$pl_path = $Config{'perlpath'};

unless ($sdk)
{
   print "\nSelect your Development Kit:\n";
   print "  1.  OpenLDAP (default)\n";
   print "  2.  Mozilla\n";
   print "Choose: ";
   $sdk = <>;
}

$version = ($sdk == 2 ? 'MOZILLA' :
	    'OPENLDAP');

if ($include_ldap eq "")
{
   print "Location of $lname Include Files (default: /usr/include):  ";
   chomp($include_ldap = <>);
   $include_ldap = "/usr/include" unless $include_ldap =~ /\S/;
}

if ($lib_ldap eq "")
{
   $df_lib = ($include_ldap =~ m%^(\S+)/include% ? "$1/lib" : "/usr/lib");
   print "Location of $lname Library Files (default: $df_lib):  ";
   chomp($lib_ldap = <>);
   $lib_ldap = $df_lib unless $lib_ldap =~ /\S/;
}

if ($version eq "MOZILLA")
{
      if ($Config::Config{'osname'} eq 'MSWin32')
      {
         $ldap_lib = 'nsldapssl32v30';
      } else {
         $ldap_lib = 'ldapssl30';
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
	($version eq "MOZILLA" ? (
	'LIBS'          =>      ["-L$lib_ldap -l$ldap_lib"],
	'DEFINE'        =>      '-DMOZILLA_LDAP',
	) : $version eq "OPENLDAP" ? (
	'LIBS'          =>      ["-L$lib_ldap -L$lib_ldap/../../local/lib $ldap_libs"],
	'DEFINE'        =>      '-DOPENLDAP',
	)),
	'depend'        =>      { 'LDAPapi.c' => 'constant.h' },
	'clean'         =>      { 'FILES'     => 'constant.h' },
);
