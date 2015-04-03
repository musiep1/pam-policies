class pam_policies::common_files_rh7 {
### linux common user login related files permisions
  file {
    "/etc/passwd":
	owner => root,
	group => root,
	mode  => 644;
    "/etc/group":
	owner => root,
	group => root,
	mode  => 644;
    "/etc/shadow":
	owner => root,
	group => root,
	mode  => 000;
    "/etc/gshadow":
	owner => root,
	group => root,
	mode  => 000;
    "/etc/login.defs":
	owner => root,
	group => root,
	mode  => 644;
  }

### linux common login.defs settings
  augeas { "login.defs_passwd_policies":
	context => "/files/etc/login.defs",
	lens    => "login_defs.lns",
	incl    => "/etc/login.defs",
	changes => [
		"set PASS_MAX_DAYS 90",
		"set PASS_MIN_DAYS 7",
		"set PASS_MIN_LEN 8",
		"set PASS_WARN_AGE 14",
		"set ENCRYPT_METHOD SHA512",
	],
  }

### password quality parameters for rh 7 and above
  file { "/etc/security/pwquality.conf":
    ensure => "present",
    owner => root,
    group => root,
    mode  => 644,
    source => "puppet:///modules/pam_policies/pwquality.conf",
  }

} # end class pam_policies::common_files_rh7
