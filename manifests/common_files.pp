class pam_policies::common_files {
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
  augeas {
	"login.defs_passwd_policies":
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

### password quality parameters for OS 7 and above
  case $::operatingsystem {
    'RedHat', 'CentOS': {
      if $::operatingsystemmajrelease > 6 {

        file { "/etc/security/pwquality.conf":
          owner => root,
          group => root,
          mode  => 644,
        }

        augeas { "pwquality_conf_OS7":
          context => "/files/etc/security/pwquality.conf",
          changes => [
			      "set minlen 8",
			      "set dcredit -1",
			      "set ucredit -1",
			      "set lcredit -1",
			      "set ocredit -1",
			      "set difok 1",
			      "set maxrepeat 2",
		      ],
	      }
      } # end if OS major release 

    } # end RedHat,CentOS case
    default:  {
      notice("${::operatingsystem} is currently not supported for OS7 pwquality.conf management")
    }

  } # END case operating system

} # end define pam_policies:common_files
