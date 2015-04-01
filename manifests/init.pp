class pam_policies {
  case $::operatingsystem {
    'RedHat', 'CentOS': { 
      if $::operatingsystemmajrelease > 5 {
	params { 'system-auth': } 
	params { 'password-auth': } 
      } else {
	params { 'system-auth': } 
      }
    }
    default: {
      notice("$operatingsystem is  not currently supported for pam_policies management")
    }
  }
}
