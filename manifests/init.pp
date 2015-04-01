class pam_policies {

  case $::operatingsystem {
    'RedHat', 'CentOS': { 
      if $::operatingsystemmajrelease > 5 {
        common_params { 'system-auth': } 
        common_params { 'password-auth': } 
      } else {
        common_params { 'system-auth': } 
      }
    }

    default: {
      notice("${::operatingsystem} is  not currently supported for pam_policies management.")
    }
  }

  include common_files 
}
