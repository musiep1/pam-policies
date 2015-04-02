class pam_policies {
  case $::operatingsystem {

    'RedHat', 'CentOS': { 
      if $::operatingsystemmajrelease == 5 {
        common_params { 'system-auth': } 
        include common_files 
      }
      elsif $::operatingsystemmajrelease == 6 {
        common_params { 'system-auth': } 
        common_params { 'password-auth': } 
        include common_files 
      }
      elsif $::operatingsystemmajrelease > 6 {
        common_params_rh7 { 'system-auth': } 
        common_params_rh7 { 'password-auth': } 
        include common_files_rh7

      } else {
        notice("MajorRelease ${::operatingsystemmajrelease} is not currently supported for pam_policies mgmt.")
      }
    }

    default: {
      notice("${::operatingsystem} is not currently supported for pam_policies mgmt.")
    }
  }

}
