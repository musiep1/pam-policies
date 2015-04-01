class pam_policies {
  case $operatingsystem {
    'RedHat', 'CentOS' { 
      if $::operatingsystemmajrelease == 6 {
        include rh6
      }
    }
  }
}
