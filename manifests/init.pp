class pam_policies {
##   if $::osfamily == 'CentOS' and $::operatingsystemmajrelease == 6 {
       include 'pam_policies::rh6' 
##   }
}
