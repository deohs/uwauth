NOTE: Module is still under active development, consider it Alpha quality. This
readme may not reflect the current state of the module. Nor, should you assume
that it will work at all.

This module enables Drupal 8 to authenticate users using Shibboleth, and assign
their roles based on group membership settings in Active Directory or in 
the UW Groups Web Service.

Whenever a Shibboleth session is detected, the user is logged in as that user.
Or, if the account doesn't exist, it'll be created automatically. There is no
filtering of what users should be created.

The module was designed and tested using Apache with mod_shib2. Shibboleth is
configured to expose the attribute "uwnetid" as the REMOTE_USER. 

For UW GWS, it assumes that your UW CA provided certificates are located in /etc/ssl:

CA Certificate /etc/ssl/drupal_uwca_ca.pem
Certificate /etc/ssl/drupal_uwca_cert.pem
Private Key /etc/ssl/drupal_uwca_key.pem

In order to enable the module, go to Manage > Extend > UW Authentication. Once
enabled there is no additional configuration required.

For role assignment, simply create roles with names that match UW groups. When
a user logs in, their role assignment will be updated automatically.
