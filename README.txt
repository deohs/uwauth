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

In order to enable the module, go to Manage > Extend > UW Auth. Once enabled,
go to Manage > Configuration > People > UW Auth to configure.

Finally, if no roles are mapped (or the user isn't assigned to any), they will
be given the role of authenticated user.
