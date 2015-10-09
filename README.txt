NOTE: Module is still under active development, consider it Alpha quality. This
readme may not reflect the current state of the module. Nor, should you assume
that it will work at all.

IMPORTANT: There is no support for federated logins. The module assumes all
users are using UW NetID's. This functionality may change in the future, if the
need arises for it.

This module enables Drupal 8 to authenticate users using Shibboleth, and assign
their roles based on group membership settings in Active Directory or in 
the UW Groups Web Service.

Whenever a Shibboleth session is detected, the user is logged in as that user.
Or, if the account doesn't exist, it'll be created automatically. There is no
filtering of what users should be created. User accounts will be given the
same user id, as their NetID. And, their email will be set to NETID@uw.edu.

The module was designed and tested using Apache with mod_shib2. Shibboleth is
configured to expose the attribute "uwnetid", which will be used as the
visitors username. 

In order to enable the module, go to Manage > Extend > UW Auth. Once enabled,
go to Manage > Configuration > People > UW Auth to configure.

Finally, if no roles are mapped (or the user isn't assigned to any), they will
be given the role of authenticated user.
