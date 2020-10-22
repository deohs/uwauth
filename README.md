# UW Auth

This module enables Drupal 8 to authenticate users using Shibboleth, and assign
their roles based on information in other identity management systems.


## Operation

Whenever a Shibboleth session is detected, the user is logged in as that user.
Or, if the account doesn't exist, it'll be created automatically. There is no
filtering of what users should be created. User accounts will be given the
same user name, as their Shibboleth `NameID`.

The module was designed and tested using Apache with `mod_shib_24`. 


### Assumptions 

Shibboleth is assumed to be configured to expose:

* `name` or `REDIRECT-name` : the Shibboleth `NameID`, typically set in 
  `/etc/shibboleth/attribute-map.xml`.
* `mail` or `REDIRECT-mail` : optional ; an e-mail address in string form.


As per [https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeExtractor](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPAttributeExtractor) :
_The name property corresponds to [...] the Format XML attribute of a SAML <NameID>[...] element._ 
Such a mapping may look like this depending on your Shibboleth configuration:

    <Attribute id="name"
      name="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified" />
    
    
### Account creation and usage

* new accounts are created on the fly
  * if the `mail` value matches one of the allowed domains, that value is used 
    for the user account `mail` and `init` base fields
  * if that value exists, but does not belong to one of the allowed domains, the
    value is used, _and_ the account is marked as blocked
  * if the `mail` value is empty or missing, a pseudo-random address is 
    generated _and_ the account is marked as blocked
* for existing accounts:
  * if the `mail` value matches, the account is used as such
  * if the `mail` value does not match, the new value is used to update the
    user account, and the change is logged for reference. The `init` field is
    not updated.
* in all cases, if the user did not have an active Drupal session, the `login` 
  timestamp field on the user is updated.
  

## Installation

To install via Composer, add a repository to your composer.json then install as usual via Composer:

````
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/deohs/uwauth"
        }
    ],
    "require": {
        "drupal/uwauth": "~3.0"
    }
}
````


In addition to enabling the module, you need to modify the `.htaccess` at the
document root, or its equivalent in your vhost definition, to avoid having URLs
needed by the Shibboleth SP being rewritten.

Before:

    # Pass all requests not referring directly to files in the filesystem to
    # index.php.
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} !=/favicon.ico
    RewriteRule ^ index.php [L]

After:

    # Pass all requests not referring directly to files in the filesystem to
    # index.php.
    RewriteCond %{REQUEST_URI} !^/Shibboleth.sso
    RewriteCond %{REQUEST_URI} !^/secure
    RewriteCond %{REQUEST_URI} !^/shibboleth-sp
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} !=/favicon.ico
    RewriteRule ^ index.php [L]

Depending on the specifics of your SP configuration, you may want to tune these
rules. The `/Shibboleth.sso` Shibboleth SP endpoint is configurable in the 
module settings form at `/admin/config/people/uwauth`.


## Recommended Version

For stable operation, please download or pull a specific tag (release).
Otherwise you are likely to download the latest development code, which may
or may not work right.

For Drupal core versions 8.0.x < 8.8.3 use version v2.2.0 (8.x-2.2).

For Drupal core versions >= 8.8.3, including Drupal 9, use v.3.0.0 or later.



## Federation

There is no support for federated logins. The module assumes all users are using 
centralized identifiers from the group's Shibboleth IdP. 

This functionality may change in the future, if the need arises for it.
