<?php

namespace Drupal\uwauth\Hook;

use Drupal\Core\Hook\Attribute\Hook;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;

/**
 * Hook implementations used to provide help.
 */
final class HelpHooks {

  use StringTranslationTrait;

  /**
   * Implements hook_help().
   */
  #[Hook('help')]
  public function help(string $route_name, RouteMatchInterface $route_match): ?string {
    switch ($route_name) {
      case 'help.page.uwauth':
        $output = '<h3>' . $this->t('About') . '</h3>';
        $output .= '<p>' . $this->t('UW Auth implements user authentication and automatic role assigment. Authentication is provided by Shibboleth, with role assignment utilizing UW Groups or Active Directory.') . '</p>';
        $output .= '<h3>' . $this->t('General Settings') . '</h3>';
        $output .= '<p>' . $this->t('From here you can specify what your group membership source is. By default, this will be set to None, which effectively disables the module. To minimize issues, select your group membership source after you have created your roles, mapped them, and configured the group source.') . '</p>';
        $output .= '<p>' . $this->t('At any time if you wish to disable the module, you can do so by setting the source to None. This change will disable it, without erasing the module configuration.') . '</p>';
        $output .= '<h3>' . $this->t('Groups Web Service') . '</h3>';
        $output .= '<p>' . $this->t('GWS offers a centralized system for managing user groups at UW. In order to utilize it, you will need a certificate issued by UW CA to authenticate your application with the web service.') . '</p>';
        $output .= '<h3>' . $this->t('Active Directory') . '</h3>';
        $output .= '<p>' . $this->t('With AD, you can utilize either NETID or a departmental AD infrastructure. Both authenticated, and anonymous binds are supported. It is recommended that you use LDAPS whenever possible, and it is required when using NETID. You may need to configure OpenLDAP to load the required CA certificates, if using LDAPS.') . '</p>';
        $output .= '<h3>' . $this->t('Group to Role Mapping') . '</h3>';
        $output .= '<p>' . $this->t('For portability purposes, externally managed groups are mapped to Drupal roles. This mapping function allows for changes in group names, and sources without having to change permissions within Drupal.') . '</p>';
        $output .= '<p>' . $this->t('Each row within the text box represents a group to role map entry. A group can only be mapped to a single role, as the group name is used as an internal identifier. Groups cannot be mapped to builtin Drupal roles. So, if you want to give a group, admin privileges, you will need to create a role with those privileges.') . '</p>';
        $output .= '<h3>' . $this->t('History') . '</h3>';
        $output .= '<p>' . $this->t('Developed by John Yocum for UW DEOHS. Source code history, releases, etc. available from') . ' <a href=https://github.com/deohs/uwauth>https://github.com/deohs/uwauth</a>.</p>';
        return $output;
    }
    return NULL;
  }

}
