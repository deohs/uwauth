<?php

namespace Drupal\uwauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;

/**
 * Class LogoutController contains the overridden controller for user.logout.
 */
class LogoutController extends ControllerBase {

  /**
   * The overridden controller for user.logout.
   *
   * @return array
   *   A render array.
   */
  public function logout() {
    $title = $this->t('Logout');
    $frontUrl = Url::fromRoute('<front>', [], ['absolute' => TRUE]);
    $frontString = $frontUrl->toString();
    $spLogoutUrl = Url::fromUri($frontUrl->toString() . 'Shibboleth.sso/Logout');
    $spLogoutString = $spLogoutUrl->toString();

    $message = $this->t('Logging out of OCEA and Shibboleth IdP');

    $ret['#attached']['html_head'][] = [
      [
        // Redirect through a 'Refresh' meta tag.
        '#tag' => 'meta',
        '#noscript' => FALSE,
        '#attributes' => [
          'http-equiv' => 'Refresh',
          'content' => '0; URL=' . $frontString,
        ],
      ],
      'shibboleth-logout-redirect',
    ];

    $ret['title'] = [
      '#markup' => "<h1>$title</h1>",
    ];
    $ret['message'] = [
      '#markup' => "<p>$message</p>",
    ];
    $ret['main'] = [
      '#type' => 'html_tag',
      '#tag' => 'iframe',
      '#attributes' => [
        'src' => $spLogoutString,
        'style' => 'visibility: hidden',
      ],
    ];
    user_logout();
    return $ret;
  }

}
