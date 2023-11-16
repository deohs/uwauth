<?php

namespace Drupal\uwauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\uwauth\Form\UwAuthSettingsForm;

/**
 * Class LogoutController contains the overridden controller for user.logout.
 */
class LogoutController extends ControllerBase {

  /**
   * The overridden controller for user.logout.
   *
   * Do not set the refresh delay to 0 to avoid having an immediate redirect
   * without page display.
   *
   * @see https://www.w3.org/TR/WCAG20-TECHS/H76.html
   *
   * @return array
   *   A render array.
   */
  public function logout(): array {
    $title = $this->t('Logout');
    $frontUrl = Url::fromRoute('<front>', [], ['absolute' => TRUE]);
    $frontString = $frontUrl->toString();
    $spEndpoint = $this->config(UwAuthSettingsForm::SETTINGS_NAME)->get('auth.sp_endpoint');
    $spLogoutUrl = Url::fromUri($frontUrl->toString() . ltrim("$spEndpoint/Logout", '/'));
    $spLogoutString = $spLogoutUrl->toString();

    $message = $this->t('Logging out of application and Shibboleth IdP');

    $ret['#attached']['html_head'][] = [
      [
        // Redirect through a 'Refresh' meta tag.
        '#tag' => 'meta',
        '#noscript' => FALSE,
        '#attributes' => [
          'http-equiv' => 'Refresh',
          'content' => '1; URL=' . $frontString,
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
