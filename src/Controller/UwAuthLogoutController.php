<?php

namespace Drupal\uwauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;

/**
 * Class UwAuthLogoutController contains the controller for SSO logout.
 */
class UwAuthLogoutController extends ControllerBase {

  /**
   * Log user out of Drupal, and redirect to web login.
   *
   * @todo user_logout will be deprecated in 11.0.
   */
  public function logout(): TrustedRedirectResponse {
    user_logout();
    return new TrustedRedirectResponse('https://weblogin.washington.edu/');
  }

}
