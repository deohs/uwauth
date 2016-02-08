<?php

/**
 * @file
 * Contains \Drupal\uwauth\Controller\UwAuthLogoutController.
 */

namespace Drupal\uwauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\TrustedRedirectResponse;

class UwAuthLogoutController extends ControllerBase {
  public function logout() {
    user_logout();
    return new TrustedRedirectResponse('https://weblogin.washington.edu/');
  }
}
?>
