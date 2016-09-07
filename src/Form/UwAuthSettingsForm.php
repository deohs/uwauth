<?php

namespace Drupal\uwauth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configure UwAuth settings for this site.
 */
class UwAuthSettingsForm extends ConfigFormBase {
  const SETTINGS_NAME = 'uwauth.settings';
  const SYNC_AD = 'ad';
  const SYNC_GROUPS = 'gws';
  const SYNC_LOCAL = 'local';
  const SYNC_NONE = 'none';

  /**
   * The config.typed service.
   *
   * @var \Drupal\Core\Config\Schema\TypedConfigInterface
   */
  protected $configTyped;

  /**
   * The module settings.
   *
   * @var \Drupal\Core\Config\Config
   */
  protected $settings;

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $configFactory, TypedConfigManagerInterface $configTyped) {
    parent::__construct($configFactory);
    $this->configTyped = $configTyped;
    $this->settings = $this->config(static::SETTINGS_NAME);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('config.factory'),
      $container->get('config.typed')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'uwauth_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      static::SETTINGS_NAME,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form = $this->buildUwSettings($form, $form_state);
    $form = $this->buildLocalSettings($form, $form_state);
    $form = $this->buildMailSettings($form, $form_state);
    return parent::buildForm($form, $form_state);
  }

  /**
   * Build the mail-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildMailSettings(array $form, FormStateInterface $form_state) {
    $schema = $this->configTyped->getDefinition(static::SETTINGS_NAME)['mapping']['mail'];
    return $form;
  }

  /**
   * Build the Drupal-local-groups-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildLocalSettings(array $form, FormStateInterface $form_state) {
    $groupSource = $this->settings->get('group.source');
    $form['uwauth_local'] = array(
      '#type' => 'details',
      '#title' => t('Local Drupal groups'),
      '#open' => $groupSource === static::SYNC_LOCAL,
    );

    $excludedRoutes = $this->settings->get('auth.excluded_routes');
    $excludedRoutes = implode("\n", $excludedRoutes);
    $form['uwauth_local']['excluded_routes'] = [
      '#cols' => 20,
      '#default_value' => $excludedRoutes,
      '#description' => t('List the routes not using SSO, one per line.'),
      '#title' => $this->t('Excluded routes'),
      '#type' => 'textarea',
    ];
    return $form;
  }

  /**
   * Build the UW-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildUwSettings(array $form, FormStateInterface $form_state) {
    $form['uwauth_general'] = array(
      '#type' => 'details',
      '#title' => t('General'),
      '#open' => TRUE,
    );

    $groupSource = $this->settings->get('group.source');
    $form['uwauth_general']['source'] = array(
      '#type' => 'select',
      '#title' => t('Group Source'),
      '#description' => t('Choose your group membership source, or none to disable.'),
      '#options' => array(
        static::SYNC_GROUPS => t('Groups Web Service'),
        static::SYNC_AD => t('Active Directory'),
        static::SYNC_LOCAL => t('Local Drupal groups'),
        static::SYNC_NONE => t("None, don't login"),
      ),
      '#default_value' => $groupSource,
    );

    $form['uwauth_general']['name_id'] = [
      '#default_value' => $this->settings->get('auth.name_id'),
      '#description' => t('The property used as Shibboleth NameID, to be used as Drupal username.'),
      '#title' => $this->t('NameID name'),
      '#type' => 'textfield',
    ];
    $allowedAttributes = $this->settings->get('auth.allowed_attributes');
    $allowedAttributes = implode("\n", $allowedAttributes);
    $form['uwauth_general']['allowed_attributes'] = [
      '#cols' => 20,
      '#default_value' => $allowedAttributes,
      '#description' => t('List the allowed attributes, one per line'),
      '#title' => $this->t('Allowed attributes'),
      '#type' => 'textarea',
    ];
    $form['uwauth_general']['sp_endpoint'] = [
      '#default_value' => $this->settings->get('auth.sp_endpoint'),
      '#description' => t('The path used by the Shibboleth SP endpoint, usually /Shibboleth.sso.'),
      '#title' => $this->t('Shibboleth SP endpoint'),
      '#type' => 'textfield',
    ];

    $form['uwauth_gws'] = array(
      '#type' => 'details',
      '#title' => t('Groups Web Service'),
      '#description' => t('If using GWS as your group source, please provide the paths to your UW certificates. For security purposes, the certificates should be stored outside of your website root.'),
      '#open' => $groupSource === static::SYNC_GROUPS,
    );

    $form['uwauth_gws']['cert'] = array(
      '#type' => 'textfield',
      '#title' => t('Certificate Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_cert.pem'),
      '#default_value' => $this->settings->get('gws.cert'),
    );

    $form['uwauth_gws']['key'] = array(
      '#type' => 'textfield',
      '#title' => t('Private Key Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_key.pem'),
      '#default_value' => $this->settings->get('gws.key'),
    );

    $form['uwauth_gws']['cacert'] = array(
      '#type' => 'textfield',
      '#title' => t('CA Certificate Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_ca.pem'),
      '#default_value' => $this->settings->get('gws.cacert'),
    );

    $form['uwauth_ad'] = array(
      '#type' => 'details',
      '#title' => t('Active Directory'),
      '#description' => t('If using AD as your group source, please provide the LDAP URI and Base DN for your domain. For anonymous lookups, leave the Bind DN and Bind Password fields blank.'),
      '#open' => $groupSource === static::SYNC_AD,
    );

    $form['uwauth_ad']['uri'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP URI'),
      '#description' => t('Example: ldap://domaincontroller.example.org'),
      '#default_value' => $this->settings->get('ad.uri'),
    );

    $form['uwauth_ad']['basedn'] = array(
      '#type' => 'textfield',
      '#title' => t('Base DN'),
      '#description' => t('Example: DC=example,DC=org'),
      '#default_value' => $this->settings->get('ad.basedn'),
    );

    $form['uwauth_ad']['binddn'] = array(
      '#type' => 'textfield',
      '#title' => t('Bind DN'),
      '#description' => t('Example: CN=drupal,CN=Users,DC=example,DC=org'),
      '#default_value' => $this->settings->get('ad.binddn'),
    );

    $form['uwauth_ad']['bindpass'] = array(
      '#type' => 'password',
      '#title' => t('Bind Password'),
      '#description' => t('NOTE: If a bind password has been set, leave this field blank to leave it unchanged.'),
    );

    $form['uwauth_map'] = array(
      '#type' => 'details',
      '#title' => t('Group to Role Mapping'),
      '#description' => t('For group source portability, groups are mapped to roles. Each group can be mapped to a single role.'),
      '#open' => in_array($groupSource, [static::SYNC_AD, static::SYNC_GROUPS]),
    );

    $form['uwauth_map']['map'] = array(
      '#type' => 'textarea',
      '#title' => t('Group Map'),
      '#description' => t('Note: Each row corresponds to a single group to role mapping. The format is group|role. All roles should be entered as their machine name.'),
      '#default_value' => $this->settings->get('group.map'),
      '#rows' => 15,
    );

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $baseDn = $form_state->getValue('basedn');
    $bindDn = $form_state->getValue('binddn');
    $caCert = $form_state->getValue('cacert');
    $cert = $form_state->getValue('cert');
    $key = $form_state->getValue('key');
    $map = $form_state->getValue('map');
    $source = $form_state->getValue('source');
    $uri = $form_state->getValue('uri');

    if (($source == static::SYNC_AD) && ((strlen($uri) == 0) || (strlen($baseDn) == 0))) {
      $form_state->setErrorByName('source', t('Active Directory requires both the URI and Base DN to be configured.'));
    }

    if (($source == static::SYNC_GROUPS) && ((strlen($cert) == 0) || (strlen($key) == 0) || (strlen($caCert) == 0))) {
      $form_state->setErrorByName('source', t('Groups Web Service requires the Certificate, Key, and CA Certificate to be configured.'));
    }

    if ((strlen($cert) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $cert)) {
      $form_state->setErrorByName('cert', t('The Certificate path contains invalid characters.'));
    }
    elseif ((strlen($cert) > 0) && !is_readable($cert)) {
      $form_state->setErrorByName('cert', t('The Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($key) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $key)) {
      $form_state->setErrorByName('key', t('The Key path contains invalid characters.'));
    }
    elseif ((strlen($key) > 0) && !is_readable($key)) {
      $form_state->setErrorByName('key', t('The Key file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($caCert) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $caCert)) {
      $form_state->setErrorByName('cacert', t('The CA Certificate path contains invalid characters.'));
    }
    elseif ((strlen($caCert) > 0) && !is_readable($caCert)) {
      $form_state->setErrorByName('cacert', t('The CA Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($uri) > 0) && (preg_match("/^(ldap:\/\/|ldaps:\/\/)[a-z0-9_\.\-]*[a-z0-9]$/i", $uri) === 0)) {
      $form_state->setErrorByName('uri', t('The LDAP URI contains invalid characters or formatting.'));
    }

    if ((strlen($baseDn) > 0) && (preg_match("/^(OU=|DC=)[a-z0-9_\-=, ]*[a-z0-9]$/i", $baseDn) === 0)) {
      $form_state->setErrorByName('basedn', t('The Base DN contains invalid characters or formatting.'));
    }

    if ((strlen($bindDn) > 0) && (preg_match("/^CN=[a-z0-9_\-=, ]*[a-z0-9]$/i", $bindDn) === 0)) {
      $form_state->setErrorByName('binddn', t('The Bind DN contains invalid characters or formatting.'));
    }

    if ((strlen($map) > 0) && preg_match_all("/^([^a-z0-9_\-]*\|[a-z0-9_\-]*|[a-z0-9_\-]*\|[^a-z0-9_\-]*)$/mi", $map)) {
      $form_state->setErrorByName('map', t('The Group Map contains invalid characters or formatting.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $allowedAttributes = $form_state->getValue('allowed_attributes');
    $allowedAttributes = explode("\n", "$allowedAttributes\n");
    $allowedAttributes = array_filter(array_map('trim', $allowedAttributes));

    $excludedRoutes = $form_state->getValue('excluded_routes');
    $excludedRoutes = explode("\n", "$excludedRoutes\n");
    $excludedRoutes = array_filter(array_map('trim', $excludedRoutes));

    $this->settings
      ->set('auth.allowed_attributes', $allowedAttributes)
      ->set('auth.excluded_routes', $excludedRoutes)
      ->set('auth.name_id', $form_state->getValue('name_id'))
      ->set('auth.sp_endpoint', $form_state->getValue('sp_endpoint'))
      ->set('gws.cert', $form_state->getValue('cert'))
      ->set('gws.key', $form_state->getValue('key'))
      ->set('gws.cacert', $form_state->getValue('cacert'))
      ->set('ad.uri', $form_state->getValue('uri'))
      ->set('ad.basedn', $form_state->getValue('basedn'))
      ->set('ad.binddn', $form_state->getValue('binddn'));
    if (($this->settings->get('ad.bindpass') === NULL) || (strlen($form_state->getValue('bindpass')) > 0)) {
      $this->settings->set('ad.bindpass', $form_state->getValue('bindpass'));
    }
    $this->settings->set('group.map', $form_state->getValue('map'))
      ->set('group.source', $form_state->getValue('source'));

    $this->settings->save();

    parent::submitForm($form, $form_state);
  }

}
