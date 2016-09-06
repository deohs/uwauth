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
    ksm($this->settings, $schema);
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
        'gws' => t('Groups Web Service'),
        'ad' => t('Active Directory'),
        'login' => t('None, but login'),
        'none' => t("None, don't login"),
      ),
      '#default_value' => $groupSource,
    );

    $form['uwauth_general']['name_id'] = [
      '#default_value' => $this->settings->get('auth.name_id'),
      '#description' => t('The property used as Shibboleth NameID, to be used as Drupal username.'),
      '#title' => $this->t('NameID name'),
      '#type' => 'textfield',
    ];
    $form['uwauth_general']['allowed_attributes'] = [
      '#cols' => 20,
      '#default_value' => $this->settings->get('auth.allowed_attributes'),
      '#description' => t('List the allowed attributes, one per line'),
      '#title' => $this->t('Allowed attributes'),
      '#type' => 'textarea',
    ];

    $form['uwauth_gws'] = array(
      '#type' => 'details',
      '#title' => t('Groups Web Service'),
      '#description' => t('If using GWS as your group source, please provide the paths to your UW certificates. For security purposes, the certificates should be stored outside of your website root.'),
      '#open' => $groupSource === 'gws',
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
      '#open' => $groupSource === 'ad',
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
      '#open' => in_array($groupSource, ['ad', 'gws']),
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

    if (($form_state->getValue('source') == "ad") && ((strlen($form_state->getValue('uri')) == 0) || (strlen($form_state->getValue('basedn')) == 0))) {
      $form_state->setErrorByName('source', t('Active Directory requires both the URI and Base DN to be configured.'));
    }

    if (($form_state->getValue('source') == "gws") && ((strlen($form_state->getValue('cert')) == 0) || (strlen($form_state->getValue('key')) == 0) || (strlen($form_state->getValue('cacert')) == 0))) {
      $form_state->setErrorByName('source', t('Groups Web Service requires the Certificate, Key, and CA Certificate to be configured.'));
    }

    if ((strlen($form_state->getValue('cert')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('cert'))) {
      $form_state->setErrorByName('cert', t('The Certificate path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('cert')) > 0) && !is_readable($form_state->getValue('cert'))) {
      $form_state->setErrorByName('cert', t('The Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('key')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('key'))) {
      $form_state->setErrorByName('key', t('The Key path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('key')) > 0) && !is_readable($form_state->getValue('key'))) {
      $form_state->setErrorByName('key', t('The Key file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('cacert')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('cacert'))) {
      $form_state->setErrorByName('cacert', t('The CA Certificate path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('cacert')) > 0) && !is_readable($form_state->getValue('cacert'))) {
      $form_state->setErrorByName('cacert', t('The CA Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('uri')) > 0) && (preg_match("/^(ldap:\/\/|ldaps:\/\/)[a-z0-9_\.\-]*[a-z0-9]$/i", $form_state->getValue('uri')) === 0)) {
      $form_state->setErrorByName('uri', t('The LDAP URI contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('basedn')) > 0) && (preg_match("/^(OU=|DC=)[a-z0-9_\-=, ]*[a-z0-9]$/i", $form_state->getValue('basedn')) === 0)) {
      $form_state->setErrorByName('basedn', t('The Base DN contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('binddn')) > 0) && (preg_match("/^CN=[a-z0-9_\-=, ]*[a-z0-9]$/i", $form_state->getValue('binddn')) === 0)) {
      $form_state->setErrorByName('binddn', t('The Bind DN contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('map')) > 0) && preg_match_all("/^([^a-z0-9_\-]*\|[a-z0-9_\-]*|[a-z0-9_\-]*\|[^a-z0-9_\-]*)$/mi", $form_state->getValue('map'))) {
      $form_state->setErrorByName('map', t('The Group Map contains invalid characters or formatting.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->settings
      ->set('auth.name_id', $form_state->getValue('name_id'))
      ->set('auth.allowed_attributes', $form_state->getValue('allowed_attributes'))
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