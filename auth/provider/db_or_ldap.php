<?php

namespace rokx\dborldap\auth\provider;

use phpbb\captcha\factory;
use phpbb\captcha\plugins\captcha_abstract;
use phpbb\config\config;
use phpbb\db\driver\driver_interface;
use phpbb\passwords\manager;
use phpbb\request\request_interface;
use phpbb\user;
use phpbb\auth\provider\base;
use phpbb\language\language;


/**
 * Database authentication provider for phpBB3
 *
 * This is for authentication via the integrated user table
 */
class db_or_ldap extends base
{
        /** @var factory CAPTCHA factory */
	protected $captcha_factory;

	/** @var config phpBB config */
	protected $config;

	/** @var driver_interface DBAL driver instance */
	protected $db;

	/** @var request_interface Request object */
	protected $request;

	/** @var user User object */
	protected $user;

	/** @var string phpBB root path */
	protected $phpbb_root_path;

	/** @var string PHP file extension */
	protected $php_ext;

	/**
	* phpBB passwords manager
	*
	* @var manager
	*/
	protected $passwords_manager;

	/** @var language phpBB language class */
	protected $language;

	/**
	 * Database Authentication Constructor
	 *
	 * @param factory $captcha_factory
	 * @param	config 		$config
	 * @param	driver_interface		$db
	 * @param	manager	$passwords_manager
	 * @param	request_interface		$request
	 * @param	user			$user
	 * @param	string				$phpbb_root_path
	 * @param	string				$php_ext
	 * @param	language			$language	Language object
        */
	public function __construct(factory $captcha_factory, config $config, driver_interface $db, manager $passwords_manager, request_interface $request, user $user, $phpbb_root_path, $php_ext, language $language)
	{
		$this->captcha_factory = $captcha_factory;
		$this->config = $config;
		$this->db = $db;
		$this->passwords_manager = $passwords_manager;
		$this->request = $request;
		$this->user = $user;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;
                $this->language = $language;
	}

        /**
	 * {@inheritdoc}
	 */
	public function init()
	{
		if (!@extension_loaded('ldap'))
		{
			return $this->language->lang('LDAP_NO_LDAP_EXTENSION');
		}

		$this->config['ldap_port'] = (int) $this->config['ldap_port'];
		if ($this->config['ldap_port'])
		{
			$ldap = @ldap_connect($this->config['ldap_server'], $this->config['ldap_port']);
		}
		else
		{
			$ldap = @ldap_connect($this->config['ldap_server']);
		}

		if (!$ldap)
		{
			return $this->language->lang('LDAP_NO_SERVER_CONNECTION');
		}

		@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
		@ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

		if ($this->config['ldap_user'] || $this->config['ldap_password'])
		{
			if (!@ldap_bind($ldap, htmlspecialchars_decode($this->config['ldap_user'], ENT_COMPAT), htmlspecialchars_decode($this->config['ldap_password'], ENT_COMPAT)))
			{
				return $this->language->lang('LDAP_INCORRECT_USER_PASSWORD');
			}
		}

		// ldap_connect only checks whether the specified server is valid, so the connection might still fail
		$search = @ldap_search(
			$ldap,
			htmlspecialchars_decode($this->config['ldap_base_dn'], ENT_COMPAT),
			$this->ldap_user_filter($this->user->data['username']),
			(empty($this->config['ldap_email'])) ?
				array(htmlspecialchars_decode($this->config['ldap_uid'], ENT_COMPAT)) :
				array(htmlspecialchars_decode($this->config['ldap_uid'], ENT_COMPAT), htmlspecialchars_decode($this->config['ldap_email'], ENT_COMPAT)),
			0,
			1
		);

		if ($search === false)
		{
			return $this->language->lang('LDAP_SEARCH_FAILED');
		}

		$result = @ldap_get_entries($ldap, $search);

		@ldap_close($ldap);

		if (!is_array($result) || count($result) < 2)
		{
			return $this->language->lang('LDAP_NO_IDENTITY', $this->user->data['username']);
		}

		if (!empty($this->config['ldap_email']) && !isset($result[0][htmlspecialchars_decode($this->config['ldap_email'])]))
		{
			return $this->language->lang('LDAP_NO_EMAIL');
		}

		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function login($username, $password)
	{
		// Auth plugins get the password untrimmed.
		// For compatibility we trim() here.
		$password = trim($password);

		// do not allow empty password
		if (!$password)
		{
			return array(
				'status'	=> LOGIN_ERROR_PASSWORD,
				'error_msg'	=> 'NO_PASSWORD_SUPPLIED',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}

		if (!$username)
		{
			return array(
				'status'	=> LOGIN_ERROR_USERNAME,
				'error_msg'	=> 'LOGIN_ERROR_USERNAME',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}

		if (!@extension_loaded('ldap'))
		{
			return array(
				'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
				'error_msg'		=> 'LDAP_NO_LDAP_EXTENSION',
				'user_row'		=> array('user_id' => ANONYMOUS),
			);
		}

		$username_clean = utf8_clean_string($username);

		$sql = 'SELECT *
			FROM ' . USERS_TABLE . "
			WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if (($this->user->ip && !$this->config['ip_login_limit_use_forwarded']) ||
			($this->user->forwarded_for && $this->config['ip_login_limit_use_forwarded']))
		{
			$sql = 'SELECT COUNT(*) AS attempts
				FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE attempt_time > ' . (time() - (int) $this->config['ip_login_limit_time']);
			if ($this->config['ip_login_limit_use_forwarded'])
			{
				$sql .= " AND attempt_forwarded_for = '" . $this->db->sql_escape($this->user->forwarded_for) . "'";
			}
			else
			{
				$sql .= " AND attempt_ip = '" . $this->db->sql_escape($this->user->ip) . "' ";
			}

			$result = $this->db->sql_query($sql);
			$attempts = (int) $this->db->sql_fetchfield('attempts');
			$this->db->sql_freeresult($result);

			$attempt_data = array(
				'attempt_ip'			=> $this->user->ip,
				'attempt_browser'		=> trim(substr($this->user->browser, 0, 149)),
				'attempt_forwarded_for'	=> $this->user->forwarded_for,
				'attempt_time'			=> time(),
				'user_id'				=> ($row) ? (int) $row['user_id'] : 0,
				'username'				=> $username,
				'username_clean'		=> $username_clean,
			);
			$sql = 'INSERT INTO ' . LOGIN_ATTEMPT_TABLE . $this->db->sql_build_array('INSERT', $attempt_data);
			$this->db->sql_query($sql);
		}
		else
		{
			$attempts = 0;
		}

		$login_error_attempts = 'LOGIN_ERROR_ATTEMPTS';

		$user_login_attempts	= (is_array($row) && $this->config['max_login_attempts'] && $row['user_login_attempts'] >= $this->config['max_login_attempts']);
		$ip_login_attempts		= ($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max']);

		$show_captcha = $user_login_attempts || $ip_login_attempts;

		if ($show_captcha)
		{
			$captcha = $this->captcha_factory->get_instance($this->config['captcha_plugin']);

			// Get custom message for login error when exceeding maximum number of attempts
			if ($captcha instanceof captcha_abstract)
			{
				$login_error_attempts = $captcha->get_login_error_attempts();
			}
		}

		if (!$row)
		{
			if ($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max'])
			{
				return array(
					'status'		=> LOGIN_ERROR_ATTEMPTS,
					'error_msg'		=> $login_error_attempts,
					'user_row'		=> array('user_id' => ANONYMOUS),
				);
			}

			return array(
				'status'	=> LOGIN_ERROR_USERNAME,
				'error_msg'	=> 'LOGIN_ERROR_USERNAME',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}

		// If there are too many login attempts, we need to check for a confirm image
		// Every auth module is able to define what to do by itself...
		if ($show_captcha)
		{
			$captcha->init(CONFIRM_LOGIN);
			$vc_response = $captcha->validate($row);
			if ($vc_response)
			{
				return array(
					'status'		=> LOGIN_ERROR_ATTEMPTS,
					'error_msg'		=> $login_error_attempts,
					'user_row'		=> $row,
				);
			}
			else
			{
				$captcha->reset();
			}

		}

		// Check password ...
		if ($this->passwords_manager->check($password, $row['user_password'], $row))
		{
			// Check for old password hash...
			if ($this->passwords_manager->convert_flag || strlen($row['user_password']) == 32)
			{
				$hash = $this->passwords_manager->hash($password);

				// Update the password in the users table to the new format
				$sql = 'UPDATE ' . USERS_TABLE . "
					SET user_password = '" . $this->db->sql_escape($hash) . "'
					WHERE user_id = {$row['user_id']}";
				$this->db->sql_query($sql);

				$row['user_password'] = $hash;
			}

			$sql = 'DELETE FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE user_id = ' . this->db->sql_escape($row['user_id']);
			$this->db->sql_query($sql);

			if ($row['user_login_attempts'] != 0)
			{
				// Successful, reset login attempts (the user passed all stages)
				$sql = 'UPDATE ' . USERS_TABLE . '
					SET user_login_attempts = 0
					WHERE user_id = ' . this->db->sql_escape($row['user_id']);
				$this->db->sql_query($sql);
			}

			// User inactive...
			if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
			{
				return array(
					'status'		=> LOGIN_ERROR_ACTIVE,
					'error_msg'		=> 'ACTIVE_ERROR',
					'user_row'		=> $row,
				);
			}

			// Successful login... set user_login_attempts to zero...
			return array(
				'status'		=> LOGIN_SUCCESS,
				'error_msg'		=> false,
				'user_row'		=> $row,
			);
		}


//LDAP Part
		$this->config['ldap_port'] = (int) $this->config['ldap_port'];
		if ($this->config['ldap_port'])
		{
			$ldap = @ldap_connect($this->config['ldap_server'], $this->config['ldap_port']);
		}
		else
		{
			$ldap = @ldap_connect($this->config['ldap_server']);
		}

		if (!$ldap)
		{
			return array(
				'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
				'error_msg'		=> 'LDAP_NO_SERVER_CONNECTION',
				'user_row'		=> array('user_id' => ANONYMOUS),
			);
		}

		@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
		@ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

		if ($this->config['ldap_user'] || $this->config['ldap_password'])
		{
			if (!@ldap_bind($ldap, htmlspecialchars_decode($this->config['ldap_user'], ENT_COMPAT), htmlspecialchars_decode($this->config['ldap_password'], ENT_COMPAT)))
			{
				return array(
					'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
					'error_msg'		=> 'LDAP_NO_SERVER_CONNECTION',
					'user_row'		=> array('user_id' => ANONYMOUS),
				);
			}
		}

		$search = @ldap_search(
			$ldap,
			htmlspecialchars_decode($this->config['ldap_base_dn'], ENT_COMPAT),
			$this->ldap_user_filter($username),
			(empty($this->config['ldap_email'])) ?
				array(htmlspecialchars_decode($this->config['ldap_uid'], ENT_COMPAT)) :
				array(htmlspecialchars_decode($this->config['ldap_uid'], ENT_COMPAT), htmlspecialchars_decode($this->config['ldap_email'], ENT_COMPAT)),
			0,
			1
		);

		$ldap_result = @ldap_get_entries($ldap, $search);

		if (is_array($ldap_result) && count($ldap_result) > 1)
		{
			if (@ldap_bind($ldap, $ldap_result[0]['dn'], htmlspecialchars_decode($password, ENT_COMPAT)))
			{
				@ldap_close($ldap);

				$sql ='SELECT user_id, username, user_password, user_passchg, user_email, user_type
					FROM ' . USERS_TABLE . "
					WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($username)) . "'";
				$result = $this->db->sql_query($sql);
				$row = $this->db->sql_fetchrow($result);
				$this->db->sql_freeresult($result);

				if ($row)
				{
					unset($ldap_result);

					// User inactive...
					if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
					{
						return array(
							'status'		=> LOGIN_ERROR_ACTIVE,
							'error_msg'		=> 'ACTIVE_ERROR',
							'user_row'		=> $row,
						);
					}

					// Successful login... set user_login_attempts to zero...
					return array(
						'status'		=> LOGIN_SUCCESS,
						'error_msg'		=> false,
						'user_row'		=> $row,
					);
				}
				else
				{
					// retrieve default group id
					$sql = 'SELECT group_id
						FROM ' . GROUPS_TABLE . "
						WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
							AND group_type = " . GROUP_SPECIAL;
					$result = $this->db->sql_query($sql);
					$row = $this->db->sql_fetchrow($result);
					$this->db->sql_freeresult($result);

					if (!$row)
					{
						trigger_error('NO_GROUP');
					}

					// generate user account data
					$ldap_user_row = array(
						'username'		=> $username,
						'user_password'	=> '',
						'user_email'	=> (!empty($this->config['ldap_email'])) ? utf8_htmlspecialchars($ldap_result[0][htmlspecialchars_decode($this->config['ldap_email'], ENT_COMPAT)][0]) : '',
						'group_id'		=> (int) $row['group_id'],
						'user_type'		=> USER_NORMAL,
						'user_ip'		=> $this->user->ip,
						'user_new'		=> ($this->config['new_member_post_limit']) ? 1 : 0,
					);

					unset($ldap_result);

					// this is the user's first login so create an empty profile
					return array(
						'status'		=> LOGIN_SUCCESS_CREATE_PROFILE,
						'error_msg'		=> false,
						'user_row'		=> $ldap_user_row,
					);
				}
			}
			else
			{
				unset($ldap_result);
				@ldap_close($ldap);

				// Give status about wrong password...
				return array(
					'status'		=> LOGIN_ERROR_PASSWORD,
					'error_msg'		=> 'LOGIN_ERROR_PASSWORD',
					'user_row'		=> array('user_id' => ANONYMOUS),
				);
			}
		}

		@ldap_close($ldap);

		// Password incorrect - increase login attempts
		$sql = 'UPDATE ' . USERS_TABLE . '
			SET user_login_attempts = user_login_attempts + 1
			WHERE user_id = ' . (int) $row['user_id'] . '
				AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
		$this->db->sql_query($sql);

		// Give status about wrong password...
		return array(
			'status'		=> ($show_captcha) ? LOGIN_ERROR_ATTEMPTS : LOGIN_ERROR_PASSWORD,
			'error_msg'		=> 'LOGIN_ERROR_PASSWORD',
			'user_row'		=> $row,
		);
	
    }

/**
	 * {@inheritdoc}
	 */
	public function acp()
	{
		// These are fields required in the config table
		return array(
			'ldap_server', 'ldap_port', 'ldap_base_dn', 'ldap_uid', 'ldap_user_filter', 'ldap_email', 'ldap_user', 'ldap_password',
		);
	}

	/**
	 * Generates a filter string for ldap_search to find a user
	 *
	 * @param	$username	string	Username identifying the searched user
	 *
	 * @return				string	A filter string for ldap_search
	 */
	private function ldap_user_filter($username)
	{
		$filter = '(' . $this->config['ldap_uid'] . '=' . $this->ldap_escape(htmlspecialchars_decode($username, ENT_COMPAT)) . ')';
		if ($this->config['ldap_user_filter'])
		{
			$_filter = ($this->config['ldap_user_filter'][0] == '(' && substr($this->config['ldap_user_filter'], -1) == ')') ? $this->config['ldap_user_filter'] : "({$this->config['ldap_user_filter']})";
			$filter = "(&{$filter}{$_filter})";
		}
		return $filter;
	}

	/**
	 * Escapes an LDAP AttributeValue
	 *
	 * @param	string	$string	The string to be escaped
	 * @return	string	The escaped string
	 */
	private function ldap_escape($string)
	{
		return str_replace(array('*', '\\', '(', ')'), array('\\*', '\\\\', '\\(', '\\)'), $string);
	}

}
