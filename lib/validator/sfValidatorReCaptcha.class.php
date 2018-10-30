<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * sfValidatorReCaptcha validates a ReCaptcha.
 *
 * This validator uses ReCaptcha: http://recaptcha.net/
 *
 * The ReCaptcha API documentation can be found at http://recaptcha.net/apidocs/captcha/
 *
 * To be able to use this validator, you need an API key: http://recaptcha.net/api/getkey
 *
 * To create a captcha validator:
 *
 *    $captcha = new sfValidatorReCaptcha(array('private_key' => RECAPTCHA_PRIVATE_KEY));
 *
 * where RECAPTCHA_PRIVATE_KEY is the ReCaptcha private key.
 *
 * @package    symfony
 * @subpackage validator
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: sfValidatorReCaptcha.class.php 7903 2008-03-15 13:17:41Z fabien $
 */
class sfValidatorReCaptcha extends sfValidatorBase
{
    /**
     * Configures the current validator.
     *
     * Available options:
     *
     *  * private_key:    The ReCaptcha private key (required)
     *  * remote_addr:    The remote address of the user
     *  * server_host:    The ReCaptcha server host
     *  * server_port:    The ReCaptcha server port
     *  * server_path:    The ReCatpcha server path
     *  * server_timeout: The timeout to use when contacting the ReCaptcha server
     *
     * Available error codes:
     *
     *  * captcha
     *  * server_problem
     *
     * @see sfValidatorBase
     */
    protected function configure($options = array(), $messages = array())
    {
        $this->addRequiredOption('private_key');

        $this->addOption('remote_addr');
        $this->addOption('server_host', 'www.google.com');
        $this->addOption('server_port', 443);
        $this->addOption('server_path', '/recaptcha/api/siteverify');
        $this->addOption('server_timeout', 10);

        $this->addMessage('captcha', 'The captcha is not valid (%error%).');
        $this->addMessage('server_problem', 'Unable to check the captcha from the server (%error%).');
    }

    /**
     * Cleans the input value.
     *
     * The input value must be an array with 2 required keys: recaptcha_challenge_field and recaptcha_response_field.
     *
     * It always returns null.
     *
     * @see sfValidatorBase
     */
    protected function doClean($value)
    {
        $response = isset($value['recaptcha_response_field']) ? $value['recaptcha_response_field'] : null;

        if (empty($response)) {
            throw new sfValidatorError($this, 'captcha', array('error' => 'invalid captcha'));
        }

        if (true !== ($answer = $this->check(array(
                'privatekey' => $this->getOption('private_key'),
                'remoteip' => $this->getOption('remote_addr') ? $this->getOption('remote_addr') : $_SERVER['REMOTE_ADDR'],
                'response' => $response,
            )))) {
            throw new sfValidatorError($this, 'captcha', array('error' => $answer));
        }

        return null;
    }

    /**
     * @param $parameters
     * @return mixed
     * @throws sfValidatorError
     */
    protected function check($parameters)
    {
        if (false === ($fs = @fsockopen($this->getOption('server_host'), $this->getOption('server_port'), $errno, $errstr, $this->getOption('server_timeout')))) {
            throw new sfValidatorError($this, 'server_problem', array('error' => $errstr));
        }

        $url = "https://www.google.com/recaptcha/api/siteverify";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, array(
            "secret" => $parameters['privatekey'], "response" => $parameters['response']));
        $response = curl_exec($ch);
        curl_close($ch);
        $data = json_decode($response);

        return $data->success;
    }
}
