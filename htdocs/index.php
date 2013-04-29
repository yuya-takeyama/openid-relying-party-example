<?php
require_once __DIR__.'/../vendor/autoload.php';
set_include_path(
    __DIR__ . '/../src' .
    PATH_SEPARATOR .
    get_include_path()
);
ini_set('display_errors', 'On');

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

$app = new Silex\Application;

$app['debug'] = true;
$app['root']  = __DIR__ . '/..';

$app['server.scheme'] = isset($_SERVER['HTTPS']) ? 'https' : 'http';
$app['server.host']   = $_SERVER['SERVER_NAME'];
$app['server.port']   = $_SERVER['SERVER_PORT'];
$app['server.host_plus_port'] = $app['server.host'] .
    ($app['server.scheme'] === 'http' ?
        ((int)$app['server.port'] !== 80 ? ":{$app['server.port']}" : '') :
        ((int)$app['server.port'] !== 443 ? ":{$app['server.port']}" : ''));
$app['server.root'] = "{$app['server.scheme']}://{$app['server.host_plus_port']}";

$app->register(new \Yuyat\OpenIdRelyingPartyExample\OpenIdServiceProvider);
$app->register(new \Silex\Provider\SessionServiceProvider);
$app->register(new \Silex\Provider\TwigServiceProvider, array(
    'twig.path' => __DIR__ . '/../views',
));

$app->before(function () use ($app) {
    $app['twig']->addGlobal('layout', $app['twig']->loadTemplate('layout.twig'));
    $app['twig']->addGlobal('session', $app['session']);

    require_once 'Auth/OpenID/SReg.php';
    require_once 'Auth/OpenID/PAPE.php';

    $app['twig']->addGlobal('pape_policy_uris', array(
        PAPE_AUTH_MULTI_FACTOR_PHYSICAL,
        PAPE_AUTH_MULTI_FACTOR,
        PAPE_AUTH_PHISHING_RESISTANT,
    ));
});

$app->post('/auth/openid/try', function (Request $req) use ($app) {
    $openId = $req->get('openid_identifier');

    if (is_null($openId)) {
        $app['session']->getFlashBag()->set('warning', 'Expected an OpenID URL.');

        return $app->redirect('/');
    }

    $consumer = $app['openid.consumer'];
    $authReq  = $consumer->begin($openId);

    if (!$authReq) {
        $app['session']->getFlashBag()->set('error', 'Authentication Error; not a valid OpenID.');

        return $app->redirect('/');
    }

    $sregReq = \Auth_OpenID_SRegRequest::build(
        array('nickname'),
        array('fullname', 'email')
    );

    if ($sregReq) {
        $authReq->addExtension($sregReq);
    }

    $trustRoot = $app['server.root'];
    $returnTo  = "{$app['server.root']}/auth/openid/finish";

    if ($authReq->shouldSendRedirect()) {
        $redirectUrl = $authReq->redirectURL($trustRoot, $returnTo);

        if (Auth_OpenID::isFailure($redirectUrl)) {
            $app['session']->getFlashBag()->set('error', 'Could not redirect to server: ' . $redirectUrl->message);

            return $app->redirect('/');
        } else {
            return $app->redirect($redirectUrl);
        }
    } else {
        $formHtml = $authReq->htmlMarkup(
            $trustRoot,
            $returnTo,
            false,
            array('id' => 'openid_message')
        );

        if (Auth_OpenID::isFailure($formHtml)) {
            $app['session']->getFlashBag()->set('error', 'Could not redirect to server: ' . $formHtml->message);

            return $app->redirect('/');
        } else {
            return $formHtml;
        }
    }
});

$app->get('/', function () use ($app) {
    return $app['twig']->render('index.twig');
});

$app->run();
